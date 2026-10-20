"""승인 보류(REQUIRE_APPROVAL) · 1회용 허가 · 서버 측정 급증 · 탈취 의심 시 교체 제안 테스트."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from backend.services.change_control_service import ChangeControlService
from backend.services.control_approval import ApprovalError, ControlApprovalService
from backend.services.control_service import ControlService
from backend.services.usage_rate import MIN_BASELINE_CALLS, UsageRateTracker
from core.agent_access_models import AgentAccessGrant, AgentAccessProfile
from core.config import GovernanceSettings
from core.governance_models import ChangeStatus, ChangeType, ControlEventType
from core.nhi_models import PermissionLevel
from storage.sqlite_store import SQLiteStorage

from tests.test_agent_access_control import (
    OTHER_FP,
    call,
    make_nhi,
    make_profile,
)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def build(store, mode="human_in_the_loop", clock=None, tracker=None):
    clock = clock or Clock()
    settings = replace(GovernanceSettings(), control_mode=mode)
    changes = ChangeControlService(store, settings=settings)
    approvals = ControlApprovalService(
        store, approval_ttl_seconds=900, grant_ttl_seconds=300, clock=clock
    )
    service = ControlService(
        store,
        changes=changes,
        settings=settings,
        approvals=approvals,
        tracker=tracker or UsageRateTracker(clock),
    )
    return service, changes, clock


def incomplete_profile(store):
    """권한·자원 기준선이 불완전해 확정 불가(REVIEW)가 되는 Agent."""
    return make_profile(
        store,
        grants=[
            AgentAccessGrant(
                provider="github",
                nhi_id="nhi-1",
                credential_fingerprints=["sha256:" + "a" * 16],
                credential_inventory_complete=True,
                permissions=[PermissionLevel.READ],
                permission_inventory_complete=False,
                resources=["acme/backend"],
                resource_inventory_complete=False,
            )
        ],
    )


def held(service, **overrides):
    values = dict(permission=PermissionLevel.WRITE, resource="acme/other")
    values.update(overrides)
    return service.authorize_call(call(**values))


# ------------------------------------------------------------ 보류 → 승인 → 재시도
def test_review_is_held_in_human_in_the_loop_mode(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    result = held(service)
    assert result["directive"] == "REQUIRE_APPROVAL" and result["allowed"] is False
    assert result["approval"]["status"] == "PENDING"
    assert store.list_control_events()[0]["allowed"] is False


def test_enforce_mode_blocks_review(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store, mode="enforce")
    result = held(service)
    assert result["directive"] == "BLOCK" and result["allowed"] is False
    assert result["approval"] is None


def test_approved_hold_passes_once_with_grant_and_is_bound_to_the_request(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    first = held(service, event_id="req-1")
    decision_id = first["decision_id"]

    approval, grant = service.approvals.approve(decision_id, actor="alice", reason="확인함")
    assert approval["status"] == "APPROVED" and "grant_digest" not in approval
    assert grant not in str(store.get_control_approval(decision_id))  # 원문 미저장

    other_resource = service.authorize_call(
        call(permission=PermissionLevel.WRITE, resource="acme/else", event_id="req-2"),
        grant_token=grant,
    )
    assert other_resource["directive"] != "PASS"
    assert "resource" in other_resource["grant_rejected_reason"]

    retry = service.authorize_call(
        call(permission=PermissionLevel.WRITE, resource="acme/other", event_id="req-1-retry"),
        grant_token=grant,
    )
    assert retry["directive"] == "PASS" and retry["allowed"] is True
    assert retry["grant_redeemed"] is True

    again = service.authorize_call(
        call(permission=PermissionLevel.WRITE, resource="acme/other", event_id="req-1-retry2"),
        grant_token=grant,
    )
    assert again["allowed"] is False
    assert "이미 사용" in again["grant_rejected_reason"]


def test_retry_with_same_event_id_and_grant_still_redeems(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    first = held(service, event_id="same")
    _, grant = service.approvals.approve(first["decision_id"], actor="alice", reason="ok")
    retry = service.authorize_call(
        call(permission=PermissionLevel.WRITE, resource="acme/other", event_id="same"),
        grant_token=grant,
    )
    assert retry["directive"] == "PASS"


def test_unapproved_or_tampered_grant_is_rejected(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    first = held(service)
    forged = f"{first['decision_id']}.not-the-real-secret"
    result = service.authorize_call(
        call(permission=PermissionLevel.WRITE, resource="acme/other", event_id="x"),
        grant_token=forged,
    )
    assert result["allowed"] is False and "유효하지 않은" in result["grant_rejected_reason"]


def test_rejected_hold_cannot_be_approved_later(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    first = held(service)
    service.approvals.reject(first["decision_id"], actor="alice", reason="의심스러움")
    with pytest.raises(ApprovalError):
        service.approvals.approve(first["decision_id"], actor="bob", reason="번복")


def test_hold_expires_without_decision_and_grant_expires_after_ttl(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, clock = build(store)
    first = held(service)
    clock.advance(seconds=901)
    assert service.approvals.get(first["decision_id"])["status"] == "EXPIRED"
    with pytest.raises(ApprovalError):
        service.approvals.approve(first["decision_id"], actor="alice", reason="늦음")

    second = held(service, event_id="e2", resource="acme/x")
    _, grant = service.approvals.approve(second["decision_id"], actor="alice", reason="ok")
    clock.advance(seconds=301)
    result = service.authorize_call(
        call(permission=PermissionLevel.WRITE, resource="acme/x", event_id="e3"),
        grant_token=grant,
    )
    assert result["allowed"] is False and "유효 시간" in result["grant_rejected_reason"]


def test_second_admin_cannot_decide_an_already_decided_hold(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    first = held(service)
    service.approvals.approve(first["decision_id"], actor="alice", reason="ok")
    with pytest.raises(ApprovalError):
        service.approvals.reject(first["decision_id"], actor="bob", reason="늦은 반대")


def test_hard_deny_is_never_held_for_approval(store):
    make_nhi(store)
    incomplete_profile(store)
    service, _, _ = build(store)
    result = held(service, authenticated_agent_id="rogue-agent")
    assert result["directive"] == "BLOCK" and result["approval"] is None


# ------------------------------------------------------------ 탈취 의심 → 교체 제안
def test_credential_theft_signal_blocks_and_proposes_rotation_for_approval(store):
    make_nhi(store)
    make_profile(store)
    service, changes, _ = build(store)
    result = service.authorize_call(call(credential_fingerprint=OTHER_FP))
    assert result["directive"] == "BLOCK"
    rotation = changes.get(result["follow_up_change_ids"][0])
    assert rotation.change_type is ChangeType.TOKEN_ROTATE
    assert rotation.status is ChangeStatus.PENDING_APPROVAL  # 실행은 사람의 승인 이후


def test_overreach_alone_does_not_propose_rotation(store):
    make_nhi(store)
    make_profile(store)
    service, _, _ = build(store)
    result = service.authorize_call(
        call(permission=PermissionLevel.ADMIN, action="administration:write")
    )
    assert result["directive"] == "BLOCK" and result["follow_up_change_ids"] == []


# ------------------------------------------------------------ 서버 측정 급증 (R4)
def warm_up(service, clock, calls=MIN_BASELINE_CALLS + 5):
    for _ in range(calls):
        clock.advance(seconds=60)
        service.authorize_call(call(event_id=f"warm-{clock.now.timestamp()}"))


def test_server_measured_spike_alerts_for_normal_privilege(store):
    make_nhi(store)
    make_profile(store)
    service, _, clock = build(store, mode="enforce")
    warm_up(service, clock)  # 분당 1회 수준의 기준선
    for i in range(6):
        result = service.authorize_call(call(event_id=f"burst-{i}"))
    rule = next(r for r in result["rules"] if r["rule_id"] == "AGENT_CALL_RATE_SPIKE")
    assert rule["verdict"] == "REVIEW"


def test_no_spike_judgement_without_a_reliable_baseline(store):
    make_nhi(store)
    make_profile(store)
    service, _, _ = build(store, mode="enforce")
    for i in range(30):  # 기준선이 없는 상태의 연속 호출
        result = service.authorize_call(call(event_id=f"cold-{i}"))
    assert result["verdict"] == "ALLOW"


# ------------------------------------------------------------ 보정된 기존 규칙
def test_unknown_permission_baseline_is_not_treated_as_overreach(store):
    make_nhi(store, permissions=[])
    service, _, _ = build(store, mode="enforce")
    result = service.authorize("nhi-1", "WRITE")
    assert result["verdict"] == "REVIEW" and result["allowed"] is False
    assert result["rules"][0]["rule_id"] == "PERMISSION_BASELINE_INCOMPLETE"


def test_caller_reported_spike_is_labelled_as_such(store):
    make_nhi(store, permissions=["READ"])
    service, _, _ = build(store, mode="enforce")
    result = service.evaluate(
        "nhi-1",
        ControlEventType.USAGE_SPIKE,
        {"requests_per_min": 600, "baseline_per_min": 100},
    )
    assert "호출자 보고값" in result["rules"][0]["message"]
