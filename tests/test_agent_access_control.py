"""Agent 접근 기준선 평가 + 실시간 통제(`authorize_call`) 테스트."""

from __future__ import annotations

from dataclasses import replace

import pytest

from backend.services.agent_access_evaluator import (
    AGENT_ACCESS_RULE_CATALOG,
    AgentAccessEvaluator,
)
from backend.services.change_control_service import ChangeControlService
from backend.services.control_service import ControlService
from backend.services.lifecycle_service import LifecycleService
from backend.services.nhi_state import load_nhi, save_nhi
from core.agent_access_models import (
    AgentAccessGrant,
    AgentAccessProfile,
    AgentApiObservation,
    AgentLifecycleStatus,
)
from core.config import GovernanceSettings
from core.governance_models import ControlState
from core.nhi_models import PermissionLevel
from storage.sqlite_store import SQLiteStorage

FP = "sha256:" + "a" * 16
OTHER_FP = "sha256:" + "b" * 16


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def make_nhi(store, nhi_id="nhi-1", **overrides):
    data = {
        "nhi_id": nhi_id,
        "nhi_name": nhi_id,
        "nhi_type": "SERVICE_ACCOUNT",
        "provider": "github",
        "owner": "platform",
        "identified": True,
        "environment": "production",
        "permissions": ["READ", "WRITE"],
        "raw_scopes": ["contents:read", "contents:write"],
    }
    data.update(overrides)
    store.upsert_nhi(nhi_id, data)
    LifecycleService(store).ensure_tracked(nhi_id)
    # ensure_tracked 가 상태 필드를 초기화하므로, 시나리오용 상태는 등록 뒤에 다시 적용한다.
    forced = {
        key: overrides[key]
        for key in ("lifecycle_stage", "credential_state", "control_state")
        if key in overrides
    }
    if forced:
        nhi = load_nhi(store, nhi_id)
        nhi.update(forced)
        save_nhi(store, nhi)
    return nhi_id


def make_profile(store, **overrides) -> AgentAccessProfile:
    grant = AgentAccessGrant(
        provider="github",
        nhi_id="nhi-1",
        credential_fingerprints=[FP],
        credential_inventory_complete=True,
        permissions=[PermissionLevel.READ, PermissionLevel.WRITE],
        permission_inventory_complete=True,
        resources=["acme/backend", "acme/docs/*"],
        resource_inventory_complete=True,
    )
    values = dict(
        agent_id="deploy-agent",
        display_name="Deploy Agent",
        owner="platform",
        grants=[grant],
        inventory_complete=True,
        require_sender_constraint=False,
    )
    values.update(overrides)
    profile = AgentAccessProfile(**values)
    store.save_agent_access_profile(profile.model_dump(mode="json"))
    return profile


def call(**overrides) -> AgentApiObservation:
    values = dict(
        claimed_agent_id="deploy-agent",
        authenticated_agent_id="deploy-agent",
        provider="github",
        nhi_id="nhi-1",
        credential_fingerprint=FP,
        action="contents:write",
        permission=PermissionLevel.WRITE,
        resource="acme/backend",
    )
    values.update(overrides)
    return AgentApiObservation(**values)


def control(store, mode="enforce"):
    settings = replace(GovernanceSettings(), control_mode=mode)
    changes = ChangeControlService(store, settings=settings)
    return ControlService(store, changes=changes, settings=settings)


def rule_ids(result):
    return {rule["rule_id"] for rule in result["rules"]}


# ------------------------------------------------------------- 정상 / 위장
def test_matching_call_is_allowed_and_not_recorded(store):
    make_nhi(store)
    make_profile(store)
    result = control(store).authorize_call(call())
    assert result["verdict"] == "ALLOW" and result["allowed"] is True
    assert result["access_outcome"] == "ALLOW"
    assert store.list_control_events() == []


def test_claimed_agent_differs_from_authenticated_agent_is_denied(store):
    make_nhi(store)
    make_profile(store)
    result = control(store).authorize_call(call(authenticated_agent_id="rogue-agent"))
    assert result["verdict"] == "DENY" and result["allowed"] is False
    assert "CLAIMED_IDENTITY_MISMATCH" in rule_ids(result)


def test_unregistered_agent_is_denied(store):
    make_nhi(store)
    result = control(store).authorize_call(call(claimed_agent_id="ghost", authenticated_agent_id="ghost"))
    assert result["verdict"] == "DENY"
    assert "UNREGISTERED_AGENT" in rule_ids(result)


def test_unapproved_nhi_and_credential_are_denied(store):
    make_nhi(store)
    make_nhi(store, "nhi-2")
    make_profile(store)
    other_nhi = control(store).authorize_call(call(nhi_id="nhi-2"))
    assert "UNAPPROVED_NHI" in rule_ids(other_nhi) and other_nhi["allowed"] is False
    other_cred = control(store).authorize_call(call(credential_fingerprint=OTHER_FP))
    assert "UNAPPROVED_CREDENTIAL" in rule_ids(other_cred) and other_cred["allowed"] is False


def test_resource_outside_scope_is_denied_but_wildcard_prefix_is_allowed(store):
    make_nhi(store)
    make_profile(store)
    svc = control(store)
    assert svc.authorize_call(call(resource="acme/docs/guide"))["verdict"] == "ALLOW"
    outside = svc.authorize_call(call(resource="acme/payments"))
    assert "RESOURCE_SCOPE_EXCEEDED" in rule_ids(outside) and outside["allowed"] is False


# ------------------------------------------------------------- R1 / R2
def test_ended_lifecycle_or_revoked_credential_is_denied(store):
    make_nhi(store, lifecycle_stage="DEACTIVATED")
    make_profile(store)
    assert "NHI_LIFECYCLE_ENDED" in rule_ids(control(store).authorize_call(call()))

    make_nhi(store, "nhi-1", credential_state="REVOKED")
    result = control(store).authorize_call(call(event_id="evt-revoked"))
    assert "NHI_LIFECYCLE_ENDED" in rule_ids(result) and result["allowed"] is False


def test_quarantined_nhi_is_denied(store):
    make_nhi(store, control_state=ControlState.QUARANTINED.value)
    make_profile(store)
    result = control(store).authorize_call(call())
    assert "NHI_QUARANTINED" in rule_ids(result) and result["allowed"] is False


# ------------------------------------------------------------- R3 반복 → 격리
def test_repeated_permission_overreach_remains_request_deny(store):
    make_nhi(store)
    make_profile(store)
    svc = control(store)
    over = dict(permission=PermissionLevel.ADMIN, action="administration:write")

    first = svc.authorize_call(call(event_id="e1", **over))
    second = svc.authorize_call(call(event_id="e2", **over))
    assert first["verdict"] == second["verdict"] == "DENY"

    third = svc.authorize_call(call(event_id="e3", **over))
    assert third["verdict"] == "DENY" and third["allowed"] is False
    assert third["quarantine_change_id"] is None
    assert load_nhi(store, "nhi-1")["control_state"] == ControlState.NORMAL.value


def test_retried_event_is_not_counted_twice(store):
    make_nhi(store)
    make_profile(store)
    svc = control(store)
    over = dict(permission=PermissionLevel.ADMIN, action="administration:write")
    for _ in range(5):
        result = svc.authorize_call(call(event_id="same-event", **over))
    assert result["verdict"] == "DENY" and result["replayed"] is True
    assert len(store.list_control_events()) == 1


# ------------------------------------------------------------- 모름 ≠ 공격
def test_incomplete_baseline_is_review_not_deny(store):
    make_nhi(store)
    grant = AgentAccessGrant(
        provider="github",
        nhi_id="nhi-1",
        credential_fingerprints=[FP],
        credential_inventory_complete=False,
        permissions=[PermissionLevel.READ],
        permission_inventory_complete=False,
        resources=["acme/backend"],
        resource_inventory_complete=False,
    )
    make_profile(store, grants=[grant])
    result = control(store).authorize_call(
        call(permission=PermissionLevel.ADMIN, resource="acme/other", credential_fingerprint=OTHER_FP)
    )
    assert result["access_outcome"] == "REVIEW"
    assert result["verdict"] == "REVIEW" and result["allowed"] is False
    assert {"PERMISSION_BASELINE_INCOMPLETE", "RESOURCE_BASELINE_INCOMPLETE"} <= rule_ids(result)


def test_unregistered_source_and_dormant_credential_alert_without_blocking(store):
    make_nhi(
        store,
        known_sources=["10.0.0.1"],
        last_used_at="2020-01-01T00:00:00+00:00",
    )
    make_profile(store)
    result = control(store).authorize_call(call(source_ip="203.0.113.9", permission=PermissionLevel.ADMIN))
    # 관리자급 권한이라도 IP 만으로 차단하지 않는다 (권한 초과 규칙은 별개)
    ids = rule_ids(result)
    assert {"UNREGISTERED_SOURCE", "DORMANT_CREDENTIAL_REACTIVATED"} <= ids
    ip_rule = next(r for r in result["rules"] if r["rule_id"] == "UNREGISTERED_SOURCE")
    assert ip_rule["verdict"] == "ALERT"


def test_suspended_agent_is_denied(store):
    make_nhi(store)
    make_profile(store, status=AgentLifecycleStatus.SUSPENDED)
    assert "AGENT_NOT_ACTIVE" in rule_ids(control(store).authorize_call(call()))


# ------------------------------------------------------------- 모드 / 보안
def test_monitor_mode_still_blocks_deny(store):
    make_nhi(store)
    make_profile(store)
    result = control(store, mode="monitor").authorize_call(
        call(authenticated_agent_id="rogue-agent")
    )
    assert result["verdict"] == "DENY" and result["allowed"] is False
    assert result["enforced"] is True
    assert store.list_control_events()[0]["enforced"] is True


def test_secret_like_action_is_redacted_in_stored_event(store):
    make_nhi(store)
    make_profile(store)
    leaked = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    control(store).authorize_call(
        call(authenticated_agent_id="rogue-agent", action=f"GET /repos?token={leaked}")
    )
    stored = str(store.list_control_events())
    assert leaked not in stored


def test_profile_is_persisted_and_scope_summary_flags_blind_spots(store):
    profile = make_profile(
        store,
        grants=[
            AgentAccessGrant(
                provider="github",
                nhi_id="nhi-1",
                permissions=[PermissionLevel.ADMIN],
                resources=["acme/*"],
            )
        ],
        inventory_complete=False,
    )
    assert store.get_agent_access_profile("deploy-agent")["display_name"] == "Deploy Agent"
    summary = AgentAccessEvaluator().summarize_scope(profile)
    types = {item["type"] for item in summary["broad_access_indicators"]}
    assert types == {"HIGH_PRIVILEGE", "WILDCARD_RESOURCE"}
    assert summary["inventory_complete"] is False and summary["blind_spots"]


def test_rule_catalog_covers_every_rule_the_evaluator_can_emit():
    for rule_id in (
        "NHI_LIFECYCLE_ENDED",
        "NHI_QUARANTINED",
        "UNREGISTERED_SOURCE",
        "DORMANT_CREDENTIAL_REACTIVATED",
        "PERMISSION_SCOPE_EXCEEDED",
    ):
        assert rule_id in AGENT_ACCESS_RULE_CATALOG
