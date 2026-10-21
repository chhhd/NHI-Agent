"""aging 승인 요청 자동 생성 + 파기 증적(수행자≠검증자, 해시 체인) 테스트."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from backend.services.change_control_service import ChangeControlService, ChangeNotAllowed
from backend.services.nhi_aging import AGING_ACTOR, NHIAgingService
from backend.services.nhi_state import load_nhi, save_nhi
from core.config import reset_settings
from core.destruction_models import evidence_digest
from core.governance_models import ChangeStatus, ChangeType
from storage.sqlite_store import SQLiteStorage

from tests.helpers_app import load_private_app, unload_private_app
from tests.test_governance import make_nhi

EVIDENCE = {
    "method": "SECRET_MATERIAL_DELETED",
    "verified_by": "carol",
    "verification_check": "보관 원문 조회",
    "verification_result": "MATERIAL_ABSENT",
}


def days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def services(store):
    changes = ChangeControlService(store)
    return changes, NHIAgingService(store, changes=changes)


def terminate(store, changes, nhi_id="nhi-1", days_ago_terminated=40):
    revoke = changes.propose(nhi_id, ChangeType.TOKEN_REVOKE, requested_by="a")
    changes.approve(revoke.change_id, actor="b", acknowledge_impact=True)
    nhi = load_nhi(store, nhi_id)
    nhi["stage_entered_at"] = days_ago(days_ago_terminated)
    save_nhi(store, nhi)


# ------------------------------------------------------------ aging
def test_stale_nhi_gets_a_termination_request_even_when_the_tier_is_low(store):
    # 비운영 · 읽기 전용 → 위험 표시는 LOW지만 관리자 승인이 필요한 조합
    make_nhi(
        store, environment="development", permissions=["READ"], blast_radius={},
        linked_ai_agent=None, last_used_at=days_ago(200),
    )
    changes, aging = services(store)

    result = aging.run(triggered_by="alice")

    item = result["items"][0]
    assert item["outcome"] == "PROPOSED" and item["change_type"] == "TOKEN_REVOKE"
    assert item["tier"] == "LOW"
    change = changes.get(item["change_id"])
    assert change.status is ChangeStatus.PENDING_APPROVAL  # 자동 적용되지 않았다
    assert change.requested_by == AGING_ACTOR and change.source == "aging-policy"
    assert any("관리자 한 명" in reason for reason in change.approval["reasons"])
    assert load_nhi(store, "nhi-1")["credential_state"] == "ACTIVE"


def test_second_run_does_not_duplicate_pending_requests(store):
    make_nhi(store, last_used_at=days_ago(200))
    _, aging = services(store)
    first = aging.run(triggered_by="alice")
    second = aging.run(triggered_by="alice")
    assert first["counts"]["proposed"] == 1
    assert second["counts"] == {"proposed": 0, "already_pending": 1, "failed": 0, "dry_run": 0}
    assert second["items"][0]["change_id"] == first["items"][0]["change_id"]


def test_dry_run_only_reports_candidates(store):
    make_nhi(store, last_used_at=days_ago(200))
    changes, aging = services(store)
    result = aging.run(triggered_by="alice", create_changes=False)
    assert result["dry_run"] is True and result["items"][0]["outcome"] == "DRY_RUN"
    assert changes.list() == []
    assert not [e for e in store.list_audit_events() if e["event_type"] == "AGING_RUN"]


def test_recently_used_nhi_is_not_a_candidate(store):
    make_nhi(store, last_used_at=days_ago(3))
    _, aging = services(store)
    assert aging.candidates() == []


def test_terminated_nhi_is_proposed_for_disposal_only_after_the_retention_period(store):
    make_nhi(store, last_used_at=days_ago(1))
    changes, aging = services(store)
    terminate(store, changes, days_ago_terminated=5)  # 보존 기간(30일) 이내
    assert aging.candidates() == []

    nhi = load_nhi(store, "nhi-1")
    nhi["stage_entered_at"] = days_ago(40)
    save_nhi(store, nhi)
    result = aging.run(triggered_by="alice")
    item = result["items"][0]
    assert (item["signal"], item["change_type"], item["outcome"]) == (
        "DISPOSAL_DUE", "TOKEN_DISPOSE", "PROPOSED"
    )
    assert changes.get(item["change_id"]).status is ChangeStatus.PENDING_APPROVAL
    assert load_nhi(store, "nhi-1")["lifecycle_stage"] == "DEACTIVATED"  # 아직 파기되지 않음


def test_run_is_audited_with_counts_only(store):
    make_nhi(store, last_used_at=days_ago(200))
    _, aging = services(store)
    aging.run(triggered_by="alice")
    event = next(e for e in store.list_audit_events() if e["event_type"] == "AGING_RUN")
    assert event["actor"] == "alice" and event["detail"]["proposed"] == 1


# ------------------------------------------------------------ 파기 증적
def dispose_request(store):
    make_nhi(store, last_used_at=days_ago(1))
    changes, _ = services(store)
    terminate(store, changes)
    return changes, changes.propose("nhi-1", ChangeType.TOKEN_DISPOSE, requested_by="a")


def test_disposal_cannot_be_approved_without_evidence(store):
    changes, dispose = dispose_request(store)
    with pytest.raises(ChangeNotAllowed, match="증적"):
        changes.approve(dispose.change_id, actor="bob")
    assert load_nhi(store, "nhi-1")["lifecycle_stage"] == "DEACTIVATED"


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"verified_by": "bob"}, "서로 달라야"),            # 수행자(기본=승인자 bob)가 스스로 검증
        ({"verified_by": ""}, "기록해야"),
        ({"verification_check": " "}, "검증 방법"),
        ({"verification_result": "LOOKS_FINE"}, "다음 중 하나"),
        ({"method": "WISHFUL_THINKING"}, "파기 방법"),
    ],
)
def test_invalid_evidence_is_rejected_and_nothing_is_destroyed(store, overrides, message):
    changes, dispose = dispose_request(store)
    with pytest.raises(ChangeNotAllowed, match=message):
        changes.approve(dispose.change_id, actor="bob", destruction_evidence={**EVIDENCE, **overrides})
    assert load_nhi(store, "nhi-1")["lifecycle_stage"] == "DEACTIVATED"
    assert changes.get(dispose.change_id).status is ChangeStatus.PENDING_APPROVAL


def test_valid_evidence_is_recorded_with_a_digest_chained_to_the_previous_event(store):
    changes, dispose = dispose_request(store)
    before = store.list_lifecycle_events(nhi_id="nhi-1", limit=1)[0]["event_id"]

    changes.approve(dispose.change_id, actor="bob", destruction_evidence=EVIDENCE)

    event = next(
        e for e in store.list_lifecycle_events(nhi_id="nhi-1", limit=20)
        if e["event_type"] == "TOKEN_DISPOSED"
    )
    detail = event["detail"]
    assert detail["previous_event_id"] == before
    recorded = detail["destruction_evidence"]
    assert recorded["performed_by"] == "bob" and recorded["verified_by"] == "carol"
    assert detail["evidence_digest"] == evidence_digest(recorded, before)
    # 증적 내용이나 직전 이벤트가 바뀌면 digest 가 달라진다(변조 탐지)
    assert evidence_digest({**recorded, "verified_by": "mallory"}, before) != detail["evidence_digest"]
    assert evidence_digest(recorded, "other-event") != detail["evidence_digest"]
    assert load_nhi(store, "nhi-1")["lifecycle_stage"] == "DECOMMISSIONED"


# ------------------------------------------------------------ API: 공용 관리자 키와 파기 증적
ADMIN = "bootstrap-shared-key-0123456789abcdef0123"


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", ADMIN)
    module, name = load_private_app(tmp_path, monkeypatch)
    module.storage = SQLiteStorage(":memory:")
    reset_settings()
    yield module
    module.storage.close()
    unload_private_app(module, name)


def test_shared_admin_mode_requires_a_different_evidence_verifier(app):
    make_nhi(app.storage, last_used_at=days_ago(1))
    changes = ChangeControlService(app.storage)
    terminate(app.storage, changes)
    dispose = changes.propose("nhi-1", ChangeType.TOKEN_DISPOSE, requested_by="alice")
    def approve(verifier):
        return app.approve_change(
            dispose.change_id,
            app.ChangeDecisionRequest(
                actor="bob",
                destruction_evidence={**EVIDENCE, "verified_by": verifier},
            ),
            x_nhi_admin_key=ADMIN,
        )

    with pytest.raises(HTTPException) as exc:
        approve("bob")  # 수행자(bob)가 스스로 검증
    assert exc.value.status_code in (409, 422)

    done = approve("alice")
    assert done["status"] == "APPLIED"


def test_aging_run_endpoint_never_applies_changes(app):
    make_nhi(app.storage, environment="development", permissions=["READ"], blast_radius={},
             linked_ai_agent=None, last_used_at=days_ago(300))
    result = app.lifecycle_aging_run(
        app.AgingRunRequest(actor="alice"), x_nhi_admin_key=ADMIN
    )
    assert result["counts"]["proposed"] == 1
    assert load_nhi(app.storage, "nhi-1")["credential_state"] == "ACTIVE"
    listed = app.lifecycle_aging_candidates()
    assert listed["count"] == 1
    with pytest.raises(HTTPException) as exc:
        app.lifecycle_aging_run(app.AgingRunRequest(actor="alice"), x_nhi_admin_key=None)
    assert exc.value.status_code == 401
