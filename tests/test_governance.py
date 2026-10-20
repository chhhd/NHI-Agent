"""실시간 통제 · 변경 승인(영향도/롤백) · 생명주기(DAS) 테스트."""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from backend.services.change_control_service import (
    ChangeControlService,
    ChangeNotAllowed,
    SeparationOfDutiesError,
    StateConflict,
)
from backend.services.control_service import ControlService
from backend.services.demo_workspace import clear_demo_workspace, seed_demo_workspace
from backend.services.lifecycle_service import LifecycleError, LifecycleService
from backend.services.nhi_state import load_nhi
from core.config import GovernanceSettings
from core.governance_models import (
    ChangeStatus,
    ChangeType,
    ControlEventType,
    LifecycleStage,
)
from storage.sqlite_store import SQLiteStorage


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
        "data_sensitivity": "internal",
        "permissions": ["READ", "WRITE"],
        "raw_scopes": ["contents:read", "contents:write"],
        "blast_radius": {"connected_services": ["GitHub"], "accessible_resources": 4},
        "linked_ai_agent": "deploy-agent",
    }
    data.update(overrides)
    store.upsert_nhi(nhi_id, data)
    LifecycleService(store).ensure_tracked(nhi_id)
    return nhi_id


def services(store, mode="enforce"):
    settings = replace(GovernanceSettings(), control_mode=mode)
    changes = ChangeControlService(store, settings=settings)
    return changes, ControlService(store, changes=changes, settings=settings)


# ---------------------------------------------------------------- 생명주기
def test_new_nhi_with_owner_is_auto_activated_and_logged(store):
    make_nhi(store)
    nhi = load_nhi(store, "nhi-1")
    assert nhi["lifecycle_stage"] == "ACTIVE"
    events = [e["event_type"] for e in LifecycleService(store).timeline("nhi-1")]
    assert events == ["DISCOVERED", "AUTO_ACTIVATED"]


def test_ownerless_nhi_stays_in_creation_until_owner_is_set(store):
    make_nhi(store, owner=None)
    lifecycle = LifecycleService(store)
    assert load_nhi(store, "nhi-1")["lifecycle_stage"] == "REGISTERED"
    with pytest.raises(LifecycleError):
        lifecycle.advance("nhi-1", actor="admin")


def test_manual_advance_is_limited_to_safe_transitions(store):
    make_nhi(store)
    with pytest.raises(LifecycleError):  # ACTIVE 에서 종료/파기는 변경 승인 흐름으로만
        LifecycleService(store).advance("nhi-1", actor="admin")


def test_aging_flags_cover_stale_rotation_and_disposal(store):
    make_nhi(
        store,
        last_used_at="2020-01-01T00:00:00+00:00",
        last_rotated_at="2020-01-01T00:00:00+00:00",
    )
    codes = {f["code"] for f in LifecycleService(store).view("nhi-1")["aging"]}
    assert {"STALE_UNUSED", "ROTATION_OVERDUE"} <= codes


# ---------------------------------------------------------------- 변경 승인
def test_preview_shows_before_after_and_does_not_persist(store):
    make_nhi(store)
    changes, _ = services(store)
    plan = changes.preview(
        "nhi-1", ChangeType.SCOPE_CHANGE, {"target_permissions": ["READ"]}
    )
    diff = plan["impact"]["diff"]["permissions"]
    assert diff["before"] == ["READ", "WRITE"] and diff["after"] == ["READ"]
    assert diff["removed"] == ["WRITE"]
    assert plan["impact"]["service_continuity"]["will_interrupt"] is True
    assert plan["rollback"]["supported"] is True
    assert changes.list() == []
    assert load_nhi(store, "nhi-1")["permissions"] == ["READ", "WRITE"]


def test_low_tier_is_auto_approved_and_applied(store):
    make_nhi(
        store, environment="development", permissions=["READ"],
        blast_radius={}, linked_ai_agent=None,
    )
    changes, _ = services(store)
    change = changes.propose(
        "nhi-1", ChangeType.TOKEN_ROTATE, requested_by="alice",
        params={"grace_period_hours": 2},
    )
    assert change.tier.value == "LOW"
    assert change.status is ChangeStatus.APPLIED
    assert change.approved_by == "policy:auto-low"
    assert load_nhi(store, "nhi-1")["credential_version"] == 2


def test_high_tier_waits_and_requires_a_different_approver(store):
    make_nhi(store)
    changes, _ = services(store)
    change = changes.propose(
        "nhi-1", ChangeType.TOKEN_REVOKE, requested_by="alice", reason="정리"
    )
    assert change.status is ChangeStatus.PENDING_APPROVAL
    assert change.tier.value == "HIGH"
    assert load_nhi(store, "nhi-1")["credential_state"] == "ACTIVE"  # 아직 적용 전
    with pytest.raises(SeparationOfDutiesError):
        changes.approve(change.change_id, actor="alice")
    applied = changes.approve(change.change_id, actor="bob")
    nhi = load_nhi(store, "nhi-1")
    assert applied.status is ChangeStatus.APPLIED
    assert nhi["credential_state"] == "REVOKED"
    assert nhi["lifecycle_stage"] == "DEACTIVATED"


def test_critical_requires_impact_acknowledgement(store):
    make_nhi(store, permissions=["READ", "WRITE", "DELETE"])
    changes, _ = services(store)
    change = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="alice")
    assert change.tier.value == "CRITICAL"
    with pytest.raises(ChangeNotAllowed):
        changes.approve(change.change_id, actor="bob")
    assert changes.approve(
        change.change_id, actor="bob", acknowledge_impact=True
    ).status is ChangeStatus.APPLIED


def test_reject_leaves_state_untouched(store):
    make_nhi(store)
    changes, _ = services(store)
    change = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="alice")
    rejected = changes.reject(change.change_id, actor="bob", reason="시기상조")
    assert rejected.status is ChangeStatus.REJECTED
    assert load_nhi(store, "nhi-1")["credential_state"] == "ACTIVE"
    with pytest.raises(StateConflict):
        changes.approve(change.change_id, actor="bob")


def test_scope_change_applies_and_rolls_back_to_previous_shape(store):
    make_nhi(store)
    changes, _ = services(store)
    change = changes.propose(
        "nhi-1", ChangeType.SCOPE_CHANGE, requested_by="alice",
        params={"target_permissions": ["READ"], "target_scopes": ["contents:read"]},
    )
    changes.approve(change.change_id, actor="bob")
    nhi = load_nhi(store, "nhi-1")
    assert nhi["permissions"] == ["READ"]
    assert nhi["lifecycle_stage"] == "ACTIVE"
    assert any(e["event_type"] == "PERMISSION_CHANGE" for e in store.list_lifecycle_events(nhi_id="nhi-1"))

    rolled = changes.rollback(change.change_id, actor="bob", reason="장애")
    nhi = load_nhi(store, "nhi-1")
    assert rolled.status is ChangeStatus.ROLLED_BACK
    assert nhi["permissions"] == ["READ", "WRITE"]
    assert nhi["raw_scopes"] == ["contents:read", "contents:write"]
    assert nhi["lifecycle_stage"] == "ACTIVE"


def test_revoke_rollback_restores_service(store):
    make_nhi(store)
    changes, control = services(store)
    change = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="alice")
    changes.approve(change.change_id, actor="bob")
    assert control.authorize("nhi-1", "READ")["allowed"] is False
    changes.rollback(change.change_id, actor="bob")
    assert load_nhi(store, "nhi-1")["credential_state"] == "ACTIVE"
    assert control.authorize("nhi-1", "READ")["allowed"] is True


def test_rollback_is_blocked_when_state_changed_since(store):
    make_nhi(store)
    changes, _ = services(store)
    scope = changes.propose(
        "nhi-1", ChangeType.SCOPE_CHANGE, requested_by="a",
        params={"target_permissions": ["READ"]},
    )
    changes.approve(scope.change_id, actor="b")
    revoke = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="a")
    changes.approve(revoke.change_id, actor="b")
    with pytest.raises(StateConflict):
        changes.rollback(scope.change_id, actor="b")  # 이후 변경을 덮어쓰게 된다


def test_stale_proposal_cannot_be_approved(store):
    make_nhi(store)
    changes, _ = services(store)
    first = changes.propose(
        "nhi-1", ChangeType.SCOPE_CHANGE, requested_by="a",
        params={"target_permissions": ["READ"]},
    )
    store_nhi = load_nhi(store, "nhi-1")
    store_nhi["permissions"] = ["READ", "WRITE", "ADMIN"]  # 제안 이후 권한이 바뀜
    store.upsert_nhi("nhi-1", store_nhi)
    with pytest.raises(StateConflict):
        changes.approve(first.change_id, actor="b")


def test_duplicate_pending_request_is_rejected(store):
    make_nhi(store)
    changes, _ = services(store)
    changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="a")
    with pytest.raises(StateConflict):
        changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="a")


def test_dispose_requires_termination_and_cannot_be_rolled_back(store):
    make_nhi(store)
    changes, _ = services(store)
    with pytest.raises(ChangeNotAllowed):
        changes.preview("nhi-1", ChangeType.TOKEN_DISPOSE)
    revoke = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="a")
    changes.approve(revoke.change_id, actor="b")
    dispose = changes.propose("nhi-1", ChangeType.TOKEN_DISPOSE, requested_by="a")
    assert dispose.rollback["supported"] is False
    changes.approve(
        dispose.change_id, actor="b",
        destruction_evidence={
            "method": "SECRET_MATERIAL_DELETED", "verified_by": "c",
            "verification_check": "보관 원문 조회", "verification_result": "MATERIAL_ABSENT",
        },
    )
    nhi = load_nhi(store, "nhi-1")
    assert nhi["lifecycle_stage"] == "DECOMMISSIONED" and nhi["permissions"] == []
    with pytest.raises(ChangeNotAllowed):
        changes.rollback(dispose.change_id, actor="b")


def test_rotation_without_grace_is_not_rollbackable(store):
    make_nhi(store)
    changes, _ = services(store)
    plan = changes.preview("nhi-1", ChangeType.TOKEN_ROTATE, {"grace_period_hours": 0})
    assert plan["rollback"]["supported"] is False
    assert plan["impact"]["service_continuity"]["will_interrupt"] is True


def test_privilege_increase_raises_the_tier(store):
    make_nhi(store, permissions=["READ"], environment="development", blast_radius={})
    changes, _ = services(store)
    plan = changes.preview("nhi-1", ChangeType.SCOPE_CHANGE, {"target_permissions": ["ADMIN"]})
    assert plan["tier"] != "LOW"
    assert plan["impact"]["diff"]["permissions"]["added"] == ["ADMIN"]


# ---------------------------------------------------------------- 실시간 통제
def test_use_beyond_granted_permission_only_denies_the_request(store):
    make_nhi(store, permissions=["READ"])
    _, control = services(store)
    first = control.authorize("nhi-1", "DELETE")
    second = control.authorize("nhi-1", "DELETE")
    assert first["verdict"] == "DENY" and first["allowed"] is False
    assert second["verdict"] == "DENY"
    third = control.authorize("nhi-1", "DELETE")  # 임계값 3회 도달
    assert third["verdict"] == "DENY"
    assert load_nhi(store, "nhi-1")["control_state"] == "NORMAL"
    assert control.authorize("nhi-1", "READ")["allowed"] is True


def test_allowed_request_is_not_recorded(store):
    make_nhi(store)
    _, control = services(store)
    assert control.authorize("nhi-1", "WRITE")["verdict"] == "ALLOW"
    assert store.list_control_events() == []


def test_exposure_quarantines_immediately_and_asks_approval_for_revoke(store):
    make_nhi(store, permissions=["READ", "WRITE", "ADMIN"])
    changes, control = services(store)
    result = control.evaluate("nhi-1", ControlEventType.EXPOSURE_DETECTED, {})
    assert result["verdict"] == "DENY"
    assert load_nhi(store, "nhi-1")["control_state"] == "NORMAL"
    revoke = changes.get(result["follow_up_change_ids"][0])
    assert revoke.change_type is ChangeType.TOKEN_REVOKE
    assert revoke.status is ChangeStatus.PENDING_APPROVAL  # 폐기는 승인 후에만
    assert load_nhi(store, "nhi-1")["credential_state"] == "ACTIVE"


def test_release_quarantine_is_a_rollback(store):
    make_nhi(store)
    changes, control = services(store)
    changes.propose("nhi-1", ChangeType.QUARANTINE, requested_by="admin")
    released = changes.release_quarantine("nhi-1", actor="admin", reason="오탐")
    assert released.status is ChangeStatus.ROLLED_BACK
    assert load_nhi(store, "nhi-1")["control_state"] == "NORMAL"
    assert control.authorize("nhi-1", "READ")["allowed"] is True


def test_usage_spike_alerts_or_quarantines_by_privilege(store):
    make_nhi(store, nhi_id="ro", permissions=["READ"])
    make_nhi(store, nhi_id="rw", permissions=["READ", "WRITE"])
    _, control = services(store)
    spike = {"requests_per_min": 600, "baseline_per_min": 100}
    assert control.evaluate("ro", ControlEventType.USAGE_SPIKE, spike)["verdict"] == "REVIEW"
    huge = {"requests_per_min": 2000, "baseline_per_min": 100}
    assert control.evaluate("rw", ControlEventType.USAGE_SPIKE, huge)["verdict"] == "REVIEW"


def test_terminated_credential_use_is_denied_as_compromise_signal(store):
    make_nhi(store)
    changes, control = services(store)
    revoke = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="a")
    changes.approve(revoke.change_id, actor="b")
    result = control.authorize("nhi-1", "READ")
    assert result["allowed"] is False
    assert result["rules"][0]["rule_id"] == "NHI_LIFECYCLE_ENDED"


def test_unknown_source_alerts_but_never_blocks_by_ip_alone(store):
    make_nhi(store, nhi_id="rw", permissions=["WRITE"], known_sources=["10.0.0.1"])
    make_nhi(store, nhi_id="adm", permissions=["ADMIN", "DELETE"], known_sources=["10.0.0.1"])
    _, control = services(store)
    assert control.authorize("rw", "WRITE", source_ip="9.9.9.9")["verdict"] == "ALERT"
    assert control.authorize("rw", "WRITE", source_ip="9.9.9.9")["allowed"] is True
    admin = control.authorize("adm", "ADMIN", source_ip="9.9.9.9")
    # IP 는 인증 근거가 아니다: 관리자급이어도 차단하지 않고 심각도만 올린다.
    assert admin["allowed"] is True and admin["verdict"] == "ALERT"
    assert admin["severity"] == "HIGH"


def test_monitor_mode_still_blocks_deny(store):
    make_nhi(store, permissions=["READ"])
    _, control = services(store, mode="monitor")
    for _ in range(3):
        result = control.authorize("nhi-1", "DELETE")
    assert result["verdict"] == "DENY"      # 판정은 계산하지만
    assert result["allowed"] is False              # DENY는 monitor에서도 차단
    assert result["enforced"] is True
    assert load_nhi(store, "nhi-1")["control_state"] == "NORMAL"  # 격리도 하지 않는다
    assert store.list_control_events()[0]["enforced"] is True


def test_control_event_polling_cursor(store):
    make_nhi(store, permissions=["READ"])
    _, control = services(store)
    control.authorize("nhi-1", "DELETE")
    seq = store.list_control_events()[0]["seq"]
    control.authorize("nhi-1", "ADMIN")
    newer = store.list_control_events(after_seq=seq)
    assert len(newer) == 1 and newer[0]["seq"] > seq


# ---------------------------------------------------------------- 재분석 보존 / 데모
def test_reanalysis_preserves_lifecycle_and_control_state(store):
    from agents.pipeline import NHIAnalysisPipeline
    from processing import persist_analysis
    from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
    from core.nhi_models import Environment

    nhi = GitHubNHIInput(
        nhi_id="gh-app-1", nhi_name="deploy-app", nhi_type=GitHubNHIType.GITHUB_APP,
        owner="platform", environment=Environment.PRODUCTION, active=True,
        repositories=[RepositoryInfo(name="acme/api", visibility="private")],
        raw_permissions={"contents": "write", "metadata": "read"},
    )
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)
    persist_analysis(store, analysis)
    nhi_id = analysis.profile.nhi_id
    assert load_nhi(store, nhi_id)["lifecycle_stage"] == "ACTIVE"

    changes, _ = services(store)
    quarantine = changes.propose(nhi_id, ChangeType.QUARANTINE, requested_by="admin")
    assert quarantine.status is ChangeStatus.APPLIED
    persist_analysis(store, NHIAnalysisPipeline().analyze_github_nhi(nhi))  # 재분석
    assert load_nhi(store, nhi_id)["control_state"] == "QUARANTINED"
    assert load_nhi(store, nhi_id)["lifecycle_stage"] == "ACTIVE"


def test_demo_workspace_covers_all_stages_and_clears_cleanly(store):
    result = seed_demo_workspace(store)
    assert result["pending_change_count"] >= 3
    report = LifecycleService(store).report()
    assert {s["stage"]: s["count"] for s in report["stages"]} == {
        "REGISTERED": 1, "ACTIVE": 4, "DEACTIVATED": 1, "DECOMMISSIONED": 1,
    }
    cleared = clear_demo_workspace(store)["deleted"]
    assert cleared["change_requests"] >= 5 and cleared["control_events"] >= 4
    assert store.list_change_requests() == []
    assert store.list_control_events() == []
    assert store.list_lifecycle_events() == []


# ---------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client(tmp_path_factory):
    env = pytest.MonkeyPatch()
    env.setenv("NHI_DB_PATH", str(tmp_path_factory.mktemp("gov") / "gov.db"))
    env.setenv("NHI_ADMIN_API_KEY", "test-admin-key-test-admin-key")
    from fastapi.testclient import TestClient

    from core.config import reset_settings
    import api.app as app_module

    reset_settings()
    test_client = TestClient(app_module.app)
    try:
        yield test_client
    finally:
        test_client.close()
        env.undo()
        reset_settings()


def test_api_demo_flow_preview_approve_rollback(client):
    client.post("/demo/workspace")
    preview = client.post(
        "/changes/preview",
        json={
            "nhi_id": "demo-nhi:shared-ci-bot",
            "change_type": "SCOPE_CHANGE",
            "params": {"target_permissions": ["READ"]},
        },
    )
    assert preview.status_code == 200
    assert preview.json()["impact"]["diff"]["permissions"]["removed"] == ["WRITE"]

    pending = client.get("/changes?status=PENDING_APPROVAL").json()["changes"]
    target = next(c for c in pending if c["change_type"] == "SCOPE_CHANGE")
    assert target["tier"] == "CRITICAL"

    same_person = client.post(
        f"/changes/{target['change_id']}/approve",
        json={"actor": target["requested_by"], "acknowledge_impact": True},
    )
    assert same_person.status_code == 403
    no_ack = client.post(f"/changes/{target['change_id']}/approve", json={"actor": "dashboard-admin"})
    assert no_ack.status_code == 422
    ok = client.post(
        f"/changes/{target['change_id']}/approve",
        json={"actor": "dashboard-admin", "acknowledge_impact": True},
    )
    assert ok.status_code == 200 and ok.json()["status"] == "APPLIED"
    rolled = client.post(
        f"/changes/{target['change_id']}/rollback", json={"actor": "dashboard-admin"}
    )
    assert rolled.json()["status"] == "ROLLED_BACK"
    client.delete("/demo/workspace")


def test_api_real_nhi_requires_admin_key(client):
    client.post("/demo/workspace")
    # 데모가 아닌 NHI 를 하나 만든다.
    import api.app as app_module

    make_nhi(app_module.storage, nhi_id="real-nhi")
    body = {"nhi_id": "real-nhi", "permission": "READ"}
    assert client.post("/control/authorize", json=body).status_code == 401
    ok = client.post(
        "/control/authorize", json=body,
        headers={"X-NHI-Admin-Key": "test-admin-key-test-admin-key"},
    )
    assert ok.status_code == 200 and ok.json()["allowed"] is True
    client.delete("/demo/workspace")


def test_api_lifecycle_and_control_endpoints(client):
    client.post("/demo/workspace")
    report = client.get("/lifecycle").json()
    assert len(report["stages"]) == 4
    view = client.get("/lifecycle/demo-nhi:staging-event-relay").json()
    assert view["stage"] == "DEACTIVATED"
    assert any(f["code"] == "DISPOSAL_DUE" for f in view["aging"])
    assert client.get("/lifecycle/nope").status_code == 404

    status = client.get("/control/status").json()
    assert status["mode"] == "enforce" and not status["quarantined"]
    sim = client.post(
        "/control/events",
        json={"nhi_id": "demo-nhi:shared-ci-bot", "event_type": "USAGE_SPIKE",
              "attributes": {"requests_per_min": 900, "baseline_per_min": 50}},
    ).json()
    assert sim["verdict"] == "REVIEW"
    release = client.post(
        "/control/nhi/demo-nhi:shared-ci-bot/release", json={"actor": "dashboard-admin"}
    )
    assert release.status_code == 409
    client.delete("/demo/workspace")
