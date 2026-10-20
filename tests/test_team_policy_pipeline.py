"""팀 합의 정책이 API·서비스·재분석·저장 데이터에 일관되게 적용되는지 검증한다."""

import json
from dataclasses import replace

import pytest

from backend.services.control_service import ControlService
from backend.services.lifecycle_service import LifecycleError, LifecycleService
from backend.services.nhi_state import load_nhi
from backend.services.usage_rate import UsageRateTracker
from core.config import GovernanceSettings
from core.governance_models import LifecycleStage
from storage.sqlite_store import SQLiteStorage
from tests.test_agent_access_control import call, make_nhi, make_profile
from tests.test_control_approval import Clock, incomplete_profile, warm_up
from tests.test_governance import store  # noqa: F401
from tests.test_aging_and_destruction import EVIDENCE


@pytest.mark.parametrize("path", ["agent", "nhi"])
@pytest.mark.parametrize("mode", ["enforce", "monitor", "human_in_the_loop"])
@pytest.mark.parametrize("outcome", ["ALLOW", "ALERT", "REVIEW", "DENY"])
def test_full_mode_matrix_on_both_entry_points(store, path, mode, outcome):
    make_nhi(store, known_sources=["10.0.0.1"] if outcome == "ALERT" else [])
    make_profile(store)
    if outcome == "REVIEW":
        incomplete_profile(store)
        make_nhi(store, permissions=[])
    svc = ControlService(
        store, settings=replace(GovernanceSettings(), control_mode=mode),
        tracker=UsageRateTracker(),
    )
    permission = "ADMIN" if outcome == "DENY" else "WRITE"
    if path == "agent":
        result = svc.authorize_call(call(permission=permission, source_ip="203.0.113.9"))
    else:
        result = svc.authorize("nhi-1", permission, source_ip="203.0.113.9")
    allowed = outcome in {"ALLOW", "ALERT"} or (outcome == "REVIEW" and mode == "monitor")
    assert result["access_outcome"] == result["verdict"] == outcome
    assert result["allowed"] is allowed
    assert result["mode"] == mode
    if outcome == "REVIEW" and mode == "human_in_the_loop":
        assert result["directive"] == "REQUIRE_APPROVAL"
        assert result["approval"]["status"] == "PENDING"
    elif not allowed:
        assert result["directive"] == "BLOCK"
    assert load_nhi(store, "nhi-1")["control_state"] == "NORMAL"


def test_direct_decommission_requires_valid_evidence_before_any_write(store):
    make_nhi(store, lifecycle_stage="DEACTIVATED")
    service = LifecycleService(store)
    valid = {**EVIDENCE, "performed_by": "bob"}
    for raw in (None, {}, {**valid, "verified_by": "bob"}):
        with pytest.raises(LifecycleError):
            service.transition(
                "nhi-1", LifecycleStage.DECOMMISSIONED,
                actor="bob", event_type="DECOMMISSIONED",
                detail={"destruction_evidence": raw},
            )
        assert load_nhi(store, "nhi-1")["lifecycle_stage"] == "DEACTIVATED"
        assert store.list_lifecycle_events(nhi_id="nhi-1") == []
    result = service.transition(
        "nhi-1", LifecycleStage.DECOMMISSIONED,
        actor="bob", event_type="DECOMMISSIONED",
        detail={"destruction_evidence": valid},
    )
    assert result["lifecycle_stage"] == "DECOMMISSIONED"
    event = store.list_lifecycle_events(nhi_id="nhi-1")[0]
    assert event["detail"]["evidence_digest"].startswith("sha256:")
    assert any(e["detail"].get("event_id") == event["event_id"] for e in store.list_audit_events())


@pytest.mark.parametrize("old,new", [
    ("CREATION", "REGISTERED"), ("PERMISSION_CHANGE", "ACTIVE"),
    ("TERMINATION", "DEACTIVATED"), ("DISPOSED", "DECOMMISSIONED"),
])
def test_existing_database_is_migrated_idempotently(tmp_path, old, new):
    path = str(tmp_path / "legacy.db")
    db = SQLiteStorage(path)
    make_nhi(db)
    # Simulate the on-disk data written by the previous application version.
    data = load_nhi(db, "nhi-1")
    data["lifecycle_stage"] = old
    db._conn.execute("UPDATE nhi_identities SET data=? WHERE nhi_id='nhi-1'", (json.dumps(data),))
    db._conn.commit()
    db.close()
    for _ in range(2):
        db = SQLiteStorage(path)
        assert db.get_nhi_record("nhi-1")["lifecycle_stage"] == new
        assert {s.value for s in LifecycleStage} == {
            "REGISTERED", "ACTIVE", "DEACTIVATED", "DECOMMISSIONED",
        }
        db.close()


@pytest.mark.parametrize("anomaly", [False, True])
def test_measured_spike_combines_only_with_independent_anomaly(store, anomaly):
    make_nhi(store)
    make_profile(store)
    clock = Clock()
    svc = ControlService(
        store, settings=replace(GovernanceSettings(), control_mode="monitor"),
        tracker=UsageRateTracker(clock),
    )
    warm_up(svc, clock)
    if anomaly:
        record = load_nhi(store, "nhi-1")
        record["known_sources"] = ["10.0.0.1"]
        store.upsert_nhi("nhi-1", record)
    for index in range(6):
        result = svc.authorize_call(call(event_id=f"spike-{index}", source_ip="203.0.113.9"))
    assert "AGENT_CALL_RATE_SPIKE" in {r["rule_id"] for r in result["rules"]}
    assert result["verdict"] == ("DENY" if anomaly else "REVIEW")
    assert result["allowed"] is (not anomaly)
    assert load_nhi(store, "nhi-1")["control_state"] == "NORMAL"


def test_approved_review_never_overrides_new_lifecycle_deny(store):
    make_nhi(store)
    incomplete_profile(store)
    svc = ControlService(store, settings=replace(GovernanceSettings(), control_mode="human_in_the_loop"))
    observation = call(permission="WRITE", resource="acme/other", event_id="same-request")
    first = svc.authorize_call(observation)
    _, grant = svc.approvals.approve(first["decision_id"], actor="alice", reason="검토 완료")
    record = load_nhi(store, "nhi-1")
    record["lifecycle_stage"] = "DEACTIVATED"
    store.upsert_nhi("nhi-1", record)
    retry = svc.authorize_call(observation, grant_token=grant)
    assert retry["verdict"] == "DENY" and retry["allowed"] is False
    assert retry["grant_redeemed"] is False


def test_reanalysis_records_permission_change_without_changing_active_state(store, low_risk_nhi):
    from agents.pipeline import NHIAnalysisPipeline
    from processing import persist_analysis
    pipeline = NHIAnalysisPipeline()
    first = pipeline.analyze_github_nhi(low_risk_nhi)
    persist_analysis(store, first)
    low_risk_nhi.raw_permissions["contents"] = "write"
    second = pipeline.analyze_github_nhi(low_risk_nhi)
    persist_analysis(store, second)
    assert load_nhi(store, first.profile.nhi_id)["lifecycle_stage"] == "ACTIVE"
    events = store.list_lifecycle_events(nhi_id=first.profile.nhi_id)
    changes = [e for e in events if e["event_type"] == "PERMISSION_CHANGE"]
    assert len(changes) == 1 and changes[0]["stage"] == "ACTIVE"
    assert "WRITE" in changes[0]["detail"]["after"]["permissions"]


def test_retry_after_mode_change_opens_a_real_approval_hold(store):
    make_nhi(store)
    incomplete_profile(store)
    observation = call(permission="WRITE", resource="acme/other", event_id="mode-change")
    settings = GovernanceSettings()
    monitor = ControlService(store, settings=replace(settings, control_mode="monitor"))
    assert monitor.authorize_call(observation)["allowed"] is True
    human = ControlService(store, settings=replace(settings, control_mode="human_in_the_loop"))
    retry = human.authorize_call(observation)
    assert retry["allowed"] is False
    assert retry["directive"] == "REQUIRE_APPROVAL"
    assert retry["approval"]["status"] == "PENDING"
