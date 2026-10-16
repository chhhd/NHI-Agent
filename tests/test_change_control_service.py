"""backend/services/change_control_service.py — 승인 등급·직무분리·적용·롤백.

Change Preview 엔진(`agents/dry_run_service.py`)은 전혀 수정하지 않고 그대로
재사용하는지, InventoryStateExecutor가 NHI Lifecycle 상태만 바꾸고 실제
Provider 는 절대 호출하지 않는지(`provider_call == "not_configured"`), 승인
없이는 적용되지 않는지, 요청자==승인자 조합이 거부되는지, 중복 적용/중복
롤백이 막히는지, 롤백 유효 기간이 지나면 거부되는지, 실패해도 상태가
안전하게 유지되는지를 확인한다.
"""

from __future__ import annotations

import threading

import pytest

from agents.dry_run_service import get_latest_analysis_snapshot
from agents.pipeline import NHIAnalysisPipeline
from backend.services.change_control_service import ChangeControlService, InventoryStateExecutor
from core.change_control_models import (
    ApprovalTier,
    ChangeExecutionError,
    ChangeNotAllowed,
    ChangeStatus,
    SeparationOfDutiesError,
    StateConflict,
)
from core.nhi_lifecycle_models import NHILifecycleStatus
from core.nhi_models import AnalysisSignals, RecommendedAction
from processing.analysis_persistence import persist_analysis
from storage.sqlite_store import SQLiteStorage
from tests.test_nhi_agents import make_finding


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


@pytest.fixture
def service(store):
    return ChangeControlService(store)


def _persist_with_action(store, action: RecommendedAction, **finding_kwargs) -> str:
    """분석을 실제로 저장한 뒤, 최신 snapshot의 recommended_action만 원하는
    값으로 바꿔 다시 저장한다 — Change Preview가 읽는 입력(replay_snapshot)은
    실제 파이프라인 결과 그대로다."""
    finding = make_finding(credential_active=True, **finding_kwargs)
    signals = AnalysisSignals(repository="acme/support")
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    persist_analysis(store, analysis)
    nhi_id = analysis.profile.nhi_id
    snapshot = get_latest_analysis_snapshot(store, nhi_id)
    snapshot["recommended_action"] = action.value
    store.save_analysis(snapshot, repository="acme/support", fingerprint=finding.fingerprint)
    return nhi_id


# ---------------------------------------------------------------------------
# propose() — Change Preview 재계산 + 승인 등급
# ---------------------------------------------------------------------------
def test_propose_critical_tier_requires_impact_acknowledged(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)

    with pytest.raises(ChangeNotAllowed):
        service.propose(nhi_id, requested_by="alice", reason="탈취 의심", idempotency_key="k1")


def test_propose_critical_tier_succeeds_with_acknowledgement(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)

    change = service.propose(
        nhi_id, requested_by="alice", reason="탈취 의심", idempotency_key="k1",
        impact_acknowledged=True,
    )

    assert change.tier is ApprovalTier.CRITICAL
    assert change.status is ChangeStatus.PENDING_APPROVAL
    assert change.preview["recommended_action"] == "TOKEN_REVOCATION"
    assert change.executor_result == {}  # 아직 적용 전


def test_propose_low_tier_is_auto_approved(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.MONITOR)

    change = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="k-low")

    assert change.tier is ApprovalTier.LOW
    assert change.status is ChangeStatus.APPROVED
    assert change.approved_by == "system-auto-approval"


def test_propose_without_analysis_history_is_rejected(store, service):
    store.upsert_nhi("nhi:no-analysis", {"nhi_id": "nhi:no-analysis", "nhi_name": "x"})
    with pytest.raises(ChangeNotAllowed):
        service.propose("nhi:no-analysis", requested_by="alice", reason="", idempotency_key="k2")


def test_propose_is_idempotent_on_same_key(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.MONITOR)

    first = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="same-key")
    second = service.propose(nhi_id, requested_by="bob", reason="다른요청", idempotency_key="same-key")

    assert first.change_id == second.change_id
    assert second.requested_by == "alice"  # 두 번째 호출 내용이 아니라 처음 그대로


# ---------------------------------------------------------------------------
# approve() — 직무 분리
# ---------------------------------------------------------------------------
def test_approve_rejects_same_requester_and_approver(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.SCOPE_REDUCTION)
    change = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="k3")

    with pytest.raises(SeparationOfDutiesError):
        service.approve(change.change_id, approved_by="alice")


def test_approve_by_different_actor_succeeds(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.SCOPE_REDUCTION)
    change = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="k4")

    approved = service.approve(change.change_id, approved_by="bob")

    assert approved.status is ChangeStatus.APPROVED
    assert approved.approved_by == "bob"


def test_approve_already_approved_raises_state_conflict(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.SCOPE_REDUCTION)
    change = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="k5")
    service.approve(change.change_id, approved_by="bob")

    with pytest.raises(StateConflict):
        service.approve(change.change_id, approved_by="carol")


# ---------------------------------------------------------------------------
# apply() — 승인 없이 실행 불가 / 내부 상태만 변경 / 중복 실행 방지
# ---------------------------------------------------------------------------
def test_apply_without_approval_is_rejected(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.SCOPE_REDUCTION)
    change = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="k6")

    with pytest.raises(StateConflict):
        service.apply(change.change_id, actor="bob")


def test_apply_token_revocation_deactivates_lifecycle_and_marks_internal_only(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k7", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")

    applied = service.apply(change.change_id, actor="bob")

    assert applied.status is ChangeStatus.APPLIED
    assert applied.executor_result["provider_call"] == "not_configured"
    assert applied.executor_result["scope"] == "internal_only"
    state = store.get_nhi_lifecycle_state(nhi_id)
    assert state["status"] == NHILifecycleStatus.DEACTIVATED.value


def test_apply_scope_reduction_only_records_permission_event_not_lifecycle_change(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.SCOPE_REDUCTION)
    change = service.propose(nhi_id, requested_by="alice", reason="", idempotency_key="k8")
    service.approve(change.change_id, approved_by="bob")

    applied = service.apply(change.change_id, actor="bob")

    assert applied.executor_result["lifecycle_event"] == "PERMISSION_CHANGED"
    assert applied.executor_result["provider_call"] == "not_configured"
    history = store.get_nhi_lifecycle_history(nhi_id)
    assert any(h["event_type"] == "PERMISSION_CHANGED" for h in history)
    # 상태 자체(REGISTERED/ACTIVE)는 건드리지 않는다 — DEACTIVATED로만 안 바뀌면 된다.
    assert store.get_nhi_lifecycle_state(nhi_id)["status"] != NHILifecycleStatus.DEACTIVATED.value


def test_apply_is_idempotent_and_does_not_duplicate_lifecycle_events(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k9", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")
    service.apply(change.change_id, actor="bob")

    second = service.apply(change.change_id, actor="bob")  # 같은 요청 재실행

    assert second.status is ChangeStatus.APPLIED
    history = store.get_nhi_lifecycle_history(nhi_id)
    deactivated_events = [h for h in history if h["event_type"] == "DEACTIVATED"]
    assert len(deactivated_events) == 1  # 중복 실행되지 않았다


def test_concurrent_apply_only_one_thread_executes(store, service):
    """동시에 10개 스레드가 같은 승인된 변경을 적용해도 실행기는 한 번만 실행된다."""
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k10", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")

    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(10)

    def _attempt():
        barrier.wait()
        try:
            result = service.apply(change.change_id, actor="bob")
            with lock:
                results.append(("ok", result.status))
        except StateConflict:
            with lock:
                results.append(("conflict", None))

    threads = [threading.Thread(target=_attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(outcome == "ok" for outcome, _ in results)  # 전부 성공(멱등) 하거나 conflict, 중복 실행은 없다
    history = store.get_nhi_lifecycle_history(nhi_id)
    assert len([h for h in history if h["event_type"] == "DEACTIVATED"]) == 1


def test_apply_failure_leaves_change_failed_and_lifecycle_untouched(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k11", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")

    class _BoomExecutor:
        name = "boom"

        def apply(self, change, nhi):
            raise RuntimeError("provider adapter unavailable")

        def rollback(self, change, nhi):
            raise RuntimeError("unused")

    broken_service = ChangeControlService(store, executor=_BoomExecutor())
    with pytest.raises(ChangeExecutionError):
        broken_service.apply(change.change_id, actor="bob")

    failed = broken_service.get(change.change_id)
    assert failed.status is ChangeStatus.FAILED
    assert "provider adapter unavailable" in failed.failure_reason
    # Lifecycle은 전혀 바뀌지 않았다 — REGISTERED(초기화만 됐거나) 상태 그대로.
    state = store.get_nhi_lifecycle_state(nhi_id)
    assert state["status"] != NHILifecycleStatus.DEACTIVATED.value


# ---------------------------------------------------------------------------
# rollback() — 유효 기간 검증 / 실패 시 안전 복귀
# ---------------------------------------------------------------------------
def test_rollback_within_grace_period_reactivates_lifecycle(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k12", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")
    service.apply(change.change_id, actor="bob")

    rolled_back = service.rollback(change.change_id, actor="bob")

    assert rolled_back.status is ChangeStatus.ROLLED_BACK
    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.ACTIVE.value


def test_rollback_after_expiry_is_rejected(store):
    expired_service = ChangeControlService(store, rollback_grace_hours=-1)  # 적용 즉시 만료되게
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = expired_service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k13", impact_acknowledged=True
    )
    expired_service.approve(change.change_id, approved_by="bob")
    expired_service.apply(change.change_id, actor="bob")

    with pytest.raises(StateConflict):
        expired_service.rollback(change.change_id, actor="bob")


def test_rollback_without_apply_is_rejected(store, service):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k14", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")

    with pytest.raises(StateConflict):
        service.rollback(change.change_id, actor="bob")


def test_rollback_failure_reverts_to_applied_not_stuck_or_wrongly_rolled_back(store):
    nhi_id = _persist_with_action(store, RecommendedAction.TOKEN_REVOCATION)
    service = ChangeControlService(store)
    change = service.propose(
        nhi_id, requested_by="alice", reason="", idempotency_key="k15", impact_acknowledged=True
    )
    service.approve(change.change_id, approved_by="bob")
    service.apply(change.change_id, actor="bob")

    class _BoomOnRollback:
        name = "boom-rollback"

        def apply(self, change, nhi):
            return {"executor": self.name, "provider_call": "not_configured"}

        def rollback(self, change, nhi):
            raise RuntimeError("rollback adapter unavailable")

    broken_service = ChangeControlService(store, executor=_BoomOnRollback())
    with pytest.raises(ChangeExecutionError):
        broken_service.rollback(change.change_id, actor="bob")

    reverted = broken_service.get(change.change_id)
    assert reverted.status is ChangeStatus.APPLIED  # ROLLING_BACK에 멈추거나 ROLLED_BACK으로 잘못 넘어가지 않음
    assert "rollback adapter unavailable" in reverted.failure_reason


# ---------------------------------------------------------------------------
# InventoryStateExecutor — 절대 실제 Provider 를 호출하지 않는다
# ---------------------------------------------------------------------------
def test_inventory_state_executor_never_sets_provider_call_to_configured():
    import inspect

    source = inspect.getsource(InventoryStateExecutor)
    assert '"provider_call": "not_configured"' in source
    assert "requests." not in source
    assert "httpx" not in source
