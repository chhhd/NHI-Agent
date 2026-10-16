"""processing/analysis_persistence.py::persist_analysis() 의 NHI 생명주기 초기화.

신규 NHI가 최초로 분석·저장될 때 `storage.initialize_nhi_lifecycle()`이
호출되어 `REGISTERED` 상태 + `CREATED` 이벤트가 자동으로 남는지, 재분석 시
기존 상태를 덮어쓰거나 이벤트를 중복 생성하지 않는지, 저장 중간 단계가
실패하면 생명주기 데이터가 전혀 생기지 않는지(정합성)를 확인한다.
"""

from __future__ import annotations

import pytest

from agents.pipeline import NHIAnalysisPipeline
from core.nhi_lifecycle_models import NHILifecycleEventType, NHILifecycleStatus
from core.nhi_models import AnalysisSignals
from processing import persist_analysis, persist_report
from storage.sqlite_store import SQLiteStorage
from tests.test_nhi_agents import make_finding


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def _analysis(**signal_overrides):
    finding = make_finding(credential_active=True)
    return NHIAnalysisPipeline().analyze_finding(
        finding,
        repository="acme/support",
        signals=AnalysisSignals(repository_public=True, **signal_overrides),
    )


# ---------------------------------------------------------------------------
# 신규 NHI 최초 등록
# ---------------------------------------------------------------------------
def test_first_persist_registers_lifecycle_state_and_created_event(store):
    analysis = _analysis()

    result = persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    state = store.get_nhi_lifecycle_state(nhi_id)
    assert state is not None
    assert state["status"] == NHILifecycleStatus.REGISTERED.value

    history = store.get_nhi_lifecycle_history(nhi_id)
    assert len(history) == 1
    assert history[0]["event_type"] == NHILifecycleEventType.CREATED.value
    assert history[0]["from_status"] is None
    assert history[0]["to_status"] == NHILifecycleStatus.REGISTERED.value
    assert history[0]["actor"] == "system"
    # `detail`은 다른 보안 이벤트와 동일하게 저장 전 redaction을 거친다
    # (`storage/sqlite_store.py::_insert_nhi_lifecycle_history_locked`).
    # analysis_id처럼 긴 불투명 식별자는 `usage_event_adapter.py`의
    # `event_id`와 동일하게 끝 4자만 남고 마스킹된다 — 원문 전체가 아니라
    # 상관관계 확인용 꼬리만 보존되는 것이 의도된 동작이다.
    assert history[0]["detail"]["analysis_id"].endswith(result["analysis_id"][-4:])
    assert history[0]["detail"]["analysis_id"] != result["analysis_id"]
    assert history[0]["detail"]["source"] == analysis.source.value


def test_persist_report_registers_each_distinct_nhi_once(store):
    from core.nhi_models import NHIAnalysisReport

    first = _analysis()
    second_finding = make_finding(secret_type="GITHUB_PAT", provider="github", credential_active=True)
    second = NHIAnalysisPipeline().analyze_finding(
        second_finding, repository="acme/infra", signals=AnalysisSignals(repository_public=False)
    )
    report = NHIAnalysisReport(repository="acme/multi", analyses=[first, second])

    persist_report(store, report)

    for analysis in (first, second):
        history = store.get_nhi_lifecycle_history(analysis.profile.nhi_id)
        assert len(history) == 1
        assert history[0]["event_type"] == NHILifecycleEventType.CREATED.value


# ---------------------------------------------------------------------------
# 재분석 — 중복 이벤트 없음, 기존 상태 보존
# ---------------------------------------------------------------------------
def test_reanalysis_does_not_duplicate_created_event(store):
    analysis = _analysis()

    persist_analysis(store, analysis)
    persist_analysis(store, analysis)  # 동일 NHI 재분석 저장
    persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    history = store.get_nhi_lifecycle_history(nhi_id)
    assert len(history) == 1
    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.REGISTERED.value


def test_reanalysis_does_not_overwrite_advanced_lifecycle_status(store):
    """관리자가 이미 ACTIVE/DEACTIVATED 등으로 전이시킨 뒤 재분석이 들어와도
    그 상태를 REGISTERED로 되돌리면 안 된다."""
    analysis = _analysis()
    persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    store.update_nhi_lifecycle_status(
        nhi_id,
        NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED,
        actor="security@example.com",
    )

    persist_analysis(store, analysis)  # 재분석(예: 스케줄 재스캔)

    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.ACTIVE.value
    history = store.get_nhi_lifecycle_history(nhi_id)
    assert [item["event_type"] for item in history] == [
        NHILifecycleEventType.CREATED.value,
        NHILifecycleEventType.ACTIVATED.value,
    ]


# ---------------------------------------------------------------------------
# 분석 저장 실패 시 생명주기 데이터 정합성
# ---------------------------------------------------------------------------
def test_lifecycle_is_not_initialized_when_save_analysis_fails(store, monkeypatch):
    """분석 저장(save_analysis)이 실패하면 생명주기 초기화도 전혀 일어나지
    않아야 한다 — 분석도 없이 NHI만 '등록됨'으로 보이는 불일치를 막는다."""
    analysis = _analysis()

    def _boom(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(store, "save_analysis", _boom)

    with pytest.raises(RuntimeError):
        persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    assert store.get_nhi_lifecycle_state(nhi_id) is None
    assert store.get_nhi_lifecycle_history(nhi_id) == []


def test_lifecycle_is_not_initialized_when_action_service_fails(store, monkeypatch):
    """persist_analysis의 마지막 단계(ActionService) 이전에 실패해도 동일하게
    생명주기 데이터가 생기지 않아야 한다."""
    analysis = _analysis()

    import processing.analysis_persistence as persistence_module

    class _BoomActionService:
        def __init__(self, storage):
            pass

        def create_from_analysis(self, *args, **kwargs):
            raise RuntimeError("action service unavailable")

    monkeypatch.setattr(persistence_module, "ActionService", _BoomActionService)

    with pytest.raises(RuntimeError):
        persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    assert store.get_nhi_lifecycle_state(nhi_id) is None
    assert store.get_nhi_lifecycle_history(nhi_id) == []


def test_lifecycle_initializes_successfully_after_a_previous_failed_attempt(store, monkeypatch):
    """실패한 시도 이후 재시도가 성공하면, 그 때는 정상적으로 초기화돼야 한다."""
    analysis = _analysis()

    def _boom(*args, **kwargs):
        raise RuntimeError("transient failure")

    monkeypatch.setattr(store, "save_analysis", _boom)
    with pytest.raises(RuntimeError):
        persist_analysis(store, analysis)
    monkeypatch.undo()

    persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.REGISTERED.value
    assert len(store.get_nhi_lifecycle_history(nhi_id)) == 1


# ---------------------------------------------------------------------------
# 민감정보 미저장 (detail/note에 원문 Credential 없음)
# ---------------------------------------------------------------------------
def test_created_event_detail_contains_no_raw_credential(store):
    analysis = _analysis()

    persist_analysis(store, analysis)

    history = store.get_nhi_lifecycle_history(analysis.profile.nhi_id)
    detail = history[0]["detail"]
    assert set(detail.keys()) == {"source", "provider", "analysis_id"}
