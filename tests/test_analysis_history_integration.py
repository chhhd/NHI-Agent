"""실제 영속화 경로(persist_analysis)로 쌓인 스냅샷이 NHI 이력·비교에서 조회되는지 본다."""

from __future__ import annotations

import pytest

from agents.pipeline import NHIAnalysisPipeline
from backend.services.analysis_history import AnalysisHistoryService
from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
from core.nhi_models import Environment
from normalization import observation_from_inventory
from processing import persist_analysis
from storage.sqlite_store import SQLiteStorage


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def nhi(**overrides) -> GitHubNHIInput:
    values = dict(
        nhi_id="app-1",
        nhi_name="deploy-app",
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner="platform",
        environment=Environment.STAGING,
        raw_permissions={"contents": "read"},
        repositories=[RepositoryInfo(name="acme/backend", visibility="private")],
    )
    values.update(overrides)
    return GitHubNHIInput(**values)


#: 인벤토리 입력의 nhi_id("app-1")는 분석 시 "<provider>:<id>" 로 정규화되어 저장된다(GET /nhi 의 ID).
CANONICAL_ID = "github:app-1"


def analyze_and_save(store, item: GitHubNHIInput, revision: str, signals=None) -> None:
    store.save_observation(observation_from_inventory(item, source_event_id=revision))
    analysis = NHIAnalysisPipeline().analyze_github_nhi(item, signals=signals)
    persist_analysis(store, analysis, input_revision=revision)


def test_history_lists_snapshots_newest_first_and_compare_shows_what_changed(store):
    analyze_and_save(store, nhi(), "rev-1")
    # 권한이 늘고 Owner 가 사라진 재분석
    analyze_and_save(
        store,
        nhi(owner=None, raw_permissions={"contents": "write", "administration": "write"}),
        "rev-2",
    )
    service = AnalysisHistoryService(store)

    history = service.list_history(CANONICAL_ID)
    assert history["count"] == 2
    assert history["analyses"][0]["risk_score"] >= history["analyses"][1]["risk_score"]

    diff = service.compare(CANONICAL_ID)
    assert "ADMIN" in str(diff)  # 새로 생긴 권한이 변화 목록에 나타난다
    assert "OWNER_REQUIRED" in str(diff)  # Owner 제거로 새 정책 위반이 생겼다


def test_history_of_unknown_nhi_is_empty_and_compare_is_404_style(store):
    service = AnalysisHistoryService(store)
    assert service.list_history("ghost")["count"] == 0
    with pytest.raises(KeyError):
        service.compare("ghost")
