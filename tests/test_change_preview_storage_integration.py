"""agents/dry_run_service.py::get_latest_analysis_snapshot() 통합 테스트.

새 저장소 코드를 추가하지 않고 기존 `Storage.list_nhi_analyses()`를 그대로
재사용하는지, 그리고 그 결과를 `build_change_preview()`에 바로 넘겼을 때
(1) 최신 분석이 재현 가능한 경우와 (2) `replay_snapshot`이 없는 과거/합성
분석(예: 데모 workspace처럼 파이프라인을 거치지 않고 저장된 경우) 모두
안전하게 처리되는지 확인한다.
"""

from __future__ import annotations

import pytest

from agents.dry_run_service import build_change_preview, get_latest_analysis_snapshot
from agents.pipeline import NHIAnalysisPipeline
from core.nhi_models import AnalysisSignals, RecommendedAction
from processing.analysis_persistence import persist_analysis
from storage.sqlite_store import SQLiteStorage
from tests.test_nhi_agents import make_finding


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def test_returns_none_when_nhi_has_no_analysis(store):
    assert get_latest_analysis_snapshot(store, "nhi:nonexistent") is None


def test_returns_latest_snapshot_saved_through_pipeline_and_feeds_change_preview(store):
    finding = make_finding(
        file_path="config/production/support_bot.env",
        raw_scopes=["channels:history", "chat:write", "admin.users:write"],
        credential_active=True,
        credential_revoked=False,
        resources=[{"name": "general"}],
    )
    signals = AnalysisSignals(repository="acme/support", repository_public=True)
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    persist_analysis(store, analysis)

    nhi_id = analysis.profile.nhi_id
    snapshot = get_latest_analysis_snapshot(store, nhi_id)

    assert snapshot is not None
    assert snapshot["replay_snapshot"]["signals"]
    assert snapshot["replay_snapshot"]["finding"]

    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value
    preview = build_change_preview(nhi_id, snapshot)

    assert preview.applicable is True
    assert preview.risk_after.score < preview.risk_before.score


def test_newest_snapshot_is_returned_when_nhi_has_multiple_analyses(store):
    finding = make_finding(credential_active=True, raw_scopes=["channels:history"])
    signals = AnalysisSignals(repository="acme/support")
    pipeline = NHIAnalysisPipeline()

    first = pipeline.analyze_finding(finding, signals=signals)
    persist_analysis(store, first)

    signals2 = AnalysisSignals(repository="acme/support", owner="platform-team")
    second = pipeline.analyze_finding(finding, signals=signals2)
    persist_analysis(store, second)

    nhi_id = second.profile.nhi_id
    snapshot = get_latest_analysis_snapshot(store, nhi_id)

    assert snapshot["owner"] == "platform-team"


def test_legacy_analysis_without_replay_snapshot_is_handled_gracefully(store):
    """데모 workspace처럼 파이프라인을 거치지 않고 저장된(또는 이 기능 도입 이전)
    분석은 `replay_snapshot`이 없다 — 조회는 되지만 Change Preview는 계산 불가로 표시된다.
    """
    legacy_analysis = {
        "fingerprint": "sha256:legacy0011",
        "repository": "acme/legacy",
        "file_path": "config/legacy.env",
        "line_number": 1,
        "masked_value": "xoxb-****",
        "discovery": {"nhi_id": "nhi:legacy-1", "nhi_name": "legacy-bot", "nhi_type": "SLACK_BOT"},
        "context_analysis": {"environment": "production"},
        "permission_detail": {"permissions": ["READ", "WRITE"], "raw_scopes": []},
        "risk_score": 70,
        "risk_level": "HIGH",
        "recommended_action": "TOKEN_REVOCATION",
        "blast_radius": {"connected_services": ["Slack"]},
        "analyzed_at": "2024-01-01T00:00:00+00:00",
        # 이 기능 도입 이전 레코드를 흉내내기 위해 replay_snapshot 자체를 넣지 않는다.
    }
    store.bind_credential_to_nhi(
        legacy_analysis["fingerprint"], "nhi:legacy-1", confidence=0.9, evidence=[]
    )
    store.save_analysis(
        legacy_analysis,
        repository=legacy_analysis["repository"],
        fingerprint=legacy_analysis["fingerprint"],
    )

    snapshot = get_latest_analysis_snapshot(store, "nhi:legacy-1")
    assert snapshot is not None
    assert "replay_snapshot" not in snapshot

    preview = build_change_preview("nhi:legacy-1", snapshot)

    assert preview.applicable is False
    assert preview.not_applicable_reason
    assert preview.unknown_notes
