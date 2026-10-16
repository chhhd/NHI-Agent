"""POST /nhi/{nhi_id}/dry-run — API 엔드포인트 테스트.

recommended_action 기준으로 실제 변경 없이 예상 조치 결과만 계산하는지
확인한다. 실행/승인(권한 변경)은 이 단계에서 구현하지 않았으므로 다루지
않는다.
"""

from __future__ import annotations

import os

import pytest

from core.config import reset_settings
from core.nhi_models import AnalysisSignals, RecommendedAction


@pytest.fixture(autouse=True)
def _no_default_tokens(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    reset_settings()
    yield
    reset_settings()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """임시 DB 경로를 지정한 뒤 앱을 로딩한다 (프로젝트 디렉터리 오염 방지)."""
    os.environ["NHI_DB_PATH"] = str(tmp_path_factory.mktemp("db") / "test.db")
    from fastapi.testclient import TestClient

    import api.app as app_module

    return TestClient(app_module.app)


def _seed(app_module, nhi_id, *, risk_score, recommended_action):
    app_module.storage.upsert_nhi(
        nhi_id,
        {
            "nhi_id": nhi_id,
            "provider": "aws",
            "nhi_name": "ci-deploy-user",
            "risk_score": risk_score,
            "risk_level": "HIGH",
            "recommended_action": recommended_action,
        },
    )


# ---------------------------------------------------------------------------
# 정상 흐름
# ---------------------------------------------------------------------------
def test_dry_run_returns_requested_fields(client):
    import api.app as app_module

    _seed(app_module, "aws:dry-run-1", risk_score=80, recommended_action="TOKEN_REVOCATION")

    response = client.post("/nhi/aws:dry-run-1/dry-run")

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {
        "target_nhi_id",
        "recommended_action",
        "expected_changes",
        "risk_before",
        "risk_after_estimate",
    }
    assert body["target_nhi_id"] == "aws:dry-run-1"
    assert body["recommended_action"] == "TOKEN_REVOCATION"
    assert body["risk_before"] == 80
    assert body["risk_after_estimate"] == 0
    assert body["expected_changes"]


def test_dry_run_does_not_mutate_stored_record(client):
    """dry-run 은 조회만 할 뿐 저장된 NHI 레코드를 바꾸지 않는다."""
    import api.app as app_module

    _seed(app_module, "aws:dry-run-2", risk_score=60, recommended_action="MONITOR")

    before = client.get("/nhi/aws:dry-run-2").json()
    client.post("/nhi/aws:dry-run-2/dry-run")
    after = client.get("/nhi/aws:dry-run-2").json()

    assert before == after


def test_dry_run_reflects_scope_reduction_action(client):
    import api.app as app_module

    _seed(app_module, "aws:dry-run-3", risk_score=70, recommended_action="SCOPE_REDUCTION")

    response = client.post("/nhi/aws:dry-run-3/dry-run")

    body = response.json()
    assert body["recommended_action"] == "SCOPE_REDUCTION"
    assert 0 < body["risk_after_estimate"] < 70


# ---------------------------------------------------------------------------
# 예외 처리
# ---------------------------------------------------------------------------
def test_dry_run_returns_404_for_unknown_nhi(client):
    response = client.post("/nhi/does-not-exist/dry-run")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 기존 GET /nhi/{nhi_id} 는 영향받지 않았는지
# ---------------------------------------------------------------------------
def test_existing_get_nhi_detail_endpoint_still_works(client):
    import api.app as app_module

    _seed(app_module, "aws:dry-run-4", risk_score=10, recommended_action="MONITOR")

    response = client.get("/nhi/aws:dry-run-4")

    assert response.status_code == 200
    assert response.json()["nhi_id"] == "aws:dry-run-4"


# ---------------------------------------------------------------------------
# Change Preview — 분석 snapshot이 있을 때 추가되는 change_preview 섹션
# ---------------------------------------------------------------------------
def _seed_real_analysis(app_module, *, recommended_action):
    """실제 파이프라인으로 분석·저장해 Change Preview 재현 입력(replay_snapshot)을 확보한다.

    `recommended_action`을 강제로 지정할 때는 `analysis.recommendations`에
    우선순위 0인 권고를 추가한다 — `NHIAnalysis.recommended_action`은
    `recommendations`에서 계산되는 속성이라 직접 대입할 수 없고, 분석 결과를
    실제로 저장(`persist_analysis`)하기 전에 바꿔야 저장되는 snapshot(and그
    안의 `recommended_action` 필드)에도 반영된다.
    """
    from core.nhi_models import Recommendation
    from tests.test_nhi_agents import make_finding

    finding = make_finding(
        file_path="config/production/support_bot.env",
        raw_scopes=["channels:history", "chat:write", "admin.users:write"],
        credential_active=True,
        credential_revoked=False,
        resources=[{"name": "general"}],
    )
    signals = AnalysisSignals(repository="acme/support", repository_public=True)
    analysis = app_module.nhi_pipeline.analyze_finding(finding, signals=signals)
    if recommended_action is not None:
        analysis.recommendations.insert(
            0,
            Recommendation(
                action=RecommendedAction(recommended_action),
                priority=0,
                rationale="test override",
            ),
        )
    app_module.persist_analysis(app_module.storage, analysis)
    return analysis.profile.nhi_id


def test_dry_run_still_returns_legacy_fields_when_change_preview_is_attached(client):
    """change_preview가 추가돼도 기존 5개 필드는 그대로 존재한다(응답이 더 풍부해질 뿐)."""
    import api.app as app_module

    nhi_id = _seed_real_analysis(app_module, recommended_action="TOKEN_REVOCATION")

    response = client.post(f"/nhi/{nhi_id}/dry-run")

    assert response.status_code == 200
    body = response.json()
    for key in ("target_nhi_id", "recommended_action", "expected_changes", "risk_before", "risk_after_estimate"):
        assert key in body
    assert body["target_nhi_id"] == nhi_id
    assert body["recommended_action"] == "TOKEN_REVOCATION"


def test_dry_run_change_preview_contains_calculated_estimated_unknown_sections(client):
    import api.app as app_module

    nhi_id = _seed_real_analysis(app_module, recommended_action="TOKEN_REVOCATION")

    response = client.post(f"/nhi/{nhi_id}/dry-run")
    body = response.json()

    preview = body["change_preview"]
    assert preview["applicable"] is True
    assert preview["risk_after"]["score"] < preview["risk_before"]["score"]
    assert "NO_PLAINTEXT_CREDENTIAL" in preview["policy_diff"]["resolved_violations"]
    assert preview["data_quality"]["calculated_notes"]
    assert preview["data_quality"]["estimated_notes"]
    assert preview["data_quality"]["unknown_notes"]
    assert preview["service_dependency_impact"]
    assert all(
        item["confidence"] in {"calculated", "estimated", "unknown"}
        for item in preview["service_dependency_impact"]
    )


def test_dry_run_change_preview_absent_when_no_analysis_history_exists(client):
    """`upsert_nhi`만으로 만든(기존 테스트와 동일한) 레코드는 분석 이력이 없어 change_preview가 붙지 않는다."""
    import api.app as app_module

    _seed(app_module, "aws:no-history", risk_score=55, recommended_action="MONITOR")

    response = client.post("/nhi/aws:no-history/dry-run")
    body = response.json()

    assert "change_preview" not in body


def test_dry_run_does_not_mutate_credential_or_permission_state(client):
    """Change Preview가 붙어도 저장된 NHI 레코드의 권한/Credential 상태는 바뀌지 않는다."""
    import api.app as app_module

    nhi_id = _seed_real_analysis(app_module, recommended_action="TOKEN_REVOCATION")

    before = client.get(f"/nhi/{nhi_id}").json()
    client.post(f"/nhi/{nhi_id}/dry-run")
    after = client.get(f"/nhi/{nhi_id}").json()

    assert before["permissions"] == after["permissions"]
    assert before["risk_score"] == after["risk_score"]
    assert before == after
