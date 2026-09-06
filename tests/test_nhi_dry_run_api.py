"""POST /nhi/{nhi_id}/dry-run — API 엔드포인트 테스트.

recommended_action 기준으로 실제 변경 없이 예상 조치 결과만 계산하는지
확인한다. 실행/승인(권한 변경)은 이 단계에서 구현하지 않았으므로 다루지
않는다.
"""

from __future__ import annotations

import os

import pytest

from core.config import reset_settings


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
