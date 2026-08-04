"""NHI 분석 / Agent 실행 API 엔드포인트 테스트 (네트워크·영속 DB 없음)."""

from __future__ import annotations

import os

import pytest

from core.config import reset_settings
from tests.test_nhi_agents import make_finding


@pytest.fixture(autouse=True)
def _no_github_token(monkeypatch):
    """Agent 실행 시 실제 GitHub 호출이 나가지 않게 한다."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
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


def _payload(**overrides):
    finding = make_finding(
        raw_scopes=["channels:history", "chat:write"],
        credential_active=True,
        account={"team": "Customer Support Team", "user": "customer-support-bot"},
        resources=[{"name": "general"}],
        **overrides,
    )
    return finding.to_dict()


def test_analyze_endpoint_returns_report(client):
    response = client.post(
        "/nhi/analyze",
        json={
            "full_name": "acme/support",
            "findings": [_payload()],
            "signals": {"repository_public": True},
        },
    )
    assert response.status_code == 200

    body = response.json()
    assert body["repository"] == "acme/support"
    assert body["summary"]["total"] == 1
    analysis = body["analyses"][0]
    assert analysis["nhi_name"] == "customer-support-bot"
    assert analysis["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert analysis["recommended_action"]
    assert body["graph"]["stats"]["NHI"] == 1


def test_analyze_endpoint_without_findings_returns_404(client):
    response = client.post("/nhi/analyze", json={"full_name": "acme/not-scanned"})
    assert response.status_code == 404


def test_analyze_endpoint_accepts_per_finding_signals(client):
    finding = _payload()
    response = client.post(
        "/nhi/analyze",
        json={
            "full_name": "acme/support",
            "findings": [finding],
            "signals_by_fingerprint": {
                finding["fingerprint"]: {"agent_status": "terminated", "repository_public": True}
            },
        },
    )
    body = response.json()
    analysis = body["analyses"][0]

    assert analysis["risk_level"] == "CRITICAL"
    assert "TERMINATED_AGENT_ACTIVE_TOKEN" in {
        rule["rule_id"] for rule in analysis["risk_detail"]["forced_rules"]
    }


def test_scope_translate_endpoint(client):
    response = client.post(
        "/nhi/scopes/translate",
        json={"scopes": ["channels:history", "chat:write"], "provider": "slack"},
    )
    assert response.status_code == 200
    assert response.json()["permissions"] == ["READ", "WRITE"]
    assert response.json()["highest_permission"] == "WRITE"


# ---------------------------------------------------------------------------
# 인벤토리 입력 (스캔 결과 없이 NHI 정보만으로)
# ---------------------------------------------------------------------------
def _inventory_nhi(**overrides):
    payload = {
        "nhi_id": "github-app-api-test",
        "nhi_name": "production-deployment-app",
        "nhi_type": "GITHUB_APP",
        "owner": None,
        "environment": "production",
        "active": True,
        "repositories": [
            {"name": "acme/backend", "visibility": "private", "is_sensitive": True},
            {"name": "acme/infrastructure", "visibility": "private", "is_sensitive": True},
            {"name": "acme/frontend", "visibility": "private", "is_sensitive": False},
        ],
        "raw_permissions": {
            "contents": "write",
            "administration": "write",
            "metadata": "read",
        },
        "last_used_at": "2025-01-01T00:00:00Z",
        "expires_at": None,
    }
    payload.update(overrides)
    return payload


def test_inventory_analyze_endpoint(client):
    response = client.post("/nhi/inventory/analyze", json={"nhi": _inventory_nhi()})
    assert response.status_code == 200

    body = response.json()
    assert body["source"] == "inventory"
    assert body["nhi_type"] == "GITHUB_APP"
    assert body["permissions"] == ["READ", "WRITE", "ADMIN"]
    assert body["risk_level"] in {"CRITICAL", "HIGH"}
    assert body["recommended_action"]
    # 요약 뒤에 근거가 함께 온다 (대시보드 상세 화면 입력)
    for key in ("risk_detail", "policy", "blast_radius", "permission_detail"):
        assert key in body


def test_inventory_analyze_validation_error(client):
    """필수 값(nhi_id)이 없으면 분석까지 가지 않고 422 로 걸러진다."""
    invalid = _inventory_nhi()
    invalid.pop("nhi_id")

    response = client.post("/nhi/inventory/analyze", json={"nhi": invalid})
    assert response.status_code == 422


def test_inventory_analyze_rejects_unknown_enum_value(client):
    response = client.post(
        "/nhi/inventory/analyze", json={"nhi": _inventory_nhi(nhi_type="아무문자열")}
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Agent 실행
# ---------------------------------------------------------------------------
def test_agent_run_endpoint(client):
    response = client.post(
        "/agent/nhi/run",
        json={
            "nhi": _inventory_nhi(),
            "goal": "고위험 NHI 를 분석하고 정책 판정을 확인한다.",
            "allow_secret_scan": True,
            "allow_policy_evaluation": True,
        },
    )
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "COMPLETED"
    assert body["replan_count"] == 1
    assert body["nhi_analysis"]["risk_level"] in {"CRITICAL", "HIGH"}
    assert body["policy_evaluation"]["policy_evaluated"] is True

    plan = [step["action_type"] for step in body["plan"]]
    assert plan[0] == "ANALYZE_NHI"
    assert "SCAN_SECRETS" in plan
    assert plan[-1] == "COMPLETE"

    origins = {step["action_type"]: step["created_by"] for step in body["plan"]}
    assert origins["ANALYZE_NHI"] == "INITIAL_PLAN"
    assert origins["SCAN_SECRETS"] == "REPLANNER"

    # 토큰이 없으므로 스캔은 실행되지 않았음을 명시한다.
    assert body["secret_scan"]["scan_executed"] is False


# ---------------------------------------------------------------------------
# 운영 Backend / Dashboard
# ---------------------------------------------------------------------------
def test_project_and_dashboard_endpoints(client):
    response = client.post(
        "/projects",
        json={
            "name": "API dashboard project",
            "repository": "acme/dashboard-api",
            "description": "Backend API coverage",
        },
    )
    assert response.status_code == 201
    project = response.json()
    assert project["repository"] == "acme/dashboard-api"

    listing = client.get("/projects")
    assert listing.status_code == 200
    assert any(
        item["project_id"] == project["project_id"]
        for item in listing.json()["projects"]
    )

    summary = client.get("/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json()["project_count"] >= 1


def test_connector_and_dashboard_static_assets(client):
    response = client.post(
        "/connectors/github",
        json={"name": "GitHub dashboard connector"},
    )
    assert response.status_code == 201
    assert response.json()["status"] == "PENDING"
    assert "secret_ref" not in response.json()

    page = client.get("/dashboard/")
    assert page.status_code == 200
    assert "NHI Sentinel" in page.text

    script = client.get("/dashboard/app.js")
    assert script.status_code == 200
    assert "/dashboard/summary" in script.text


def test_demo_workspace_api_and_keyless_demo_review(client):
    created = client.post("/demo/workspace")
    assert created.status_code == 201
    assert created.json()["contains_real_secrets"] is False

    projects = client.get("/projects").json()["projects"]
    assert sum(
        item.get("metadata", {}).get("demo_workspace") == "nhi-sentinel-demo-v1"
        for item in projects
    ) == 3

    demo_actions = [
        item
        for item in client.get("/actions").json()["actions"]
        if item["demo_workspace"]
    ]
    assert len(demo_actions) == 5
    approved = client.post(
        f"/demo/reviews/{demo_actions[0]['action_id']}/approve",
        json={"actor": "test-reviewer", "reason": "합성 데이터 승인 테스트"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"

    cleared = client.delete("/demo/workspace")
    assert cleared.status_code == 200
    assert cleared.json()["deleted"]["projects"] == 3
    assert not any(
        item.get("metadata", {}).get("demo_workspace") == "nhi-sentinel-demo-v1"
        for item in client.get("/projects").json()["projects"]
    )


def test_global_relationship_graph_endpoint(client):
    analyzed = client.post(
        "/nhi/inventory/analyze",
        json={"nhi": _inventory_nhi(nhi_id="graph-dashboard-nhi")},
    )
    assert analyzed.status_code == 200

    graph = client.get("/graph")
    assert graph.status_code == 200
    body = graph.json()
    assert body["stats"]["NHI"] >= 1
    assert any(node["type"] == "CREDENTIAL" for node in body["nodes"])
    assert any(edge["type"] == "AUTHENTICATES_WITH" for edge in body["edges"])
