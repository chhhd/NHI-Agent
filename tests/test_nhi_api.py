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


def test_agent_access_profile_scope_and_impersonation_decision_api(client, monkeypatch):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    reset_settings()
    headers = {"X-NHI-Admin-Key": "test-admin-key"}
    profile = {
        "agent_id": "api-finance-agent",
        "display_name": "재무 API Agent",
        "owner": "finance-team",
        "inventory_complete": True,
        "require_sender_constraint": True,
        "allowed_binding_methods": ["DPoP"],
        "grants": [
            {
                "grant_id": "api-finance-read",
                "provider": "microsoft",
                "nhi_id": "sp-api-finance",
                "credential_fingerprints": [
                    "sha256:financecredential1234567890abcdef"
                ],
                "credential_inventory_complete": True,
                "permissions": ["READ"],
                "permission_inventory_complete": True,
                "resources": ["microsoft://sites/finance/*"],
                "resource_inventory_complete": True,
            }
        ],
    }
    saved = client.put(
        "/agent-access/profiles/api-finance-agent", json=profile, headers=headers
    )
    assert saved.status_code == 200

    scope = client.get(
        "/agent-access/profiles/api-finance-agent/scope", headers=headers
    )
    assert scope.status_code == 200
    assert scope.json()["permissions"] == ["READ"]
    assert scope.json()["resources"] == ["microsoft://sites/finance/*"]

    observation = {
        "event_id": "api-gateway-event-77",
        "claimed_agent_id": "api-finance-agent",
        "authenticated_agent_id": "unknown-agent",
        "provider": "microsoft",
        "nhi_id": "sp-api-finance",
        "credential_fingerprint": "sha256:attackercredential1234567890",
        "action": "Authorization: Bearer ghp_secretvalue1234567890",
        "permission": "WRITE",
        "resource": "microsoft://sites/hr/payroll.xlsx",
        "resource_sensitive": True,
        "sender_constrained": False,
        "sender_proof_valid": False,
        "source_ip": "203.0.113.77",
        "user_agent": "curl/8.0",
    }
    decision = client.post(
        "/agent-access/evaluate", headers=headers, json=observation
    )
    assert decision.status_code == 200
    body = decision.json()
    assert body["outcome"] == "DENY"
    assert "ghp_secretvalue1234567890" not in str(body)
    assert "CLAIMED_IDENTITY_MISMATCH" in {
        finding["rule_id"] for finding in body["findings"]
    }

    retried = client.post(
        "/agent-access/evaluate",
        headers=headers,
        json={**observation, "action": "POST /sites/hr/payroll"},
    )
    assert retried.status_code == 200
    assert retried.json()["decision_id"] == body["decision_id"]

    history = client.get(
        "/agent-access/decisions",
        params={"agent_id": "api-finance-agent", "outcome": "DENY"},
        headers=headers,
    )
    assert history.status_code == 200
    assert history.json()["count"] == 1
    assert history.json()["decisions"][0]["decision_id"] == body["decision_id"]


def test_slack_integration_rejects_plaintext_token_body_and_query(client, monkeypatch):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    reset_settings()
    headers = {"X-NHI-Admin-Key": "test-admin-key"}

    body_response = client.post(
        "/integrations/slack/verify",
        json={"token": "xoxb-plaintext-must-not-enter-api"},
        headers=headers,
    )
    query_response = client.get(
        "/integrations/slack/channels",
        params={"token": "xoxb-plaintext-must-not-enter-api"},
        headers=headers,
    )

    assert body_response.status_code == 422
    assert query_response.status_code == 400


def test_usage_event_normalization_downgrades_incomplete_batch(client):
    response = client.post(
        "/nhi/usage/normalize",
        json={
            "nhi_id": "agent-7",
            "provider": "github",
            "source": "organization_audit_log",
            "data_complete": True,
            "events": [
                {
                    "event_id": "evt-1",
                    "principal_id": "agent-7",
                    "action": "contents:read",
                    "occurred_at": "2026-09-01T00:00:00Z",
                },
                {"event_id": "invalid", "action": "contents:write"},
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accepted_event_count"] == 1
    assert body["invalid_event_count"] == 1
    assert body["matched_event_count"] == 1
    assert body["requested_data_complete"] is True
    assert body["effective_data_complete"] is False
    assert body["signals"]["observed_actions"] == ["contents:read"]


def test_inventory_analysis_accepts_usage_events_directly(client):
    response = client.post(
        "/nhi/inventory/analyze",
        json={
            "nhi": _inventory_nhi(
                owner="platform-team",
                raw_permissions={"contents": "read"},
            ),
            "usage_data_complete": True,
            "usage_source": "github_audit_log",
            "usage_events": [
                {
                    "event_id": "evt-write",
                    "principal_id": "github-app-api-test",
                    "action": "contents:write",
                    "occurred_at": "2026-09-01T00:00:00Z",
                    "repository": "acme/backend",
                }
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["usage_ingestion"]["matched_event_count"] == 1
    assert body["usage_ingestion"]["effective_data_complete"] is True
    assert body["usage_analysis"]["observed_permissions"] == ["WRITE"]
    assert body["usage_analysis"]["unexpected_permissions"] == ["WRITE"]
    assert "UNDECLARED_PERMISSION_USE" in {
        event["event_type"] for event in body["security_events"]
    }


def test_nhi_history_and_compare_routes_do_not_collide_with_repository_route(client):
    request = {
        "full_name": "acme/history-api-test",
        "findings": [_payload()],
        "signals": {
            "owner": "Customer Support Team",
            "last_used_at": "2026-09-01T00:00:00Z",
            "usage_data_complete": True,
        },
    }
    first = client.post("/nhi/analyze", json=request)
    request["signals"]["repository_public"] = True
    second = client.post("/nhi/analyze", json=request)
    assert first.status_code == second.status_code == 200

    first_body = first.json()
    second_body = second.json()
    nhi_id = second_body["analyses"][0]["discovery"]["nhi_id"]
    target_id = second_body["persistence"][0]["analysis_id"]

    history = client.get(f"/nhi/{nhi_id}/history")
    comparison = client.get(
        f"/nhi/{nhi_id}/history/compare",
        params={"target_analysis_id": target_id},
    )

    assert history.status_code == 200
    assert history.json()["count"] >= 2
    assert comparison.status_code == 200
    assert comparison.json()["target"]["analysis_id"] == target_id


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
    assert body["replan_count"] == 2
    assert any("실행되지 않았으므로" in note for note in body["replan_notes"])
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


def test_github_inventory_agent_endpoint_persists_safe_run_summary(
    client, monkeypatch
):
    import api.app as app_module
    from connectors.github_connector import GitHubOrganizationDiscoveryResult
    from core.inventory_models import GitHubNHIInput, GitHubNHIType

    inventory = GitHubNHIInput(
        nhi_id="github-app-installation:7007",
        nhi_name="deployment-bot@acme",
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner=None,
        active=True,
        account={"installation_id": 7007, "app_slug": "deployment-bot"},
        repositories=[],
        repository_selection="all",
        repository_inventory_complete=False,
        inventory_is_complete=True,
        collection_source="github_org_installations_api",
        collection_evidence=["synthetic API test evidence"],
        raw_permissions={"contents": "write", "administration": "write"},
    )

    class StubInventoryConnector:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return None

        def discover_organization_apps(self, organization, *, limit):
            assert organization == "acme"
            assert limit == 100
            return GitHubOrganizationDiscoveryResult(
                organization=organization,
                items=[inventory],
                total_count=1,
                pages_fetched=1,
                inventory_complete=True,
            )

    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    reset_settings()
    monkeypatch.setattr(
        app_module.GitHubConnector,
        "for_inventory",
        staticmethod(lambda: StubInventoryConnector()),
    )

    response = client.post(
        "/integrations/github/discover",
        json={"organization": "acme", "analyze": True},
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200
    body = response.json()
    summary = body["run_summary"]

    assert summary["status"] == "COMPLETED"
    assert summary["collection"] == {
        "count": 1,
        "total_count": 1,
        "pages_fetched": 1,
        "inventory_complete": True,
        "retrieval_truncated": False,
        "failure_count": 0,
        "coverage_note": summary["collection"]["coverage_note"],
    }
    assert summary["repository_coverage"]["incomplete_count"] == 1
    assert summary["analysis"]["count"] == 1
    assert summary["persistence"]["complete"] is True
    assert all("result" not in step for step in summary["plan"])
    assert any(step["created_by"] == "REPLANNER" for step in summary["plan"])

    events = client.get("/audit?limit=100").json()["events"]
    audit = next(
        event
        for event in events
        if event["event_id"] == body["audit_event_id"]
    )
    assert audit["event_type"] == "GITHUB_INVENTORY_AGENT_COMPLETED"
    assert audit["detail"] == summary
    assert "inventory" not in audit["detail"]["collection"]


def test_github_inventory_agent_endpoint_requires_admin_key(client, monkeypatch):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    reset_settings()

    response = client.post(
        "/integrations/github/discover",
        json={"organization": "acme", "analyze": False},
    )

    assert response.status_code == 401


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
    assert "Decision Flow" in page.text
    assert 'id="github-discover-button"' in page.text

    script = client.get("/dashboard/app.js")
    assert script.status_code == 200
    assert "/dashboard/summary" in script.text
    assert 'api("/analyses?limit=100")' in script.text
    assert "renderDecisionIntelligence" in script.text


def test_competition_dashboard_static_assets(client):
    page = client.get("/competition/")
    assert page.status_code == 200
    assert "공모전 보안 운영 대시보드" in page.text
    assert 'id="top-finding"' in page.text
    assert 'data-quick-filter="NEEDS_REVIEW"' in page.text
    assert page.text.count('data-view-target="') == 5
    assert '<span>Decision Flow</span>' in page.text
    assert 'data-view="finding-detail"' in page.text
    assert 'id="finding-journey"' in page.text
    assert 'id="permission-usage-comparison"' in page.text
    assert 'id="protected-scope-summary"' in page.text
    assert 'id="review-result"' in page.text
    assert 'data-detail-tab="relationship"' in page.text

    styles = client.get("/competition/styles.css")
    assert styles.status_code == 200
    assert ".top-finding-panel" in styles.text
    assert ".priority-critical" in styles.text
    assert ".comparison-grid" in styles.text
    assert ".audit-event-row" in styles.text

    script = client.get("/competition/app.js")
    assert script.status_code == 200
    assert 'SLA_OVERDUE: "SLA 초과"' in script.text
    assert "renderTopCriticalFinding" in script.text
    assert "renderFindingDrilldown" in script.text
    assert 'api("/analyses?limit=500")' in script.text
    assert 'key: "audit"' in script.text


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


def test_microsoft_discovery_endpoint_uses_configured_connector(
    client, monkeypatch
):
    """API는 Secret을 본문으로 받지 않고 설정된 Connector만 실행한다."""
    import api.app as app_module
    from core.inventory_models import SaaSAccessResource, SaaSNHIInput
    from core.nhi_models import NHIType

    class StubMicrosoftConnector:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return None

        def discover_service_principals(self, *, limit):
            assert limit == 3
            return [
                SaaSNHIInput(
                    provider="microsoft",
                    nhi_id="sp-api-test",
                    nhi_name="Mail Automation",
                    nhi_type=NHIType.MICROSOFT_SERVICE_PRINCIPAL,
                    active=True,
                    raw_scopes=["Mail.ReadWrite"],
                    resources=[
                        SaaSAccessResource(
                            name="Microsoft Graph",
                            resource_type="microsoft_api",
                            is_sensitive=True,
                        )
                    ],
                )
            ]

    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    reset_settings()
    monkeypatch.setattr(
        app_module, "MicrosoftGraphConnector", StubMicrosoftConnector
    )

    response = client.post(
        "/integrations/microsoft/discover",
        json={"limit": 3, "analyze": True},
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["inventory"][0]["nhi_id"] == "sp-api-test"
    assert body["analyses"][0]["source"] == "inventory"
    assert body["analyses"][0]["permissions"] == ["WRITE"]


def test_microsoft_discovery_requires_admin_key(client, monkeypatch):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    reset_settings()
    response = client.post(
        "/integrations/microsoft/discover",
        json={"limit": 1, "analyze": False},
    )
    assert response.status_code == 401
