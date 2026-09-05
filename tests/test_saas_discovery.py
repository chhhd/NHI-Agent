"""Microsoft 365 / Google Workspace NHI Discovery와 공통 분석 연결 테스트."""

from __future__ import annotations

import json

import httpx
import pytest

from agents.pipeline import NHIAnalysisPipeline
from connectors.base_connector import AuthenticationError
from connectors.google_workspace_connector import GoogleWorkspaceConnector
from connectors.microsoft_graph_connector import MicrosoftGraphConnector
from core.inventory_models import SaaSAccessResource, SaaSNHIInput
from core.nhi_models import AnalysisSource, NHIType, PermissionLevel
from normalization import observation_from_saas_inventory


def test_generic_saas_inventory_uses_existing_risk_pipeline():
    nhi = SaaSNHIInput(
        provider="microsoft",
        nhi_id="sp-001",
        nhi_name="mail-automation",
        nhi_type=NHIType.MICROSOFT_SERVICE_PRINCIPAL,
        active=True,
        raw_scopes=["Mail.ReadWrite", "Directory.Read.All"],
        resources=[
            SaaSAccessResource(
                name="Microsoft Graph",
                resource_type="microsoft_api",
                is_sensitive=True,
            )
        ],
        connected_services=["Microsoft 365"],
    )

    analysis = NHIAnalysisPipeline().analyze_saas_nhi(nhi)

    assert analysis.source is AnalysisSource.INVENTORY
    assert analysis.permissions.permissions == [PermissionLevel.READ, PermissionLevel.WRITE]
    assert analysis.blast_radius.accessible_resources == 1
    assert analysis.context.hardcoded_in_source is False
    assert "NO_PLAINTEXT_CREDENTIAL" not in {
        violation.policy_id for violation in analysis.policy.violations
    }
    assert "OWNER_REQUIRED" in {violation.policy_id for violation in analysis.policy.violations}

    observation = observation_from_saas_inventory(nhi)
    assert observation.provider == "microsoft"
    assert observation.masked_value == ""
    assert observation.fingerprint == "nhi:microsoft:sp-001"


def test_microsoft_graph_discovers_service_principal_and_permissions():
    principals = [
        {
            "id": "sp-client",
            "appId": "app-client",
            "displayName": "Mail Automation",
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "createdDateTime": "2026-01-01T00:00:00Z",
            "keyCredentials": [],
            "passwordCredentials": [
                {
                    "startDateTime": "2026-01-01T00:00:00Z",
                    "endDateTime": "2027-01-01T00:00:00Z",
                }
            ],
            "tags": [],
            "appRoles": [],
        },
        {
            "id": "graph-resource",
            "appId": "00000003-0000-0000-c000-000000000000",
            "displayName": "Microsoft Graph",
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "keyCredentials": [],
            "passwordCredentials": [],
            "tags": [],
            "appRoles": [{"id": "role-read", "value": "User.Read.All"}],
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/servicePrincipals"):
            return httpx.Response(200, json={"value": principals})
        if request.url.path.endswith("/oauth2PermissionGrants"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "clientId": "sp-client",
                            "resourceId": "graph-resource",
                            "scope": "Mail.ReadWrite Files.Read.All",
                        }
                    ]
                },
            )
        if request.url.path.endswith("/$batch"):
            body = json.loads(request.content)
            responses = []
            for item in body["requests"]:
                if item["url"].startswith("/servicePrincipals/sp-client/owners"):
                    value = [
                        {
                            "id": "owner-1",
                            "displayName": "Security Team",
                            "userPrincipalName": "security@example.com",
                        }
                    ]
                elif item["url"].startswith(
                    "/servicePrincipals/sp-client/appRoleAssignments"
                ):
                    value = [
                        {
                            "resourceId": "graph-resource",
                            "resourceDisplayName": "Microsoft Graph",
                            "appRoleId": "role-read",
                        }
                    ]
                else:
                    value = []
                responses.append({"id": item["id"], "status": 200, "body": {"value": value}})
            return httpx.Response(200, json={"responses": responses})
        raise AssertionError(f"예상하지 않은 요청: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with MicrosoftGraphConnector(token="test-token", client=client) as connector:
        inventory = connector.discover_service_principals(limit=2)

    discovered = next(item for item in inventory if item.nhi_id == "sp-client")
    assert discovered.owner == "security@example.com"
    assert discovered.nhi_type is NHIType.MICROSOFT_SERVICE_PRINCIPAL
    assert discovered.active is True
    assert discovered.raw_scopes == ["Mail.ReadWrite", "Files.Read.All", "User.Read.All"]
    assert discovered.resources[0].name == "Microsoft Graph"
    assert discovered.last_rotated_at.isoformat().startswith("2026-01-01")


def test_google_reports_aggregates_oauth_client_events():
    activities = {
        "items": [
            {
                "id": {"time": "2026-08-20T01:00:00Z"},
                "actor": {"email": "owner@example.com"},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [
                            {"name": "client_id", "value": "google-client-1"},
                            {"name": "app_name", "value": "Document Assistant"},
                            {"name": "client_type", "value": "WEB"},
                            {
                                "name": "scope",
                                "multiValue": [
                                    "https://www.googleapis.com/auth/drive.readonly",
                                    "https://www.googleapis.com/auth/gmail.send",
                                ],
                            },
                        ],
                    }
                ],
            },
            {
                "id": {"time": "2026-08-21T02:00:00Z"},
                "actor": {"email": "owner@example.com"},
                "events": [
                    {
                        "name": "activity",
                        "parameters": [
                            {"name": "client_id", "value": "google-client-1"},
                            {"name": "app_name", "value": "Document Assistant"},
                            {"name": "api_name", "value": "Drive API"},
                        ],
                    }
                ],
            },
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/applications/token")
        assert request.headers["Authorization"] == "Bearer test-token"
        return httpx.Response(200, json=activities)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with GoogleWorkspaceConnector(token="test-token", client=client) as connector:
        inventory = connector.discover_oauth_clients(max_events=10)

    assert len(inventory) == 1
    discovered = inventory[0]
    assert discovered.nhi_type is NHIType.GOOGLE_OAUTH_CLIENT
    assert discovered.owner == "owner@example.com"
    assert discovered.active is True
    assert "https://www.googleapis.com/auth/gmail.send" in discovered.raw_scopes
    assert discovered.resources[0].name == "Drive API"
    assert discovered.account["inventory_is_complete"] is False

    permissions = NHIAnalysisPipeline().analyze_saas_nhi(discovered).permissions.permissions
    assert permissions == [PermissionLevel.READ, PermissionLevel.WRITE]


def test_google_discovery_without_token_fails_before_network():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("토큰이 없으면 네트워크를 호출하면 안 된다")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = GoogleWorkspaceConnector(token="", client=client)
    connector.token = ""
    with pytest.raises(AuthenticationError):
        connector.discover_oauth_clients()
