"""GitLab / Notion / HuggingFace Connector 테스트 (MockTransport)."""

from __future__ import annotations

import httpx

from connectors import CONNECTOR_REGISTRY, get_connector
from connectors.gitlab_connector import GitLabConnector
from connectors.huggingface_connector import HuggingFaceConnector
from connectors.notion_connector import NotionConnector


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
def test_registry_contains_all_providers():
    for provider in ("github", "slack", "gitlab", "notion", "huggingface"):
        assert provider in CONNECTOR_REGISTRY
    assert get_connector("unsupported") is None


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------
def test_gitlab_validate_credential():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/personal_access_tokens/self"):
            return httpx.Response(
                200,
                json={
                    "name": "ci-token",
                    "revoked": False,
                    "active": True,
                    "scopes": ["read_api", "read_repository"],
                    "user_id": 42,
                    "expires_at": "2027-01-01",
                },
            )
        if path.endswith("/user"):
            return httpx.Response(200, json={"username": "dev", "name": "Dev", "id": 42})
        if path.endswith("/projects"):
            return httpx.Response(
                200,
                json=[{"id": 1, "path_with_namespace": "org/repo", "visibility": "private"}],
            )
        return httpx.Response(200, json={})

    with GitLabConnector("glpat-dummy", client=_client(handler)) as gl:
        status = gl.validate_credential()

    assert status.active is True
    assert status.revoked is False
    assert status.raw_scopes == ["read_api", "read_repository"]
    assert status.account["username"] == "dev"
    assert status.accessible_resources[0]["path_with_namespace"] == "org/repo"


def test_gitlab_revoked_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "401 Unauthorized"})

    with GitLabConnector("glpat-dead", client=_client(handler)) as gl:
        status = gl.validate_credential()

    assert status.active is False
    assert status.revoked is True


# ---------------------------------------------------------------------------
# Notion
# ---------------------------------------------------------------------------
def test_notion_validate_credential():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/users/me"):
            return httpx.Response(
                200,
                json={
                    "id": "bot-1",
                    "name": "NHI Bot",
                    "bot": {
                        "workspace_name": "Hanium",
                        "owner": {"type": "workspace"},
                        "workspace_capabilities": {"read_content": True, "insert_content": False},
                    },
                },
            )
        if request.url.path.endswith("/search"):
            return httpx.Response(
                200,
                json={"results": [{"id": "page-1", "object": "page", "url": "https://notion.so/x"}]},
            )
        return httpx.Response(200, json={})

    with NotionConnector("secret_dummy", client=_client(handler)) as n:
        status = n.validate_credential()

    assert status.active is True
    assert "read_content" in status.raw_scopes
    assert "insert_content" not in status.raw_scopes
    assert status.account["workspace_name"] == "Hanium"
    assert status.accessible_resources[0]["object"] == "page"


def test_notion_invalid_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "API token is invalid."})

    with NotionConnector("secret_bad", client=_client(handler)) as n:
        status = n.validate_credential()

    assert status.active is False
    assert status.revoked is True


# ---------------------------------------------------------------------------
# Hugging Face
# ---------------------------------------------------------------------------
def test_huggingface_validate_credential_fine_grained():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "name": "researcher",
                "type": "user",
                "email": "r@example.com",
                "auth": {
                    "accessToken": {
                        "displayName": "read-token",
                        "role": "fineGrained",
                        "fineGrained": {
                            "global": ["discussion.write"],
                            "scoped": [{"permissions": ["repo.content.read"]}],
                        },
                    }
                },
                "orgs": [{"name": "hanium-org", "roleInOrg": "admin"}],
            },
        )

    with HuggingFaceConnector("hf_dummy", client=_client(handler)) as hf:
        status = hf.validate_credential()

    assert status.active is True
    assert "repo.content.read" in status.raw_scopes
    assert "discussion.write" in status.raw_scopes
    assert status.accessible_resources[0]["name"] == "hanium-org"


def test_huggingface_revoked_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Invalid credentials"})

    with HuggingFaceConnector("hf_dead", client=_client(handler)) as hf:
        status = hf.validate_credential()

    assert status.active is False
    assert status.revoked is True
