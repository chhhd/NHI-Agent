import httpx
import pytest

from connectors.base_connector import AuthenticationError, ConnectorError
from connectors.github_connector import GitHubConnector
from core.config import reset_settings


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_github_authenticated_user_uses_environment_token(monkeypatch):
    token = "ghp-test-token"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    reset_settings()
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"login": "octocat", "id": 1, "email": "private"})

    try:
        with GitHubConnector(client=_client(handler)) as github:
            assert github.get_authenticated_user() == {"login": "octocat", "id": 1}
    finally:
        reset_settings()

    assert seen == {"path": "/user", "authorization": f"Bearer {token}"}


def test_github_authenticated_user_rejects_401_without_exposing_token():
    token = "ghp-invalid-token"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    with GitHubConnector(token, client=_client(handler)) as github:
        with pytest.raises(AuthenticationError) as error:
            github.get_authenticated_user()

    assert error.value.status_code == 401
    assert token not in str(error.value)


def test_github_authenticated_user_sanitizes_api_errors():
    token = "ghp-network-test-token"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "temporary server failure"})

    with GitHubConnector(token, client=_client(handler), max_retries=0) as github:
        with pytest.raises(ConnectorError) as error:
            github.get_authenticated_user()

    assert error.value.status_code == 500
    assert "temporary server failure" not in str(error.value)
    assert token not in str(error.value)


def test_github_authenticated_user_requires_a_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    reset_settings()
    try:
        with GitHubConnector(client=_client(lambda request: httpx.Response(200))) as github:
            with pytest.raises(AuthenticationError, match="token is not configured"):
                github.get_authenticated_user()
    finally:
        reset_settings()
