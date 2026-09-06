"""GitHubAppConnector.list_installation_repositories() 검증.

`GET /installation/repositories` — Installation Token 인증, 페이지네이션,
최소 필드 보존, 예외 처리 재사용을 다룬다. `inventory_adapter`/`pipeline` 과의
연결은 아직 없으므로 다루지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from connectors.base_connector import (
    AuthenticationError,
    ConnectorError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)
from connectors.github_app_connector import GitHubAppConnector
from core.config import GitHubAppSettings

FIXED_NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)
INSTALLATION_TOKEN = "ghs_super-secret-installation-token"


@pytest.fixture(scope="module")
def rsa_private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture
def app_settings(rsa_private_key_pem: str) -> GitHubAppSettings:
    return GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        201,
        json={
            "token": INSTALLATION_TOKEN,
            "expires_at": _iso(FIXED_NOW + timedelta(hours=1)),
            "permissions": {"contents": "write"},
            "repository_selection": "selected",
        },
    )


_REPO_A = {
    "id": 1,
    "full_name": "acme/backend",
    "private": True,
    "owner": {"login": "acme", "id": 7, "type": "Organization"},
    # 반환값에 남으면 안 되는 필드
    "html_url": "https://github.com/acme/backend",
    "permissions": {"pull": True, "push": True},
    "description": "internal backend service",
}

_REPO_B = {
    "id": 2,
    "full_name": "acme/frontend",
    "private": False,
    "owner": {"login": "acme", "id": 7, "type": "Organization"},
}


def _installations_router(token_endpoint_calls: list, repo_response_fn):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            token_endpoint_calls.append(request.url.path)
            return _token_response(request)
        if request.method == "GET" and request.url.path == "/installation/repositories":
            return repo_response_fn(request)
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    return handler


# ---------------------------------------------------------------------------
# 정상 케이스
# ---------------------------------------------------------------------------
def test_list_installation_repositories_uses_installation_token_not_jwt(
    app_settings: GitHubAppSettings,
):
    seen = {}
    token_calls: list = []

    def repo_response(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"total_count": 1, "repositories": [_REPO_A]})

    handler = _installations_router(token_calls, repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.list_installation_repositories(42, now=FIXED_NOW)

    assert seen["authorization"] == f"Bearer {INSTALLATION_TOKEN}"
    # App JWT(header.payload.signature) 가 아니라 opaque installation token 이어야 한다.
    assert seen["authorization"].removeprefix("Bearer ").count(".") == 0
    assert token_calls == ["/app/installations/42/access_tokens"]


def test_list_installation_repositories_keeps_only_allowed_fields(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 1, "repositories": [_REPO_A]})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        repos = connector.list_installation_repositories(42, now=FIXED_NOW)

    assert repos == [
        {"full_name": "acme/backend", "private": True, "owner_login": "acme"}
    ]
    assert set(repos[0].keys()) == {"full_name", "private", "owner_login"}
    assert "html_url" not in repos[0]
    assert "permissions" not in repos[0]
    assert "description" not in repos[0]


def test_list_installation_repositories_handles_missing_owner_gracefully(
    app_settings: GitHubAppSettings,
):
    payload = {"id": 3, "full_name": "acme/no-owner", "private": True, "owner": None}

    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 1, "repositories": [payload]})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        repos = connector.list_installation_repositories(42, now=FIXED_NOW)

    assert repos == [
        {"full_name": "acme/no-owner", "private": True, "owner_login": None}
    ]


def test_list_installation_repositories_reuses_cached_installation_token(
    app_settings: GitHubAppSettings,
):
    token_calls: list = []

    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 1, "repositories": [_REPO_A]})

    handler = _installations_router(token_calls, repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.list_installation_repositories(42, now=FIXED_NOW)
        connector.list_installation_repositories(42, now=FIXED_NOW + timedelta(minutes=5))

    # 두 번째 호출은 캐시된 installation token 을 재사용해야 한다 (재발급 없음).
    assert token_calls == ["/app/installations/42/access_tokens"]


# ---------------------------------------------------------------------------
# 페이지네이션
# ---------------------------------------------------------------------------
def test_list_installation_repositories_follows_link_header_pagination(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "1":
            return httpx.Response(
                200,
                json={"total_count": 2, "repositories": [_REPO_A]},
                headers={
                    "Link": '<https://api.github.com/installation/repositories?per_page=1&page=2>; rel="next"'
                },
            )
        return httpx.Response(200, json={"total_count": 2, "repositories": [_REPO_B]})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        repos = connector.list_installation_repositories(42, per_page=1, now=FIXED_NOW)

    assert [r["full_name"] for r in repos] == ["acme/backend", "acme/frontend"]


def test_list_installation_repositories_stops_at_max_pages(app_settings: GitHubAppSettings):
    call_count = {"n": 0}

    def repo_response(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(
            200,
            json={"total_count": 999, "repositories": [_REPO_A]},
            headers={
                "Link": '<https://api.github.com/installation/repositories?page=99>; rel="next"'
            },
        )

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        repos = connector.list_installation_repositories(42, max_pages=2, now=FIXED_NOW)

    assert call_count["n"] == 2
    assert len(repos) == 2


def test_list_installation_repositories_stops_when_page_is_empty(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 0, "repositories": []})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        repos = connector.list_installation_repositories(42, now=FIXED_NOW)

    assert repos == []


# ---------------------------------------------------------------------------
# 예외 처리 재사용
# ---------------------------------------------------------------------------
def test_list_installation_repositories_401_raises_authentication_error_without_leaking_secrets(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError) as error:
            connector.list_installation_repositories(42, now=FIXED_NOW)

    assert error.value.status_code == 401
    assert INSTALLATION_TOKEN not in str(error.value)
    assert app_settings.private_key not in str(error.value)


def test_list_installation_repositories_403_raises_permission_denied_error(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(PermissionDeniedError):
            connector.list_installation_repositories(42, now=FIXED_NOW)


def test_list_installation_repositories_404_raises_not_found_error(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(NotFoundError):
            connector.list_installation_repositories(999, now=FIXED_NOW)


def test_list_installation_repositories_429_raises_rate_limit_error(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "20"})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(
        app_settings, client=_client(handler), max_retries=0
    ) as connector:
        with pytest.raises(RateLimitError) as error:
            connector.list_installation_repositories(42, now=FIXED_NOW)

    assert error.value.retry_after == 20.0


def test_list_installation_repositories_missing_repositories_key_raises_connector_error(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 0})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(ConnectorError) as error:
            connector.list_installation_repositories(42, now=FIXED_NOW)

    assert error.value.status_code == 502


def test_list_installation_repositories_non_dict_json_raises_connector_error(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_REPO_A])  # 배열은 잘못된 응답 형태

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(ConnectorError) as error:
            connector.list_installation_repositories(42, now=FIXED_NOW)

    assert error.value.status_code == 502


def test_list_installation_repositories_without_configured_app_raises_before_http_call():
    called = {"count": 0}

    def repo_response(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json={"total_count": 1, "repositories": [_REPO_A]})

    settings = GitHubAppSettings(app_id="", private_key="")
    handler = _installations_router([], repo_response)
    with GitHubAppConnector(settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError):
            connector.list_installation_repositories(42, now=FIXED_NOW)

    assert called["count"] == 0


# ---------------------------------------------------------------------------
# 노출 방지
# ---------------------------------------------------------------------------
def test_list_installation_repositories_never_leak_token_or_key_in_repr(
    app_settings: GitHubAppSettings,
):
    def repo_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 1, "repositories": [_REPO_A]})

    handler = _installations_router([], repo_response)
    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.list_installation_repositories(42, now=FIXED_NOW)
        text = repr(connector)

    assert INSTALLATION_TOKEN not in text
    assert app_settings.private_key not in text
