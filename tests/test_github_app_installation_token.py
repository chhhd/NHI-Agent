"""GitHubAppConnector.get_installation_access_token() 검증.

`POST /app/installations/{id}/access_tokens` 발급, 캐싱, 예외 처리 재사용을
다룬다. `/installation/repositories` 조회는 아직 없으므로 다루지 않는다.
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


_TOKEN_RESPONSE = {
    "token": "ghs_super-secret-installation-token",
    "expires_at": _iso(FIXED_NOW + timedelta(hours=1)),
    "permissions": {"contents": "write", "metadata": "read"},
    "repository_selection": "selected",
    # 실제 응답에 있지만 반환값에 남으면 안 되는 필드
    "single_file_paths": [],
}


# ---------------------------------------------------------------------------
# 정상 케이스
# ---------------------------------------------------------------------------
def test_get_installation_access_token_posts_expected_path_with_bearer_jwt(
    app_settings: GitHubAppSettings,
):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.get_installation_access_token(42, now=FIXED_NOW)

    assert seen["method"] == "POST"
    assert seen["path"] == "/app/installations/42/access_tokens"
    assert seen["authorization"].startswith("Bearer ")
    assert seen["authorization"].removeprefix("Bearer ").count(".") == 2


def test_get_installation_access_token_returns_only_allowed_fields(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        result = connector.get_installation_access_token(42, now=FIXED_NOW)

    assert result == {
        "token": "ghs_super-secret-installation-token",
        "expires_at": _TOKEN_RESPONSE["expires_at"],
        "permissions": {"contents": "write", "metadata": "read"},
        "repository_selection": "selected",
    }
    assert set(result.keys()) == {"token", "expires_at", "permissions", "repository_selection"}
    assert "single_file_paths" not in result


def test_get_installation_access_token_preserves_permissions_verbatim(
    app_settings: GitHubAppSettings,
):
    raw_permissions = {"contents": "write", "some_future_permission": "admin"}
    payload = {**_TOKEN_RESPONSE, "permissions": raw_permissions}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json=payload)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        result = connector.get_installation_access_token(42, now=FIXED_NOW)

    assert result["permissions"] == raw_permissions


# ---------------------------------------------------------------------------
# 캐싱
# ---------------------------------------------------------------------------
def test_get_installation_access_token_uses_cache_when_not_near_expiry(
    app_settings: GitHubAppSettings,
):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        first = connector.get_installation_access_token(42, now=FIXED_NOW)
        second = connector.get_installation_access_token(
            42, now=FIXED_NOW + timedelta(minutes=5)
        )

    assert call_count["n"] == 1
    assert first == second


def test_get_installation_access_token_refetches_when_expiry_imminent(
    app_settings: GitHubAppSettings,
):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.get_installation_access_token(42, now=FIXED_NOW)
        # 만료(발급 후 1시간) 59초 전 — 재발급 버퍼(60초) 이내이므로 재요청되어야 한다.
        connector.get_installation_access_token(
            42, now=FIXED_NOW + timedelta(hours=1) - timedelta(seconds=59)
        )

    assert call_count["n"] == 2


def test_get_installation_access_token_caches_per_installation_id(
    app_settings: GitHubAppSettings,
):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.get_installation_access_token(1, now=FIXED_NOW)
        connector.get_installation_access_token(2, now=FIXED_NOW)
        connector.get_installation_access_token(1, now=FIXED_NOW)  # 캐시 사용

    assert calls == [
        "/app/installations/1/access_tokens",
        "/app/installations/2/access_tokens",
    ]


def test_get_installation_access_token_refetches_when_expires_at_unparseable(
    app_settings: GitHubAppSettings,
):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(201, json={**_TOKEN_RESPONSE, "expires_at": "not-a-timestamp"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.get_installation_access_token(42, now=FIXED_NOW)
        connector.get_installation_access_token(42, now=FIXED_NOW)

    # 만료 시각을 신뢰할 수 없으므로 캐시를 쓰지 않고 매번 재발급한다.
    assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# 예외 처리 재사용
# ---------------------------------------------------------------------------
def test_get_installation_access_token_401_raises_authentication_error_without_leaking_jwt(
    app_settings: GitHubAppSettings,
):
    captured_jwt = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_jwt["value"] = request.headers.get("authorization", "").removeprefix("Bearer ")
        return httpx.Response(401, json={"message": "Bad credentials"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError) as error:
            connector.get_installation_access_token(42, now=FIXED_NOW)

    assert error.value.status_code == 401
    assert captured_jwt["value"] not in str(error.value)
    assert app_settings.private_key not in str(error.value)


def test_get_installation_access_token_403_raises_permission_denied_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(PermissionDeniedError) as error:
            connector.get_installation_access_token(42, now=FIXED_NOW)

    assert error.value.status_code == 403


def test_get_installation_access_token_404_raises_not_found_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(NotFoundError):
            connector.get_installation_access_token(999, now=FIXED_NOW)


def test_get_installation_access_token_429_raises_rate_limit_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "10"})

    with GitHubAppConnector(
        app_settings, client=_client(handler), max_retries=0
    ) as connector:
        with pytest.raises(RateLimitError) as error:
            connector.get_installation_access_token(42, now=FIXED_NOW)

    assert error.value.retry_after == 10.0


def test_get_installation_access_token_missing_token_field_raises_connector_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"expires_at": _TOKEN_RESPONSE["expires_at"]})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(ConnectorError) as error:
            connector.get_installation_access_token(42, now=FIXED_NOW)

    assert error.value.status_code == 502


def test_get_installation_access_token_without_configured_app_raises_before_http_call():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    settings = GitHubAppSettings(app_id="", private_key="")
    with GitHubAppConnector(settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError):
            connector.get_installation_access_token(42, now=FIXED_NOW)

    assert called["count"] == 0


# ---------------------------------------------------------------------------
# 노출 방지
# ---------------------------------------------------------------------------
def test_get_installation_access_token_never_appears_in_connector_repr(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json=_TOKEN_RESPONSE)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        result = connector.get_installation_access_token(42, now=FIXED_NOW)
        text = repr(connector)

    assert result["token"] not in text
    assert app_settings.private_key not in text
