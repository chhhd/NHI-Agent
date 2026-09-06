"""GitHubAppConnector.get_app_info() — `GET /app` 조회 검증.

Installation 관련 기능은 아직 없으므로 여기서는 다루지 않는다.
"""

from __future__ import annotations

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


_FULL_APP_PAYLOAD = {
    "id": 99,
    "slug": "nhi-secret-agent",
    "name": "NHI Secret Agent",
    "owner": {"login": "acme-org", "id": 7, "type": "Organization"},
    "permissions": {"contents": "write", "metadata": "read"},
    # 아래는 실제 GitHub 응답에 있지만 반환값에 포함되면 안 되는 필드들
    "html_url": "https://github.com/apps/nhi-secret-agent",
    "created_at": "2024-01-01T00:00:00Z",
    "events": ["push", "pull_request"],
    "client_id": "Iv1.super-secret-client-id",
}


# ---------------------------------------------------------------------------
# 정상 케이스
# ---------------------------------------------------------------------------
def test_get_app_info_sends_bearer_jwt(app_settings: GitHubAppSettings):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json=_FULL_APP_PAYLOAD)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.get_app_info()

    assert seen["path"] == "/app"
    assert seen["authorization"].startswith("Bearer ")
    jwt_token = seen["authorization"].removeprefix("Bearer ")
    # 유효한 JWT 구조(header.payload.signature) 인지만 확인 — 클레임 자체는
    # generate_jwt() 전용 테스트(test_github_app_jwt.py)에서 검증한다.
    assert jwt_token.count(".") == 2


def test_get_app_info_returns_only_allowed_fields(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FULL_APP_PAYLOAD)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        info = connector.get_app_info()

    assert info == {
        "id": 99,
        "slug": "nhi-secret-agent",
        "name": "NHI Secret Agent",
        "owner": {"login": "acme-org", "id": 7, "type": "Organization"},
        "permissions": {"contents": "write", "metadata": "read"},
    }
    assert set(info.keys()) == {"id", "slug", "name", "owner", "permissions"}
    # 민감하거나 불필요한 원본 필드는 절대 새어 나가면 안 된다.
    assert "client_id" not in info
    assert "html_url" not in info
    assert "events" not in info


def test_get_app_info_defaults_permissions_to_empty_dict_when_missing(
    app_settings: GitHubAppSettings,
):
    payload = {"id": 1, "slug": "x", "name": "X", "owner": {"login": "x"}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        info = connector.get_app_info()

    assert info["permissions"] == {}


# ---------------------------------------------------------------------------
# 예외 처리 재사용 — BaseConnector 의 기존 분류를 그대로 따른다
# ---------------------------------------------------------------------------
def test_get_app_info_401_raises_authentication_error_without_leaking_jwt(
    app_settings: GitHubAppSettings,
):
    captured_jwt = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_jwt["value"] = request.headers.get("authorization", "").removeprefix("Bearer ")
        return httpx.Response(401, json={"message": "Bad credentials"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError) as error:
            connector.get_app_info()

    assert error.value.status_code == 401
    assert captured_jwt["value"] not in str(error.value)
    assert app_settings.private_key not in str(error.value)


def test_get_app_info_403_raises_permission_denied_error(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(PermissionDeniedError) as error:
            connector.get_app_info()

    assert error.value.status_code == 403


def test_get_app_info_404_raises_not_found_error(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(NotFoundError):
            connector.get_app_info()


def test_get_app_info_429_raises_rate_limit_error(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"})

    with GitHubAppConnector(
        app_settings, client=_client(handler), max_retries=0
    ) as connector:
        with pytest.raises(RateLimitError) as error:
            connector.get_app_info()

    assert error.value.retry_after == 30.0


def test_get_app_info_invalid_json_response_raises_connector_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(ConnectorError) as error:
            connector.get_app_info()

    assert error.value.status_code == 502


# ---------------------------------------------------------------------------
# 설정 누락 시 — HTTP 호출 전에 AuthenticationError (generate_jwt 재사용 확인)
# ---------------------------------------------------------------------------
def test_get_app_info_without_configured_app_raises_before_http_call():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json=_FULL_APP_PAYLOAD)

    settings = GitHubAppSettings(app_id="", private_key="")
    with GitHubAppConnector(settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError):
            connector.get_app_info()

    assert called["count"] == 0


# ---------------------------------------------------------------------------
# validate_credential() — BaseConnector 추상 메서드 구현
# ---------------------------------------------------------------------------
def test_validate_credential_reports_active_on_success(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FULL_APP_PAYLOAD)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        status = connector.validate_credential()

    assert status.active is True
    assert status.revoked is False
    assert status.account["login"] == "nhi-secret-agent"


def test_validate_credential_reports_revoked_on_401(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        status = connector.validate_credential()

    assert status.active is False
    assert status.revoked is True
    assert status.error is not None
