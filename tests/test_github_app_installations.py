"""GitHubAppConnector.list_installations() — `GET /app/installations` 조회 검증.

Installation Access Token 발급, 저장소 조회는 아직 없으므로 다루지 않는다.
"""

from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from connectors.base_connector import (
    AuthenticationError,
    ConnectorError,
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


_INSTALLATION_A = {
    "id": 1,
    "account": {"login": "acme-org", "id": 7, "type": "Organization"},
    "repository_selection": "selected",
    "permissions": {"contents": "write", "metadata": "read"},
    "suspended_at": None,
    # 아래는 실제 응답에 있지만 반환값에 남으면 안 되는 필드
    "access_tokens_url": "https://api.github.com/app/installations/1/access_tokens",
    "html_url": "https://github.com/organizations/acme-org/settings/installations/1",
    "app_id": 99,
}

_INSTALLATION_B_SUSPENDED = {
    "id": 2,
    "account": {"login": "octocat", "id": 8, "type": "User"},
    "repository_selection": "all",
    "permissions": {"administration": "write"},
    "suspended_at": "2024-05-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# 정상 케이스
# ---------------------------------------------------------------------------
def test_list_installations_sends_bearer_jwt(app_settings: GitHubAppSettings):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json=[_INSTALLATION_A])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        connector.list_installations()

    assert seen["path"] == "/app/installations"
    assert seen["authorization"].startswith("Bearer ")
    assert seen["authorization"].removeprefix("Bearer ").count(".") == 2


def test_list_installations_keeps_only_allowed_fields(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_INSTALLATION_A])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations()

    assert installations == [
        {
            "installation_id": 1,
            "account_login": "acme-org",
            "account_type": "Organization",
            "repository_selection": "selected",
            "permissions": {"contents": "write", "metadata": "read"},
            "suspended": False,
        }
    ]
    keys = set(installations[0].keys())
    assert keys == {
        "installation_id",
        "account_login",
        "account_type",
        "repository_selection",
        "permissions",
        "suspended",
    }
    assert "access_tokens_url" not in installations[0]
    assert "html_url" not in installations[0]


def test_list_installations_preserves_permissions_verbatim(app_settings: GitHubAppSettings):
    """permissions 는 추측/변환 없이 GitHub 응답 그대로 보존되어야 한다."""
    raw_permissions = {
        "contents": "write",
        "issues": "read",
        "some_future_unknown_permission": "admin",  # 매핑 테이블에 없는 값도 그대로
    }
    payload = {**_INSTALLATION_A, "permissions": raw_permissions}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[payload])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations()

    assert installations[0]["permissions"] == raw_permissions
    assert installations[0]["permissions"] is not raw_permissions  # 원본 dict 참조가 아니어도 값은 동일


def test_list_installations_derives_suspended_from_suspended_at(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_INSTALLATION_A, _INSTALLATION_B_SUSPENDED])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations()

    by_id = {item["installation_id"]: item for item in installations}
    assert by_id[1]["suspended"] is False
    assert by_id[2]["suspended"] is True
    assert by_id[2]["account_login"] == "octocat"
    assert by_id[2]["account_type"] == "User"
    assert by_id[2]["repository_selection"] == "all"


def test_list_installations_handles_missing_account_gracefully(app_settings: GitHubAppSettings):
    payload = {
        "id": 3,
        "account": None,
        "repository_selection": "all",
        "permissions": {},
        "suspended_at": None,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[payload])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations()

    assert installations[0]["account_login"] is None
    assert installations[0]["account_type"] is None


# ---------------------------------------------------------------------------
# 페이지네이션
# ---------------------------------------------------------------------------
def test_list_installations_follows_link_header_pagination(app_settings: GitHubAppSettings):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.params.get("page") == "1":
            return httpx.Response(
                200,
                json=[_INSTALLATION_A],
                headers={
                    "Link": '<https://api.github.com/app/installations?per_page=1&page=2>; rel="next"'
                },
            )
        return httpx.Response(200, json=[_INSTALLATION_B_SUSPENDED])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations(per_page=1)

    assert [item["installation_id"] for item in installations] == [1, 2]
    assert len(calls) == 2


def test_list_installations_stops_at_max_pages(app_settings: GitHubAppSettings):
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(
            200,
            json=[_INSTALLATION_A],
            headers={"Link": '<https://api.github.com/app/installations?page=99>; rel="next"'},
        )

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations(max_pages=2)

    assert call_count["n"] == 2
    assert len(installations) == 2


def test_list_installations_stops_when_page_is_empty(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        installations = connector.list_installations()

    assert installations == []


# ---------------------------------------------------------------------------
# 예외 처리 재사용
# ---------------------------------------------------------------------------
def test_list_installations_401_raises_authentication_error_without_leaking_jwt(
    app_settings: GitHubAppSettings,
):
    captured_jwt = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_jwt["value"] = request.headers.get("authorization", "").removeprefix("Bearer ")
        return httpx.Response(401, json={"message": "Bad credentials"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError) as error:
            connector.list_installations()

    assert error.value.status_code == 401
    assert captured_jwt["value"] not in str(error.value)
    assert app_settings.private_key not in str(error.value)


def test_list_installations_429_raises_rate_limit_error(app_settings: GitHubAppSettings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "15"})

    with GitHubAppConnector(
        app_settings, client=_client(handler), max_retries=0
    ) as connector:
        with pytest.raises(RateLimitError) as error:
            connector.list_installations()

    assert error.value.retry_after == 15.0


def test_list_installations_invalid_json_response_raises_connector_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-a-list")

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(ConnectorError) as error:
            connector.list_installations()

    assert error.value.status_code == 502


def test_list_installations_non_list_json_raises_connector_error(
    app_settings: GitHubAppSettings,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "not a list"})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        with pytest.raises(ConnectorError) as error:
            connector.list_installations()

    assert error.value.status_code == 502


def test_list_installations_without_configured_app_raises_before_http_call():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json=[_INSTALLATION_A])

    settings = GitHubAppSettings(app_id="", private_key="")
    with GitHubAppConnector(settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError):
            connector.list_installations()

    assert called["count"] == 0
