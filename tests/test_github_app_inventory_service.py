"""analyze_github_app_nhi_from_connector() — GitHub App 전체 흐름 검증.

list_installations() → installation 별 repositories 조회 →
build_github_app_nhi_input() → 기존 NHIAnalysisPipeline.analyze_github_nhi()
재사용을 end-to-end 로 확인한다. API endpoint 연결은 아직 없으므로 다루지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agents.github_inventory_service import (
    analyze_github_app_nhi_from_connector,
    analyze_github_nhi_from_connector,
)
from connectors.base_connector import AuthenticationError
from connectors.github_app_connector import GitHubAppConnector
from connectors.github_connector import GitHubConnector
from core.config import GitHubAppSettings
from core.nhi_models import PermissionLevel

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


_INSTALLATION_1 = {
    "id": 1,
    "account": {"login": "acme-org", "id": 7, "type": "Organization"},
    "repository_selection": "selected",
    "permissions": {"contents": "write", "metadata": "read"},
    "suspended_at": None,
}

_INSTALLATION_2 = {
    "id": 2,
    "account": {"login": "octocat", "id": 8, "type": "User"},
    "repository_selection": "all",
    "permissions": {"administration": "write"},
    "suspended_at": None,
}

_REPOS_BY_INSTALLATION = {
    1: [{"id": 10, "full_name": "acme/backend", "private": True, "owner": {"login": "acme-org"}}],
    2: [
        {
            "id": 20,
            "full_name": "octocat/tools",
            "private": False,
            "owner": {"login": "octocat"},
        }
    ],
}


def _make_handler(installations, repos_by_installation, *, token_calls=None):
    """POST /app/installations/{id}/access_tokens 는 installation_id 를 담은
    opaque 토큰을 발급하고, 이후 /installation/repositories 요청은 그 토큰으로
    어느 installation 인지 구분한다 (실제 GitHub 와 동일하게 토큰이 곧 인가 범위)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/app/installations":
            return httpx.Response(200, json=installations)

        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            installation_id = int(request.url.path.split("/")[3])
            if token_calls is not None:
                token_calls.append(installation_id)
            return httpx.Response(
                201,
                json={
                    "token": f"ghs-installation-token-{installation_id}",
                    "expires_at": _iso(FIXED_NOW + timedelta(hours=1)),
                    "permissions": {},
                    "repository_selection": "selected",
                },
            )

        if request.method == "GET" and request.url.path == "/installation/repositories":
            token = request.headers.get("authorization", "").removeprefix("Bearer ")
            installation_id = int(token.removeprefix("ghs-installation-token-"))
            repos = repos_by_installation.get(installation_id, [])
            return httpx.Response(200, json={"total_count": len(repos), "repositories": repos})

        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    return handler


# ---------------------------------------------------------------------------
# 정상 흐름
# ---------------------------------------------------------------------------
def test_analyzes_one_nhi_per_installation(app_settings: GitHubAppSettings):
    handler = _make_handler([_INSTALLATION_1, _INSTALLATION_2], _REPOS_BY_INSTALLATION)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    assert len(analyses) == 2
    assert {a.profile.nhi_id for a, _ in analyses} == {
        "github:github-app-installation-1",
        "github:github-app-installation-2",
    }


def test_profile_account_login_reflects_installation_account(app_settings: GitHubAppSettings):
    handler = _make_handler([_INSTALLATION_1], _REPOS_BY_INSTALLATION)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    assert analyses[0][0].profile.account.get("login") == "acme-org"
    assert analyses[0][0].profile.owner is None


def test_repository_from_correct_installation_is_used(app_settings: GitHubAppSettings):
    handler = _make_handler([_INSTALLATION_1, _INSTALLATION_2], _REPOS_BY_INSTALLATION)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    by_id = {a.profile.nhi_id: a for a, _ in analyses}
    assert by_id["github:github-app-installation-1"].repository == ""
    # repositories 는 signals.extra 안에 담기고, blast radius 표본으로 드러난다.
    assert "acme/backend" in by_id["github:github-app-installation-1"].blast_radius.resource_samples
    assert (
        "octocat/tools"
        in by_id["github:github-app-installation-2"].blast_radius.resource_samples
    )


def test_permissions_are_translated_not_assumed(app_settings: GitHubAppSettings):
    """raw_permissions 가 채워지므로 인벤토리 경로에서도 실제 권한이 판정되어야 한다."""
    handler = _make_handler([_INSTALLATION_1, _INSTALLATION_2], _REPOS_BY_INSTALLATION)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    by_id = {a.profile.nhi_id: a for a, _ in analyses}
    installation_1 = by_id["github:github-app-installation-1"]
    installation_2 = by_id["github:github-app-installation-2"]

    assert installation_1.permissions.assumed is False
    assert PermissionLevel.WRITE in installation_1.permissions.permissions
    assert PermissionLevel.READ in installation_1.permissions.permissions
    assert PermissionLevel.ADMIN not in installation_1.permissions.permissions

    assert installation_2.permissions.assumed is False
    assert PermissionLevel.ADMIN in installation_2.permissions.permissions


def test_empty_installations_returns_empty_list(app_settings: GitHubAppSettings):
    handler = _make_handler([], {})

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    assert analyses == []


def test_fetches_repositories_for_each_installation_separately(
    app_settings: GitHubAppSettings,
):
    token_calls: list = []
    handler = _make_handler(
        [_INSTALLATION_1, _INSTALLATION_2], _REPOS_BY_INSTALLATION, token_calls=token_calls
    )

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyze_github_app_nhi_from_connector(connector)

    assert sorted(token_calls) == [1, 2]


# ---------------------------------------------------------------------------
# 예외 전파 / 노출 방지
# ---------------------------------------------------------------------------
def test_propagates_authentication_error_when_app_not_configured():
    settings = GitHubAppSettings(app_id="", private_key="")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HTTP 호출이 발생하면 안 된다")

    with GitHubAppConnector(settings, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError):
            analyze_github_app_nhi_from_connector(connector)


def test_installation_token_never_appears_in_analysis_output(app_settings: GitHubAppSettings):
    handler = _make_handler([_INSTALLATION_1], _REPOS_BY_INSTALLATION)

    with GitHubAppConnector(app_settings, client=_client(handler)) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    serialized = str([a.to_dict() for a, _ in analyses])
    assert "ghs-installation-token-1" not in serialized
    assert app_settings.private_key not in serialized


# ---------------------------------------------------------------------------
# 기존 PAT 함수는 변경되지 않았는지
# ---------------------------------------------------------------------------
def test_pat_analysis_function_is_unaffected():
    token = "ghp-existing-pat"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "octocat", "id": 42})
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=[])
        raise AssertionError(f"unexpected path: {request.url.path}")

    with GitHubConnector(
        token, client=httpx.Client(transport=httpx.MockTransport(handler))
    ) as connector:
        analysis = analyze_github_nhi_from_connector(connector)

    assert analysis.profile.account["login"] == "octocat"
    assert token not in repr(analysis)
