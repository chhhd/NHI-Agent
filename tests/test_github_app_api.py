"""POST /nhi/github/app/inventory/analyze — API 엔드포인트 테스트.

기존 PAT 엔드포인트(`/nhi/github/inventory/analyze`, `tests/test_nhi_api.py`)는
건드리지 않는다. Dashboard/frontend 연결도 없다.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.config import GitHubAppSettings, reset_settings


@pytest.fixture(autouse=True)
def _no_github_token(monkeypatch):
    """Agent 실행 등에서 실제 GitHub 호출이 나가지 않게 한다."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)
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


@pytest.fixture(scope="module")
def rsa_private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


FIXED_NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)

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


def _make_handler(installations, repos_by_installation):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/app/installations":
            return httpx.Response(200, json=installations)

        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            installation_id = int(request.url.path.split("/")[3])
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


def _patch_connector_factory(monkeypatch, app_module, settings, handler):
    from connectors.github_app_connector import GitHubAppConnector

    def connector_factory():
        return GitHubAppConnector(
            settings, client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    monkeypatch.setattr(app_module, "GitHubAppConnector", connector_factory)


# ---------------------------------------------------------------------------
# 정상 흐름
# ---------------------------------------------------------------------------
def test_github_app_inventory_endpoint_returns_one_analysis_per_installation(
    client, monkeypatch, rsa_private_key_pem: str
):
    import api.app as app_module

    settings = GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)
    handler = _make_handler([_INSTALLATION_1, _INSTALLATION_2], _REPOS_BY_INSTALLATION)
    _patch_connector_factory(monkeypatch, app_module, settings, handler)

    response = client.post("/nhi/github/app/inventory/analyze")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert len(body["analyses"]) == 2

    by_name = {a["nhi_name"]: a for a in body["analyses"]}
    assert by_name["acme-org"]["nhi_type"] == "GITHUB_APP"
    assert by_name["acme-org"]["owner"] is None
    assert set(by_name["acme-org"]["permissions"]) == {"WRITE", "READ"}
    assert set(by_name["octocat"]["permissions"]) == {"ADMIN"}

    # 각 analysis 응답에 저장 결과(persistence)가 함께 온다.
    assert "persistence" in body["analyses"][0]
    assert "persistence" in body["analyses"][1]


def test_github_app_inventory_endpoint_persists_each_installation(
    client, monkeypatch, rsa_private_key_pem: str
):
    import api.app as app_module

    settings = GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)
    handler = _make_handler([_INSTALLATION_1, _INSTALLATION_2], _REPOS_BY_INSTALLATION)
    _patch_connector_factory(monkeypatch, app_module, settings, handler)

    client.post("/nhi/github/app/inventory/analyze")

    records = {item["nhi_id"]: item for item in client.get("/nhi").json()["nhi"]}
    assert "github:github-app-installation-1" in records
    assert "github:github-app-installation-2" in records
    assert records["github:github-app-installation-1"]["owner"] is None


def test_github_app_inventory_endpoint_empty_installations_returns_zero_count(
    client, monkeypatch, rsa_private_key_pem: str
):
    import api.app as app_module

    settings = GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)
    handler = _make_handler([], {})
    _patch_connector_factory(monkeypatch, app_module, settings, handler)

    response = client.post("/nhi/github/app/inventory/analyze")

    assert response.status_code == 200
    assert response.json() == {"count": 0, "analyses": []}


# ---------------------------------------------------------------------------
# 예외 매핑 / 노출 방지
# ---------------------------------------------------------------------------
def test_github_app_inventory_endpoint_returns_401_when_app_not_configured(
    client, monkeypatch
):
    import api.app as app_module

    settings = GitHubAppSettings(app_id="", private_key="")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HTTP 호출이 발생하면 안 된다")

    _patch_connector_factory(monkeypatch, app_module, settings, handler)

    response = client.post("/nhi/github/app/inventory/analyze")

    assert response.status_code == 401


def test_github_app_inventory_endpoint_maps_upstream_401_to_401(
    client, monkeypatch, rsa_private_key_pem: str
):
    import api.app as app_module

    settings = GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    _patch_connector_factory(monkeypatch, app_module, settings, handler)

    response = client.post("/nhi/github/app/inventory/analyze")

    assert response.status_code == 401


def test_github_app_inventory_endpoint_never_exposes_token_or_key(
    client, monkeypatch, rsa_private_key_pem: str
):
    import api.app as app_module

    settings = GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)
    handler = _make_handler([_INSTALLATION_1], _REPOS_BY_INSTALLATION)
    _patch_connector_factory(monkeypatch, app_module, settings, handler)

    response = client.post("/nhi/github/app/inventory/analyze")

    assert "ghs-installation-token-1" not in response.text
    assert rsa_private_key_pem not in response.text


# ---------------------------------------------------------------------------
# 기존 PAT 엔드포인트는 영향받지 않았는지
# ---------------------------------------------------------------------------
def test_pat_endpoint_still_registered_and_independent(client, monkeypatch):
    import api.app as app_module
    from connectors.github_connector import GitHubConnector

    token = "ghp-unaffected-check"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "octocat", "id": 42})
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=[])
        raise AssertionError(f"unexpected path: {request.url.path}")

    def connector_factory():
        return GitHubConnector(
            token, client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    monkeypatch.setattr(app_module, "GitHubConnector", connector_factory)

    response = client.post("/nhi/github/inventory/analyze")

    assert response.status_code == 200
    assert response.json()["nhi_name"] == "octocat"
