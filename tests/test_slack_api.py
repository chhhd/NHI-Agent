"""POST /nhi/slack/inventory/analyze — API 엔드포인트 테스트.

기존 GitHub 엔드포인트(`/nhi/github/inventory/analyze`,
`/nhi/github/app/inventory/analyze`)는 건드리지 않는다.
"""

from __future__ import annotations

import os

import httpx
import pytest

from core.config import reset_settings


@pytest.fixture(autouse=True)
def _no_default_tokens(monkeypatch):
    """Agent 실행 등에서 실제 외부 호출이 나가지 않게 한다."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
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


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _patch_connector_factory(monkeypatch, app_module, token, handler):
    from connectors.slack_connector import SlackConnector

    def connector_factory():
        return SlackConnector(token, client=_client(handler))

    monkeypatch.setattr(app_module, "SlackConnector", connector_factory)


def _ok_handler(*, scopes="channels:history,chat:write,admin.users:write"):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth.test":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "team": "Acme",
                    "team_id": "T999",
                    "user": "support-bot",
                    "user_id": "U1",
                    "bot_id": "B1",
                    "app_id": "A1",
                },
                headers={"x-oauth-scopes": scopes},
            )
        if request.url.path == "/api/conversations.list":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": [
                        {"id": "C1", "name": "general", "is_private": False, "is_member": True}
                    ],
                },
            )
        raise AssertionError(f"unexpected path: {request.url.path}")

    return handler


# ---------------------------------------------------------------------------
# 정상 흐름
# ---------------------------------------------------------------------------
def test_slack_inventory_endpoint_returns_analysis_and_persists_it(client, monkeypatch):
    import api.app as app_module

    token = "xoxb-endpoint-test-secret"
    _patch_connector_factory(monkeypatch, app_module, token, _ok_handler())

    response = client.post("/nhi/slack/inventory/analyze")

    assert response.status_code == 200
    body = response.json()
    assert body["nhi_name"] == "support-bot"
    assert body["source"] == "inventory"
    assert set(body["permissions"]) == {"READ", "WRITE", "ADMIN"}
    assert "persistence" in body
    assert token not in response.text

    records = client.get("/nhi").json()["nhi"]
    record = next(item for item in records if item["nhi_id"] == "slack:slack-T999-B1")
    assert record["risk_score"] == body["risk_score"]
    assert record["risk_level"] == body["risk_level"]

    # provider_detail — Slack 고유 필드(channels/channels_error)가 저장된
    # 레코드에 그대로 실려 있어야 한다.
    assert record["provider_detail"]["slack"] == {
        "channels": [{"name": "general", "is_private": False, "is_sensitive": False}],
        "channels_error": None,
    }


def test_slack_inventory_endpoint_persists_channels_error_on_fetch_failure(
    client, monkeypatch
):
    """채널 조회가 실패해도(0개로 감춰지지 않고) 실패 사유가
    provider_detail["slack"]["channels_error"] 에 그대로 남아야 한다."""
    import api.app as app_module

    token = "xoxb-endpoint-channel-fetch-failure"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth.test":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "team": "Acme",
                    "team_id": "T998",
                    "user": "support-bot",
                    "user_id": "U2",
                    "bot_id": "B2",
                    "app_id": "A2",
                },
                headers={"x-oauth-scopes": "chat:write"},  # channels:read 없음
            )
        return httpx.Response(200, json={"ok": False, "error": "missing_scope"})

    _patch_connector_factory(monkeypatch, app_module, token, handler)

    response = client.post("/nhi/slack/inventory/analyze")

    assert response.status_code == 200

    records = client.get("/nhi").json()["nhi"]
    record = next(item for item in records if item["nhi_id"] == "slack:slack-T998-B2")
    detail = record["provider_detail"]["slack"]
    assert detail["channels"] == []
    assert detail["channels_error"] is not None
    assert "missing_scope" in detail["channels_error"]


def test_slack_inventory_endpoint_response_includes_blast_radius_and_policy(
    client, monkeypatch
):
    import api.app as app_module

    token = "xoxb-endpoint-detail-secret"
    _patch_connector_factory(monkeypatch, app_module, token, _ok_handler())

    response = client.post("/nhi/slack/inventory/analyze")

    body = response.json()
    for key in ("risk_detail", "policy", "blast_radius", "permission_detail"):
        assert key in body


# ---------------------------------------------------------------------------
# 예외 매핑 / 노출 방지
# ---------------------------------------------------------------------------
def test_slack_inventory_endpoint_returns_401_when_token_invalid(client, monkeypatch):
    import api.app as app_module

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})

    _patch_connector_factory(monkeypatch, app_module, "xoxb-revoked-token", handler)

    response = client.post("/nhi/slack/inventory/analyze")

    assert response.status_code == 401


def test_slack_inventory_endpoint_never_exposes_token(client, monkeypatch):
    import api.app as app_module

    token = "xoxb-must-not-leak"
    _patch_connector_factory(monkeypatch, app_module, token, _ok_handler())

    response = client.post("/nhi/slack/inventory/analyze")

    assert token not in response.text


# ---------------------------------------------------------------------------
# 기존 GitHub 엔드포인트는 영향받지 않았는지
# ---------------------------------------------------------------------------
def test_github_inventory_endpoints_still_registered_and_independent(client, monkeypatch):
    import api.app as app_module
    from connectors.github_connector import GitHubConnector

    token = "ghp-unaffected-by-slack-endpoint"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "octocat", "id": 42})
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=[])
        raise AssertionError(f"unexpected path: {request.url.path}")

    def connector_factory():
        return GitHubConnector(token, client=_client(handler))

    monkeypatch.setattr(app_module, "GitHubConnector", connector_factory)

    response = client.post("/nhi/github/inventory/analyze")

    assert response.status_code == 200
    assert response.json()["nhi_name"] == "octocat"
