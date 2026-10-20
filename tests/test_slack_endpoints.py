"""Slack 엔드포인트: 관리자 키 필수 · 토큰은 서버 설정에서만 · query/body 로 토큰 입력 금지."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from core.config import reset_settings
from storage.sqlite_store import SQLiteStorage

from tests.helpers_app import load_private_app, unload_private_app

ADMIN = "bootstrap-shared-key-0123456789abcdef0123"
SERVER_TOKEN = "xoxb-server-side-token-value"


class FakeSlack:
    seen_tokens = []

    def __init__(self, token=None, **_):
        FakeSlack.seen_tokens.append(token)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def validate_credential(self, token=None):
        from core.models import CredentialStatus

        return CredentialStatus(provider="slack", active=False, revoked=False)

    def list_channels(self, **_):
        return [{"id": "C1", "name": "general"}]


def make_request(query: str = "") -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": query.encode(), "headers": []})


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", ADMIN)
    monkeypatch.setenv("SLACK_BOT_TOKEN", SERVER_TOKEN)
    module, name = load_private_app(tmp_path, monkeypatch)
    module.storage = SQLiteStorage(":memory:")
    monkeypatch.setattr(module, "SlackConnector", FakeSlack)
    FakeSlack.seen_tokens = []
    reset_settings()
    yield module
    module.storage.close()
    unload_private_app(module, name)


def test_token_in_request_body_is_no_longer_accepted(app):
    with pytest.raises(ValidationError):
        app.SlackVerifyRequest(token="xoxb-leaky-token")


def test_both_endpoints_require_the_admin_key(app):
    with pytest.raises(HTTPException) as exc:
        app.verify_slack_token(app.SlackVerifyRequest(), x_nhi_admin_key=None)
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        app.slack_channels(make_request(), x_nhi_admin_key="wrong")
    assert exc.value.status_code == 401


def test_verify_uses_only_the_server_configured_token(app):
    app.verify_slack_token(app.SlackVerifyRequest(), x_nhi_admin_key=ADMIN)
    assert FakeSlack.seen_tokens == [SERVER_TOKEN]


def test_channels_rejects_any_query_parameter_including_token(app):
    with pytest.raises(HTTPException) as exc:
        app.slack_channels(make_request("token=xoxb-leaky"), x_nhi_admin_key=ADMIN)
    assert exc.value.status_code == 400
    assert FakeSlack.seen_tokens == []  # 커넥터를 만들기 전에 거부
    assert app.slack_channels(make_request(), x_nhi_admin_key=ADMIN)["count"] == 1


def test_missing_server_token_is_a_503_not_a_silent_unauthenticated_call(app, monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "")
    reset_settings()
    with pytest.raises(HTTPException) as exc:
        app.slack_channels(make_request(), x_nhi_admin_key=ADMIN)
    assert exc.value.status_code == 503
