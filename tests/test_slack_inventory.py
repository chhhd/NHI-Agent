"""Slack Inventory NHI 최소 구현 회귀 테스트.

확인 범위:
  * core/slack_inventory_models.py     — `SlackNHIInput`/`ChannelInfo`
  * agents/inventory_adapter.py        — Slack 전용 어댑터 함수들
  * agents/pipeline.py                 — `analyze_slack_nhi()`
  * agents/slack_inventory_service.py  — `analyze_slack_nhi_from_connector()`

실제 `auth.test` identity 와 OAuth scope 가 ScopeTranslation/Risk/Policy 까지
그대로 흘러가는지, GitHub 경로는 전혀 영향받지 않는지를 함께 확인한다.
"""

from __future__ import annotations

import httpx
import pytest

from agents.inventory_adapter import (
    build_slack_context,
    build_slack_credential_record,
    build_slack_nhi_input,
    build_slack_profile,
    build_slack_signals,
)
from agents.pipeline import NHIAnalysisPipeline
from agents.slack_inventory_service import analyze_slack_nhi_from_connector
from connectors.base_connector import AuthenticationError
from connectors.slack_connector import SlackConnector
from core.models import CredentialStatus
from core.nhi_models import NHIType, PermissionLevel
from core.slack_inventory_models import ChannelInfo, SlackNHIInput


def _status(**overrides) -> CredentialStatus:
    defaults = dict(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["channels:history", "chat:write"],
        account={
            "token_kind": "bot",
            "team": "Acme",
            "team_id": "T123",
            "user": "support-bot",
            "user_id": "U1",
            "bot_id": "B1",
            "app_id": "A1",
        },
        accessible_resources=[
            {"id": "C1", "name": "general", "is_private": False, "is_member": True}
        ],
    )
    defaults.update(overrides)
    return CredentialStatus(**defaults)


# ---------------------------------------------------------------------------
# core/slack_inventory_models.py
# ---------------------------------------------------------------------------
def test_slack_nhi_input_defaults():
    nhi = SlackNHIInput(nhi_id="x", nhi_name="x", nhi_type=NHIType.SLACK_BOT)
    assert nhi.owner is None
    assert nhi.active is True
    assert nhi.raw_scopes == []
    assert nhi.channels == []


def test_slack_nhi_input_nhi_type_common_is_identity():
    nhi = SlackNHIInput(nhi_id="x", nhi_name="x", nhi_type=NHIType.SLACK_APP)
    assert nhi.nhi_type_common is NHIType.SLACK_APP


def test_slack_nhi_input_scopes_property_strips_and_filters():
    nhi = SlackNHIInput(
        nhi_id="x",
        nhi_name="x",
        nhi_type=NHIType.SLACK_BOT,
        raw_scopes=[" channels:history ", "", "chat:write"],
    )
    assert nhi.scopes == ["channels:history", "chat:write"]


def test_channel_info_defaults():
    channel = ChannelInfo(name="general")
    assert channel.is_private is False
    assert channel.is_sensitive is False


# ---------------------------------------------------------------------------
# build_slack_nhi_input()
# ---------------------------------------------------------------------------
def test_build_slack_nhi_input_bot_token():
    nhi = build_slack_nhi_input(_status(), _status().accessible_resources)
    assert nhi.nhi_id == "slack-T123-B1"
    assert nhi.nhi_name == "support-bot"
    assert nhi.nhi_type == NHIType.SLACK_BOT
    assert nhi.owner is None
    assert nhi.active is True
    assert nhi.raw_scopes == ["channels:history", "chat:write"]
    assert [c.name for c in nhi.channels] == ["general"]


def test_build_slack_nhi_input_maps_user_token_kind():
    status = _status(
        account={"token_kind": "user", "team_id": "T1", "user_id": "U9", "user": "octocat"}
    )
    nhi = build_slack_nhi_input(status, [])
    assert nhi.nhi_type == NHIType.SLACK_USER_TOKEN
    assert nhi.nhi_id == "slack-T1-U9"


def test_build_slack_nhi_input_maps_app_level_token_kind():
    status = _status(
        account={"token_kind": "app_level", "team_id": "T1", "user_id": "U9", "bot_id": "B9"}
    )
    nhi = build_slack_nhi_input(status, [])
    assert nhi.nhi_type == NHIType.SLACK_APP


def test_build_slack_nhi_input_unknown_token_kind_falls_back_to_generic():
    status = _status(account={"token_kind": "refresh", "team_id": "T1", "bot_id": "B9"})
    nhi = build_slack_nhi_input(status, [])
    assert nhi.nhi_type == NHIType.GENERIC_SERVICE_ACCOUNT


def test_build_slack_nhi_input_active_reflects_live_verification():
    active_nhi = build_slack_nhi_input(_status(active=True), [])
    inactive_nhi = build_slack_nhi_input(_status(active=False), [])
    unknown_nhi = build_slack_nhi_input(_status(active=None), [])
    assert active_nhi.active is True
    assert inactive_nhi.active is False
    assert unknown_nhi.active is False  # 확인 못 하면 활성으로 단정하지 않는다


def test_build_slack_nhi_input_requires_identity():
    status = _status(account={"token_kind": "bot"})  # bot_id/user_id 없음
    with pytest.raises(ValueError):
        build_slack_nhi_input(status, [])


def test_build_slack_nhi_input_rejects_non_credential_status():
    with pytest.raises(ValueError):
        build_slack_nhi_input({"active": True}, [])  # type: ignore[arg-type]


def test_build_slack_nhi_input_skips_malformed_channels():
    channels = [
        {"name": "general", "is_private": False},
        {"is_private": True},  # name 없음
        None,
        "not-a-dict",
    ]
    nhi = build_slack_nhi_input(_status(), channels)
    assert [c.name for c in nhi.channels] == ["general"]


# ---------------------------------------------------------------------------
# build_slack_credential_record()
# ---------------------------------------------------------------------------
def test_build_slack_credential_record_reflects_live_active_value():
    nhi = build_slack_nhi_input(_status(active=True), [])
    record = build_slack_credential_record(nhi)
    assert record.credential_active is True
    assert record.provider == "slack"


def test_build_slack_credential_record_does_not_connect_revoked():
    """이번 단계에서는 credential_revoked 연결을 하지 않는다 — 항상 None."""
    nhi = build_slack_nhi_input(_status(active=False, revoked=True), [])
    record = build_slack_credential_record(nhi)
    assert record.credential_revoked is None


def test_build_slack_credential_record_raw_scopes_matches_nhi_scopes():
    nhi = build_slack_nhi_input(_status(), [])
    record = build_slack_credential_record(nhi)
    assert record.raw_scopes == nhi.scopes


def test_build_slack_credential_record_accessible_resources_are_channels():
    nhi = build_slack_nhi_input(_status(), _status().accessible_resources)
    record = build_slack_credential_record(nhi)
    assert record.credential_detail["accessible_resources"] == [
        {"name": "general", "is_private": False, "is_sensitive": False}
    ]


# ---------------------------------------------------------------------------
# build_slack_profile() / build_slack_context()
# ---------------------------------------------------------------------------
def test_build_slack_profile_is_bot_for_bot_and_app_types():
    from agents.inventory_adapter import build_slack_signals

    bot_nhi = build_slack_nhi_input(_status(), [])
    signals = build_slack_signals(bot_nhi)
    assert build_slack_profile(bot_nhi, signals).is_bot is True

    user_nhi = build_slack_nhi_input(
        _status(account={"token_kind": "user", "team_id": "T1", "user_id": "U1", "user": "octo"}),
        [],
    )
    user_signals = build_slack_signals(user_nhi)
    assert build_slack_profile(user_nhi, user_signals).is_bot is False


def test_build_slack_profile_nhi_id_has_slack_prefix():
    nhi = build_slack_nhi_input(_status(), [])
    signals = build_slack_signals(nhi)
    profile = build_slack_profile(nhi, signals)
    assert profile.nhi_id == "slack:slack-T123-B1"
    assert profile.provider == "slack"


def test_build_slack_context_sensitivity_from_channels():
    nhi = SlackNHIInput(
        nhi_id="x",
        nhi_name="x",
        nhi_type=NHIType.SLACK_BOT,
        channels=[ChannelInfo(name="general", is_private=False)],
    )
    signals = build_slack_signals(nhi)
    context = build_slack_context(nhi, signals)
    assert context.data_sensitivity.value == "public"

    private_nhi = nhi.model_copy(
        update={"channels": [ChannelInfo(name="incidents", is_private=True)]}
    )
    private_context = build_slack_context(private_nhi, build_slack_signals(private_nhi))
    assert private_context.data_sensitivity.value == "internal"


# ---------------------------------------------------------------------------
# NHIAnalysisPipeline.analyze_slack_nhi() — 실제 scope 가 ScopeTranslation/Risk/Policy 까지
# ---------------------------------------------------------------------------
def test_pipeline_translates_real_oauth_scopes_not_assumed():
    status = _status(raw_scopes=["channels:history", "chat:write", "admin.users:write"])
    nhi = build_slack_nhi_input(status, status.accessible_resources)

    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    assert analysis.permissions.assumed is False
    assert set(analysis.permissions.permissions) == {
        PermissionLevel.READ,
        PermissionLevel.WRITE,
        PermissionLevel.ADMIN,
    }
    assert analysis.source.value == "inventory"
    assert analysis.profile.nhi_type is NHIType.SLACK_BOT


def test_pipeline_flags_admin_scope_and_missing_owner():
    status = _status(raw_scopes=["admin.users:write"])
    nhi = build_slack_nhi_input(status, [])

    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "ADMIN_SCOPE_RESTRICTED" in violation_ids
    assert "OWNER_REQUIRED" in violation_ids


def test_pipeline_low_permission_scope_has_no_admin_violation():
    status = _status(raw_scopes=["channels:history"])
    nhi = build_slack_nhi_input(status, [])

    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "ADMIN_SCOPE_RESTRICTED" not in violation_ids
    assert analysis.permissions.permissions == [PermissionLevel.READ]


# ---------------------------------------------------------------------------
# GitHub 경로는 전혀 영향받지 않는지
# ---------------------------------------------------------------------------
def test_github_inventory_path_is_unaffected():
    from agents.inventory_adapter import build_github_nhi_input

    nhi = build_github_nhi_input({"login": "octocat", "id": 1}, [])
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)
    assert analysis.profile.provider == "github"
    assert analysis.profile.nhi_id == "github:github-user-1"


# ---------------------------------------------------------------------------
# agents/slack_inventory_service.py — 실제 커넥터 호출 (MockTransport)
# ---------------------------------------------------------------------------
def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_analyze_slack_nhi_from_connector_end_to_end():
    token = "xoxb-live-test-secret"

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
                headers={"x-oauth-scopes": "channels:history,chat:write,admin.users:write"},
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

    with SlackConnector(token, client=_client(handler)) as connector:
        analysis = analyze_slack_nhi_from_connector(connector)

    assert analysis.profile.nhi_id == "slack:slack-T999-B1"
    assert analysis.permissions.assumed is False
    assert PermissionLevel.ADMIN in analysis.permissions.permissions
    assert token not in repr(analysis)
    assert token not in str(analysis.to_dict())


def test_analyze_slack_nhi_from_connector_raises_when_token_invalid():
    token = "xoxb-revoked-token"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth.test":
            return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
        raise AssertionError(f"unexpected path: {request.url.path}")

    with SlackConnector(token, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError):
            analyze_slack_nhi_from_connector(connector)


def test_analyze_slack_nhi_from_connector_does_not_leak_token_on_error():
    token = "xoxb-revoked-token"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})

    with SlackConnector(token, client=_client(handler)) as connector:
        with pytest.raises(AuthenticationError) as error:
            analyze_slack_nhi_from_connector(connector)

    assert token not in str(error.value)
