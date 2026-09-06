"""`groups:read` Slack scope 가 명시적 READ 매핑으로 처리되는지 확인.

이전에는 `SCOPE_TABLE["slack"]` 에 `groups:read` 항목이 없어
`ScopeTranslationAgent._infer()` 의 문자열 휴리스틱("read" 토큰 매칭)으로
떨어져 `inferred=True` 로 표시됐다. `groups:history`/`channels:read` 처럼
명시적 테이블 항목을 추가해 `inferred=False` 가 되도록 고쳤다.

다른 Slack scope 와 GitHub 테이블은 전혀 건드리지 않았다는 것도 함께 확인한다.
"""

from __future__ import annotations

from agents.scope_translation_agent import ScopeTranslationAgent
from core.nhi_models import PermissionLevel


def _mapping(scopes, provider="slack"):
    profile = ScopeTranslationAgent().translate(scopes, provider=provider)
    return {m.raw_scope: m for m in profile.mappings}


# ---------------------------------------------------------------------------
# groups:read — 이번에 고친 대상
# ---------------------------------------------------------------------------
def test_groups_read_maps_to_explicit_read_not_inferred():
    mapping = _mapping(["groups:read"])["groups:read"]
    assert mapping.permission is PermissionLevel.READ
    assert mapping.inferred is False


def test_groups_read_translation_reflected_in_permission_profile():
    profile = ScopeTranslationAgent().translate(["groups:read"], provider="slack")
    assert profile.permissions == [PermissionLevel.READ]
    assert profile.assumed is False
    assert profile.unknown_scopes == []


def test_groups_read_alongside_other_scopes_is_still_explicit():
    mapping = _mapping(["groups:read", "chat:write", "admin.users:write"])
    assert mapping["groups:read"].inferred is False
    assert mapping["groups:read"].permission is PermissionLevel.READ


# ---------------------------------------------------------------------------
# 다른 Slack scope 는 영향받지 않았는지 (기존 명시적 항목들의 회귀 확인)
# ---------------------------------------------------------------------------
def test_other_slack_scopes_are_unaffected():
    mapping = _mapping(
        [
            "channels:history",
            "channels:read",
            "groups:history",
            "chat:write",
            "groups:write",
            "admin",
        ]
    )
    assert mapping["channels:history"].permission is PermissionLevel.READ
    assert mapping["channels:read"].permission is PermissionLevel.READ
    assert mapping["groups:history"].permission is PermissionLevel.READ
    assert mapping["chat:write"].permission is PermissionLevel.WRITE
    assert mapping["groups:write"].permission is PermissionLevel.WRITE
    assert mapping["admin"].permission is PermissionLevel.ADMIN
    for scope, m in mapping.items():
        assert m.inferred is False, f"{scope} 는 여전히 명시적 매핑이어야 한다"


def test_unknown_slack_scope_still_falls_back_to_heuristic_inference():
    """groups:read 를 테이블에 추가한 것이 휴리스틱 추론 경로 자체를 없애지 않는다."""
    mapping = _mapping(["some_future_slack_scope:read"])["some_future_slack_scope:read"]
    assert mapping.permission is PermissionLevel.READ
    assert mapping.inferred is True


# ---------------------------------------------------------------------------
# GitHub 테이블은 전혀 영향받지 않았는지
# ---------------------------------------------------------------------------
def test_github_scope_table_unaffected():
    mapping = _mapping(["contents:read", "repo", "administration:write"], provider="github")
    assert mapping["contents:read"].permission is PermissionLevel.READ
    assert mapping["repo"].permission is PermissionLevel.ADMIN
    assert mapping["administration:write"].permission is PermissionLevel.ADMIN
    for scope, m in mapping.items():
        assert m.inferred is False


# ---------------------------------------------------------------------------
# end-to-end — 실제 Slack 인벤토리 분석의 permission_detail 에도 반영되는지
# ---------------------------------------------------------------------------
def test_end_to_end_slack_analysis_shows_groups_read_as_not_inferred():
    from agents.inventory_adapter import build_slack_nhi_input
    from agents.pipeline import NHIAnalysisPipeline
    from core.models import CredentialStatus

    status = CredentialStatus(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["groups:read", "chat:write"],
        account={
            "token_kind": "bot",
            "team_id": "T1",
            "user": "support-bot",
            "user_id": "U1",
            "bot_id": "B1",
        },
        accessible_resources=[],
    )
    nhi = build_slack_nhi_input(status, [])
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    detail = analysis.permissions.to_dict()
    groups_read_mapping = next(
        m for m in detail["mappings"] if m["raw_scope"] == "groups:read"
    )
    assert groups_read_mapping["permission"] == "READ"
    assert groups_read_mapping["inferred"] is False
