"""build_github_app_nhi_input() — GitHub App installation → GitHubNHIInput 조립 검증.

pipeline/API endpoint 연결은 아직 없으므로 다루지 않는다. 기존 PAT 조립 함수
(`build_github_nhi_input`)는 건드리지 않았다는 것도 함께 확인한다.
"""

from __future__ import annotations

import pytest

from agents.inventory_adapter import build_github_app_nhi_input, build_github_nhi_input
from agents.scope_translation_agent import ScopeTranslationAgent
from core.inventory_models import GitHubNHIType
from core.nhi_models import PermissionLevel

_INSTALLATION = {
    "installation_id": 555,
    "account_login": "acme-org",
    "account_type": "Organization",
    "repository_selection": "selected",
    "permissions": {"contents": "write", "metadata": "read", "administration": "write"},
    "suspended": False,
}

_REPOSITORIES = [
    {"full_name": "acme/backend", "private": True, "owner_login": "acme"},
    {"full_name": "acme/public-docs", "private": False, "owner_login": "acme"},
]


# ---------------------------------------------------------------------------
# 핵심 조립 규칙
# ---------------------------------------------------------------------------
def test_nhi_type_is_github_app():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.nhi_type == GitHubNHIType.GITHUB_APP


def test_installation_id_is_used_as_stable_identifier():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.nhi_id == "github-app-installation-555"


def test_installation_id_identifier_is_stable_even_if_account_login_changes():
    renamed = {**_INSTALLATION, "account_login": "renamed-org"}
    nhi = build_github_app_nhi_input(renamed, _REPOSITORIES)
    assert nhi.nhi_id == "github-app-installation-555"


def test_raw_permissions_are_preserved_verbatim():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.raw_permissions == {
        "contents": "write",
        "metadata": "read",
        "administration": "write",
    }


def test_raw_permissions_are_not_guessed_when_containing_unknown_keys():
    installation = {**_INSTALLATION, "permissions": {"some_future_permission": "admin"}}
    nhi = build_github_app_nhi_input(installation, _REPOSITORIES)
    assert nhi.raw_permissions == {"some_future_permission": "admin"}


def test_repositories_are_converted_to_repository_info():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert [r.name for r in nhi.repositories] == ["acme/backend", "acme/public-docs"]
    assert [r.visibility for r in nhi.repositories] == ["private", "public"]


def test_installation_id_field_is_populated_as_string():
    """`provider_detail["github_app"]["installation_id"]` 저장에 쓰인다
    (`api/app.py::analyze_github_app_inventory_from_api`) — nhi_id 조립에만
    쓰이던 값을 필드로도 노출한다."""
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.installation_id == "555"


def test_repository_selection_field_is_populated_from_installation():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.repository_selection == "selected"


def test_repository_selection_field_reflects_all_selection():
    installation = {**_INSTALLATION, "repository_selection": "all"}
    nhi = build_github_app_nhi_input(installation, _REPOSITORIES)
    assert nhi.repository_selection == "all"


def test_repository_selection_defaults_to_none_when_missing():
    installation = dict(_INSTALLATION)
    del installation["repository_selection"]
    nhi = build_github_app_nhi_input(installation, _REPOSITORIES)
    assert nhi.repository_selection is None


def test_account_login_is_not_used_as_owner():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.owner is None


def test_account_login_used_as_display_name_only():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.nhi_name == "acme-org"


def test_pat_builder_is_unaffected():
    """기존 PAT 조립 함수는 이번 변경으로 동작이 바뀌지 않아야 한다."""
    user = {"login": "octocat", "id": 42}
    nhi = build_github_nhi_input(user, [{"full_name": "octocat/repo", "private": True}])
    assert nhi.nhi_type == GitHubNHIType.PERSONAL_ACCESS_TOKEN
    assert nhi.nhi_id == "github-user-42"
    assert nhi.raw_permissions == {}


# ---------------------------------------------------------------------------
# active / suspended
# ---------------------------------------------------------------------------
def test_active_is_true_when_not_suspended():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert nhi.active is True


def test_active_is_false_when_suspended():
    suspended = {**_INSTALLATION, "suspended": True}
    nhi = build_github_app_nhi_input(suspended, _REPOSITORIES)
    assert nhi.active is False


def test_active_defaults_true_when_suspended_key_missing():
    installation = dict(_INSTALLATION)
    del installation["suspended"]
    nhi = build_github_app_nhi_input(installation, [])
    assert nhi.active is True


# ---------------------------------------------------------------------------
# 결측/방어 처리
# ---------------------------------------------------------------------------
def test_missing_installation_id_raises_value_error():
    installation = {**_INSTALLATION}
    del installation["installation_id"]
    with pytest.raises(ValueError):
        build_github_app_nhi_input(installation, _REPOSITORIES)


def test_none_installation_id_raises_value_error():
    installation = {**_INSTALLATION, "installation_id": None}
    with pytest.raises(ValueError):
        build_github_app_nhi_input(installation, _REPOSITORIES)


def test_non_dict_installation_raises_value_error():
    with pytest.raises(ValueError):
        build_github_app_nhi_input(None, _REPOSITORIES)  # type: ignore[arg-type]


def test_nhi_name_falls_back_to_installation_id_when_account_login_missing():
    installation = {**_INSTALLATION, "account_login": None}
    nhi = build_github_app_nhi_input(installation, _REPOSITORIES)
    assert nhi.nhi_name == "installation-555"


def test_non_dict_permissions_becomes_empty_dict():
    installation = {**_INSTALLATION, "permissions": "not-a-dict"}
    nhi = build_github_app_nhi_input(installation, _REPOSITORIES)
    assert nhi.raw_permissions == {}


def test_repositories_with_missing_full_name_are_skipped():
    repositories = [
        {"full_name": None, "private": True, "owner_login": "acme"},
        {"private": True, "owner_login": "acme"},  # full_name 자체가 없음
        {"full_name": "acme/valid", "private": False, "owner_login": "acme"},
    ]
    nhi = build_github_app_nhi_input(_INSTALLATION, repositories)
    assert [r.name for r in nhi.repositories] == ["acme/valid"]


def test_non_dict_repository_entries_are_skipped():
    nhi = build_github_app_nhi_input(_INSTALLATION, [None, "not-a-dict"])  # type: ignore[list-item]
    assert nhi.repositories == []


def test_empty_repositories_produces_empty_list():
    nhi = build_github_app_nhi_input(_INSTALLATION, [])
    assert nhi.repositories == []


# ---------------------------------------------------------------------------
# raw_permissions 가 실제로 Scope Translation 과 호환되는지 (기존 컴포넌트 재확인용)
# ---------------------------------------------------------------------------
def test_scopes_property_expands_raw_permissions_for_scope_translation():
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    assert set(nhi.scopes) == {"contents:write", "metadata:read", "administration:write"}


def test_permissions_translate_to_real_levels_instead_of_being_unset():
    """raw_permissions 가 채워지면 ScopeTranslationAgent 가 실제 권한을 판정한다.

    (PAT 경로에서 raw_scopes/raw_permissions 가 비어 있을 때와 달리, 여기서는
    권한이 비어 있지도 않고 유형 기준으로 가정되지도 않는다.)
    """
    nhi = build_github_app_nhi_input(_INSTALLATION, _REPOSITORIES)
    profile = ScopeTranslationAgent().translate(
        nhi.scopes, provider="github", secret_type=nhi.nhi_type.value, assume_if_missing=False
    )
    assert profile.assumed is False
    assert PermissionLevel.ADMIN in profile.permissions  # administration:write
    assert PermissionLevel.WRITE in profile.permissions  # contents:write
    assert PermissionLevel.READ in profile.permissions  # metadata:read
