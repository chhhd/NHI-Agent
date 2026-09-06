"""`ScopeTranslationAgent`의 AWS 전용 분기(`_translate_aws`) 검증.

AWS raw_scopes(IAM Action 문자열)는 GitHub/Slack의 `SCOPE_TABLE`/
`COMMON_SCOPE_TABLE`/문자열 휴리스틱(`_infer()`)을 타지 않고
`agents/aws_permission_mapper.py::map_action()` 을 그대로 재사용해야 한다.
`map_action()` 이 모른다고 답한 Action 은 추측하지 않고 미확인으로 남아야
한다. Deny/Resource/Condition 상쇄 계산은 아직 없다. GitHub/Slack 경로는
이번 변경으로 전혀 영향받지 않아야 한다.
"""

from __future__ import annotations

from agents.aws_permission_mapper import map_action
from agents.scope_translation_agent import ScopeTranslationAgent
from core.nhi_models import PermissionLevel


def _agent() -> ScopeTranslationAgent:
    return ScopeTranslationAgent()


# ---------------------------------------------------------------------------
# 기본 변환 — map_action() 결과를 그대로 반영
# ---------------------------------------------------------------------------
def test_translate_uses_map_action_for_known_actions():
    profile = _agent().translate(
        ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        provider="aws",
        assume_if_missing=False,
    )
    assert set(profile.permissions) == {
        PermissionLevel.READ,
        PermissionLevel.WRITE,
        PermissionLevel.DELETE,
    }
    assert profile.assumed is False
    assert profile.unknown_scopes == []


def test_translate_iam_delete_user_is_admin_not_delete():
    """이 클래스가 map_action() 을 우회해서 문자열 휴리스틱으로 다시
    해석하면 iam:DeleteUser 가 DELETE 로 잘못 떨어진다 — 그러면 안 된다."""
    profile = _agent().translate(["iam:DeleteUser"], provider="aws", assume_if_missing=False)
    assert profile.permissions == [PermissionLevel.ADMIN]
    assert PermissionLevel.DELETE not in profile.permissions


def test_translate_mapping_metadata_matches_map_action_output():
    profile = _agent().translate(["iam:CreateUser"], provider="aws", assume_if_missing=False)
    mapping = profile.mappings[0]
    assert mapping.raw_scope == "iam:CreateUser"
    assert mapping.permission == map_action("iam:CreateUser")
    assert mapping.inferred is False


# ---------------------------------------------------------------------------
# UNKNOWN Action — 추측하지 않고 미확인으로 남긴다
# ---------------------------------------------------------------------------
def test_unknown_action_is_left_unresolved_not_guessed():
    profile = _agent().translate(
        ["s3:AbortMultipartUpload"], provider="aws", assume_if_missing=False
    )
    mapping = profile.mappings[0]
    assert mapping.permission is None
    assert profile.unknown_scopes == ["s3:AbortMultipartUpload"]
    assert profile.permissions == []
    assert profile.assumed is False  # 가정으로 대체하지 않는다(scope 자체는 있었으므로)


def test_mixed_known_and_unknown_actions():
    profile = _agent().translate(
        ["s3:GetObject", "s3:AbortMultipartUpload"], provider="aws", assume_if_missing=False
    )
    assert profile.permissions == [PermissionLevel.READ]
    assert profile.unknown_scopes == ["s3:AbortMultipartUpload"]


def test_all_unknown_actions_with_assume_if_missing_false_stays_empty():
    """scope 는 있었지만 전부 해석 불가 + assume_if_missing=False (인벤토리
    경로) 이면 가정으로 대체하지 않고 permissions 를 비워 둔다."""
    profile = _agent().translate(
        ["foo:Frobnicate", "bar:Whatchamacallit"], provider="aws", assume_if_missing=False
    )
    assert profile.permissions == []
    assert profile.assumed is False
    assert set(profile.unknown_scopes) == {"foo:Frobnicate", "bar:Whatchamacallit"}


# ---------------------------------------------------------------------------
# assume_if_missing — scope 자체가 없을 때만 가정 (다른 provider 와 동일 의미)
# ---------------------------------------------------------------------------
def test_empty_scopes_without_assume_stays_empty():
    """AWS 인벤토리 경로(assume_if_missing=False)는 Scope 가 없으면 그냥 빈 값이다."""
    profile = _agent().translate([], provider="aws", assume_if_missing=False)
    assert profile.permissions == []
    assert profile.assumed is False


def test_empty_scopes_with_assume_uses_existing_assumed_table():
    """코드 스캔 경로(assume_if_missing=True)는 기존 ASSUMED_PERMISSIONS 테이블을
    그대로 재사용한다 — 이번 변경으로 새로 만들지 않는다."""
    profile = _agent().translate(
        [], provider="aws", secret_type="AWS_ACCESS_KEY_ID", assume_if_missing=True
    )
    assert profile.assumed is True
    assert set(profile.permissions) == {
        PermissionLevel.READ,
        PermissionLevel.WRITE,
        PermissionLevel.DELETE,
        PermissionLevel.ADMIN,
    }


def test_all_unknown_actions_with_assume_if_missing_true_falls_back_to_assumed():
    profile = _agent().translate(
        ["foo:Frobnicate"], provider="aws", secret_type="AWS_ACCESS_KEY_ID", assume_if_missing=True
    )
    assert profile.assumed is True


# ---------------------------------------------------------------------------
# translate_scope() — 단일 Action 변환도 동일 경로를 탄다
# ---------------------------------------------------------------------------
def test_translate_scope_uses_map_action_for_aws():
    mapping = _agent().translate_scope("s3:PutObject", provider="aws")
    assert mapping.permission is PermissionLevel.WRITE
    assert mapping.inferred is False


def test_translate_scope_unknown_aws_action_is_none():
    mapping = _agent().translate_scope("s3:AbortMultipartUpload", provider="aws")
    assert mapping.permission is None


def test_translate_scope_provider_case_insensitive():
    mapping = _agent().translate_scope("s3:GetObject", provider="AWS")
    assert mapping.permission is PermissionLevel.READ


# ---------------------------------------------------------------------------
# translate_finding() — SecretFinding.provider="aws" 경로
# ---------------------------------------------------------------------------
def test_translate_finding_routes_aws_provider_correctly():
    from core.models import CodeContext, DetectorType, SecretFinding, Severity

    finding = SecretFinding(
        secret_type="CLOUD_SERVICE_ACCOUNT",
        provider="aws",
        masked_value="",
        fingerprint="nhi:test",
        file_path="",
        line_number=0,
        detector=DetectorType.REGEX,
        severity=Severity.MEDIUM,
        context=CodeContext(before=[], line="", after=[]),
        raw_scopes=["s3:GetObject", "iam:DeleteUser"],
    )
    profile = _agent().translate_finding(finding, assume_if_missing=False)
    assert set(profile.permissions) == {PermissionLevel.READ, PermissionLevel.ADMIN}
    assert profile.assumed is False


# ---------------------------------------------------------------------------
# GitHub/Slack 경로는 이번 변경으로 전혀 영향받지 않는지
# ---------------------------------------------------------------------------
def test_github_scope_translation_is_unaffected():
    profile = _agent().translate(["repo", "workflow"], provider="github", assume_if_missing=False)
    assert profile.permissions == [PermissionLevel.WRITE, PermissionLevel.ADMIN]
    assert profile.assumed is False


def test_slack_scope_translation_is_unaffected():
    profile = _agent().translate(
        ["groups:read", "chat:write"], provider="slack", assume_if_missing=False
    )
    assert set(profile.permissions) == {PermissionLevel.READ, PermissionLevel.WRITE}
    # groups:read 는 여전히 명시 테이블 매핑(inferred=False)이어야 한다.
    groups_read = next(m for m in profile.mappings if m.raw_scope == "groups:read")
    assert groups_read.inferred is False


def test_generic_provider_heuristic_is_unaffected():
    """AWS 가 아닌 provider 는 여전히 기존 문자열 휴리스틱(_infer())을 탄다."""
    profile = _agent().translate(
        ["some_custom_read_scope"], provider="some-other-service", assume_if_missing=False
    )
    mapping = profile.mappings[0]
    assert mapping.permission is PermissionLevel.READ
    assert mapping.inferred is True  # 휴리스틱 추정임이 여전히 표시됨
