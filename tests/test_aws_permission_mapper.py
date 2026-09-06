"""`agents/aws_permission_mapper.py` 검증.

Deny/Resource/Condition 해석·위험도 계산은 다루지 않는다 — Action 문자열
하나를 공통 권한(READ/WRITE/DELETE/ADMIN)으로, 또는 모호하면 `None`
("UNKNOWN")으로 정확히 변환하는지만 확인한다.
"""

from __future__ import annotations

from agents.aws_permission_mapper import map_action, map_actions
from agents.aws_policy_normalizer import normalize_policy_statements
from core.nhi_models import PermissionLevel


# ---------------------------------------------------------------------------
# 사용자가 제시한 예시 — 그대로 성립해야 한다
# ---------------------------------------------------------------------------
def test_s3_get_object_is_read():
    assert map_action("s3:GetObject") is PermissionLevel.READ


def test_s3_put_object_is_write():
    assert map_action("s3:PutObject") is PermissionLevel.WRITE


def test_s3_delete_object_is_delete():
    assert map_action("s3:DeleteObject") is PermissionLevel.DELETE


def test_iam_create_user_is_admin():
    assert map_action("iam:CreateUser") is PermissionLevel.ADMIN


def test_iam_wildcard_is_admin():
    assert map_action("iam:*") is PermissionLevel.ADMIN


# ---------------------------------------------------------------------------
# 와일드카드 — 서비스 전체/계정 전체
# ---------------------------------------------------------------------------
def test_bare_wildcard_is_admin():
    assert map_action("*") is PermissionLevel.ADMIN


def test_service_wildcard_for_non_iam_service_is_also_admin():
    assert map_action("s3:*") is PermissionLevel.ADMIN
    assert map_action("dynamodb:*") is PermissionLevel.ADMIN


# ---------------------------------------------------------------------------
# 서비스 무관 일반 동사 규칙 — s3 이외의 서비스에도 적용되는지
# ---------------------------------------------------------------------------
def test_generic_read_prefixes_across_services():
    assert map_action("ec2:DescribeInstances") is PermissionLevel.READ
    assert map_action("dynamodb:GetItem") is PermissionLevel.READ
    assert map_action("lambda:ListFunctions") is PermissionLevel.READ


def test_generic_write_prefixes_across_services():
    assert map_action("dynamodb:PutItem") is PermissionLevel.WRITE
    assert map_action("ec2:CreateTags") is PermissionLevel.WRITE
    assert map_action("lambda:InvokeFunction") is PermissionLevel.WRITE


def test_generic_delete_prefixes_across_services():
    assert map_action("sqs:DeleteQueue") is PermissionLevel.DELETE
    assert map_action("ec2:TerminateInstances") is PermissionLevel.DELETE
    assert map_action("ec2:RevokeSecurityGroupIngress") is PermissionLevel.DELETE


# ---------------------------------------------------------------------------
# IAM 전용 규칙 — 읽기는 READ, 상태 변경은 DELETE 가 아니라 ADMIN
# ---------------------------------------------------------------------------
def test_iam_read_actions_are_read():
    assert map_action("iam:GetUser") is PermissionLevel.READ
    assert map_action("iam:ListRoles") is PermissionLevel.READ
    assert map_action("iam:ListAttachedUserPolicies") is PermissionLevel.READ


def test_iam_delete_user_is_admin_not_delete():
    """일반 서비스라면 Delete* 는 DELETE 지만, IAM 은 신원 자체를 지우는
    행위라 ADMIN 으로 분류해야 한다 — 여기가 이 매퍼의 핵심 판단이다."""
    assert map_action("iam:DeleteUser") is PermissionLevel.ADMIN
    assert map_action("iam:DeleteAccessKey") is PermissionLevel.ADMIN


def test_iam_attach_and_put_policy_actions_are_admin():
    assert map_action("iam:AttachUserPolicy") is PermissionLevel.ADMIN
    assert map_action("iam:PutUserPolicy") is PermissionLevel.ADMIN
    assert map_action("iam:CreateAccessKey") is PermissionLevel.ADMIN


# ---------------------------------------------------------------------------
# 모호한 Action → None ("UNKNOWN"), 추측하지 않는다
# ---------------------------------------------------------------------------
def test_unrecognized_verb_returns_none():
    assert map_action("s3:AbortMultipartUpload") is None
    assert map_action("foo:FrobnicateWidget") is None


def test_iam_unrecognized_verb_returns_none_not_a_guess():
    assert map_action("iam:SimulatePrincipalPolicy") is None


def test_malformed_action_without_colon_returns_none():
    assert map_action("not-a-valid-action-format") is None


def test_empty_and_whitespace_action_returns_none():
    assert map_action("") is None
    assert map_action("   ") is None


def test_non_string_input_returns_none():
    assert map_action(None) is None  # type: ignore[arg-type]
    assert map_action(123) is None  # type: ignore[arg-type]
    assert map_action(["s3:GetObject"]) is None  # type: ignore[arg-type]


def test_action_missing_action_name_part_returns_none():
    assert map_action("s3:") is None
    assert map_action(":GetObject") is None


# ---------------------------------------------------------------------------
# map_actions() — 여러 Action 일괄 변환
# ---------------------------------------------------------------------------
def test_map_actions_returns_dict_per_action():
    result = map_actions(["s3:GetObject", "s3:PutObject", "s3:UnknownAction"])
    assert result == {
        "s3:GetObject": PermissionLevel.READ,
        "s3:PutObject": PermissionLevel.WRITE,
        "s3:UnknownAction": None,
    }


def test_map_actions_empty_list_returns_empty_dict():
    assert map_actions([]) == {}
    assert map_actions(None) == {}  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Deny 는 이 모듈의 관심사가 아니다 — Action 문자열만 보고 같은 값을 낸다
# ---------------------------------------------------------------------------
def test_mapping_does_not_consider_effect_because_it_is_not_given_one():
    """이 함수는 Action 문자열만 받는다 — Deny 문에서 나온 것이든 Allow 문에서
    나온 것이든 호출부는 구분해서 넘겨야 하고, 이 함수는 그 구분을 모른다."""
    assert map_action("s3:DeleteObject") is PermissionLevel.DELETE  # Allow/Deny 무관하게 동일


# ---------------------------------------------------------------------------
# 통합 — normalize_policy_statements() 결과를 그대로 입력할 수 있는지
# ---------------------------------------------------------------------------
def test_integrates_with_normalized_policy_statements():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": "*",
            },
            {"Effect": "Deny", "Action": "iam:DeleteUser", "Resource": "*"},
        ],
    }
    statements = normalize_policy_statements(document)

    allow_permissions = map_actions(statements[0]["actions"])
    assert allow_permissions == {
        "s3:GetObject": PermissionLevel.READ,
        "s3:PutObject": PermissionLevel.WRITE,
        "s3:DeleteObject": PermissionLevel.DELETE,
    }

    deny_permissions = map_actions(statements[1]["actions"])
    assert deny_permissions == {"iam:DeleteUser": PermissionLevel.ADMIN}
    # Effect 가 Deny 였다는 사실 자체는 이 모듈이 신경 쓰지 않는다.
    assert statements[1]["effect"] == "Deny"
