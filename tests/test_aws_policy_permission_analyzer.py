"""`agents/aws_policy_permission_analyzer.py::analyze_policy_permissions()` 검증.

Resource/Condition 에 따른 실제 권한 상쇄 계산은 아직 없으므로 다루지
않는다 — `Effect=Allow` Action 을 READ/WRITE/DELETE/ADMIN/UNKNOWN 으로
정확히 집계하고, `Effect=Deny` Statement 는 상쇄 없이 별도 보존/개수만
기록하는지 확인한다.
"""

from __future__ import annotations

from agents.aws_permission_mapper import map_action
from agents.aws_policy_normalizer import normalize_policy_statements
from agents.aws_policy_permission_analyzer import (
    AWSPolicyPermissionAnalysis,
    AWSPolicyPermissionCounts,
    analyze_policy_permissions,
)


def _statement(effect="Allow", actions=None, resources=None, condition=None):
    return {
        "effect": effect,
        "actions": actions or [],
        "resources": resources or [],
        "condition": condition,
    }


# ---------------------------------------------------------------------------
# 기본 집계 — Allow Action 을 READ/WRITE/DELETE/ADMIN/UNKNOWN 으로
# ---------------------------------------------------------------------------
def test_counts_each_permission_level_from_a_single_allow_statement():
    statements = [
        _statement(
            actions=[
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "iam:CreateUser",
                "some:unknown-action",
            ]
        )
    ]
    result = analyze_policy_permissions(statements)

    assert result.counts.to_dict() == {
        "READ": 1,
        "WRITE": 1,
        "DELETE": 1,
        "ADMIN": 1,
        "UNKNOWN": 1,
    }
    assert result.allow_statement_count == 1
    assert result.deny_statement_count == 0
    assert result.deny_statements == []


def test_aggregates_across_multiple_allow_statements():
    statements = [
        _statement(actions=["s3:GetObject", "s3:GetBucketPolicy"]),
        _statement(actions=["s3:PutObject"]),
        _statement(actions=["s3:DeleteObject", "s3:DeleteBucket"]),
    ]
    result = analyze_policy_permissions(statements)

    assert result.counts.read == 2
    assert result.counts.write == 1
    assert result.counts.delete == 2
    assert result.allow_statement_count == 3


def test_wildcard_action_counts_as_admin():
    statements = [_statement(actions=["*"])]
    result = analyze_policy_permissions(statements)
    assert result.counts.admin == 1


def test_administrator_access_shaped_policy_counts_as_single_admin_action():
    statements = [_statement(actions=["*"], resources=["*"])]
    result = analyze_policy_permissions(statements)
    assert result.counts.to_dict() == {"READ": 0, "WRITE": 0, "DELETE": 0, "ADMIN": 1, "UNKNOWN": 0}


# ---------------------------------------------------------------------------
# Deny — 상쇄하지 않고 별도로 보존/개수만 기록
# ---------------------------------------------------------------------------
def test_deny_statement_actions_are_not_counted_toward_permissions():
    statements = [_statement(effect="Deny", actions=["s3:GetObject", "iam:CreateUser"])]
    result = analyze_policy_permissions(statements)

    assert result.counts.to_dict() == {"READ": 0, "WRITE": 0, "DELETE": 0, "ADMIN": 0, "UNKNOWN": 0}
    assert result.allow_statement_count == 0


def test_deny_statement_is_counted_and_preserved_verbatim():
    deny_statement = _statement(
        effect="Deny",
        actions=["iam:DeleteUser"],
        resources=["*"],
        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    )
    result = analyze_policy_permissions([deny_statement])

    assert result.deny_statement_count == 1
    assert result.deny_statements == [deny_statement]


def test_mixed_allow_and_deny_statements_are_separated_correctly():
    statements = [
        _statement(effect="Allow", actions=["s3:GetObject"]),
        _statement(effect="Deny", actions=["s3:DeleteObject"]),
        _statement(effect="Allow", actions=["s3:PutObject"]),
    ]
    result = analyze_policy_permissions(statements)

    assert result.counts.read == 1
    assert result.counts.write == 1
    assert result.counts.delete == 0  # Deny 문의 DeleteObject 는 집계되지 않음
    assert result.allow_statement_count == 2
    assert result.deny_statement_count == 1
    assert result.deny_statements[0]["actions"] == ["s3:DeleteObject"]


def test_deny_statement_does_not_offset_an_allow_of_the_same_action():
    """실제 IAM 평가에서는 Deny 가 우선하지만, 이번 단계는 그 상쇄 계산을
    하지 않는다 — Allow 문의 집계 결과는 그대로 남아 있어야 한다."""
    statements = [
        _statement(effect="Allow", actions=["s3:DeleteObject"]),
        _statement(effect="Deny", actions=["s3:DeleteObject"]),
    ]
    result = analyze_policy_permissions(statements)

    assert result.counts.delete == 1  # 아직 상쇄되지 않음(의도된 동작)
    assert result.deny_statement_count == 1


def test_multiple_deny_statements_are_all_preserved():
    statements = [
        _statement(effect="Deny", actions=["s3:DeleteObject"]),
        _statement(effect="Deny", actions=["iam:DeleteUser"]),
    ]
    result = analyze_policy_permissions(statements)

    assert result.deny_statement_count == 2
    assert len(result.deny_statements) == 2


# ---------------------------------------------------------------------------
# Resource/Condition 은 이 계산에 관여하지 않는다
# ---------------------------------------------------------------------------
def test_resource_and_condition_do_not_affect_the_count():
    permissive = _statement(actions=["s3:GetObject"], resources=["*"], condition=None)
    restricted = _statement(
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::my-bucket/private/*"],
        condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    )

    assert analyze_policy_permissions([permissive]).counts.read == 1
    assert analyze_policy_permissions([restricted]).counts.read == 1


# ---------------------------------------------------------------------------
# 방어적 입력 처리
# ---------------------------------------------------------------------------
def test_empty_statement_list_returns_all_zero_counts():
    result = analyze_policy_permissions([])
    assert result.counts.to_dict() == {"READ": 0, "WRITE": 0, "DELETE": 0, "ADMIN": 0, "UNKNOWN": 0}
    assert result.allow_statement_count == 0
    assert result.deny_statement_count == 0


def test_none_input_returns_all_zero_counts():
    result = analyze_policy_permissions(None)  # type: ignore[arg-type]
    assert result.counts.to_dict() == {"READ": 0, "WRITE": 0, "DELETE": 0, "ADMIN": 0, "UNKNOWN": 0}


def test_non_dict_statement_items_are_skipped():
    statements = [_statement(actions=["s3:GetObject"]), "not-a-statement", None]
    result = analyze_policy_permissions(statements)
    assert result.counts.read == 1
    assert result.allow_statement_count == 1


def test_statement_with_no_effect_is_counted_in_neither_bucket():
    statement = {"effect": None, "actions": ["s3:GetObject"], "resources": [], "condition": None}
    result = analyze_policy_permissions([statement])

    assert result.counts.read == 0
    assert result.allow_statement_count == 0
    assert result.deny_statement_count == 0


def test_statement_with_empty_actions_contributes_no_counts_but_counts_as_allow_statement():
    result = analyze_policy_permissions([_statement(actions=[])])
    assert result.counts.to_dict() == {"READ": 0, "WRITE": 0, "DELETE": 0, "ADMIN": 0, "UNKNOWN": 0}
    assert result.allow_statement_count == 1


# ---------------------------------------------------------------------------
# to_dict() 직렬화
# ---------------------------------------------------------------------------
def test_counts_to_dict_shape():
    counts = AWSPolicyPermissionCounts(read=1, write=2, delete=3, admin=4, unknown=5)
    assert counts.to_dict() == {"READ": 1, "WRITE": 2, "DELETE": 3, "ADMIN": 4, "UNKNOWN": 5}


def test_analysis_to_dict_shape():
    analysis = analyze_policy_permissions(
        [
            _statement(effect="Allow", actions=["s3:GetObject"]),
            _statement(effect="Deny", actions=["s3:DeleteObject"]),
        ]
    )
    data = analysis.to_dict()
    assert data["counts"]["READ"] == 1
    assert data["allow_statement_count"] == 1
    assert data["deny_statement_count"] == 1
    assert len(data["deny_statements"]) == 1


# ---------------------------------------------------------------------------
# 통합 — normalize_policy_statements() 실제 출력과 조합
# ---------------------------------------------------------------------------
def test_integrates_with_real_normalized_document():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
            {
                "Effect": "Deny",
                "Action": "iam:DeleteUser",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
            },
        ],
    }
    statements = normalize_policy_statements(document)
    result = analyze_policy_permissions(statements)

    assert result.counts.read == 1
    assert result.counts.write == 1
    assert result.allow_statement_count == 1
    assert result.deny_statement_count == 1
    assert result.deny_statements[0]["actions"] == ["iam:DeleteUser"]
    assert result.deny_statements[0]["condition"] == {
        "Bool": {"aws:MultiFactorAuthPresent": "false"}
    }


def test_integrates_with_administrator_access_document():
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    statements = normalize_policy_statements(document)
    result = analyze_policy_permissions(statements)

    assert result.counts.admin == 1
    assert result.counts.to_dict() == {"READ": 0, "WRITE": 0, "DELETE": 0, "ADMIN": 1, "UNKNOWN": 0}


def test_map_action_consistency_used_internally():
    """analyze_policy_permissions() 는 map_action() 을 그대로 재사용한다 —
    같은 Action 은 독립 호출과 같은 결과가 나와야 한다."""
    action = "iam:AttachUserPolicy"
    expected_level = map_action(action)
    result = analyze_policy_permissions([_statement(actions=[action])])

    assert expected_level is not None
    field_name = expected_level.value.lower()
    assert getattr(result.counts, field_name) == 1
