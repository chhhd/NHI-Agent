"""`agents/aws_policy_normalizer.py::normalize_policy_statements()` 검증.

Read/Write/Delete/Admin 변환·위험도 계산은 아직 없으므로 다루지 않는다 —
Statement 구조 자체를 `effect`/`actions`/`resources`/`condition` 4개 필드로
정확히 정규화하는지만 확인한다.
"""

from __future__ import annotations

from agents.aws_policy_normalizer import normalize_policy_statements


# ---------------------------------------------------------------------------
# 기본 정규화
# ---------------------------------------------------------------------------
def test_normalizes_single_statement_with_list_action_and_resource():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
            }
        ],
    }
    result = normalize_policy_statements(document)

    assert result == [
        {
            "effect": "Allow",
            "actions": ["s3:GetObject", "s3:ListBucket"],
            "resources": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
            "condition": None,
        }
    ]


def test_normalizes_multiple_statements_independently():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ]
    }
    result = normalize_policy_statements(document)

    assert len(result) == 2
    assert result[0]["effect"] == "Allow"
    assert result[1]["effect"] == "Deny"


# ---------------------------------------------------------------------------
# Action/Resource 문자열 → 리스트 변환
# ---------------------------------------------------------------------------
def test_single_string_action_is_wrapped_in_a_list():
    document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    result = normalize_policy_statements(document)
    assert result[0]["actions"] == ["s3:GetObject"]


def test_single_string_resource_is_wrapped_in_a_list():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket"}
        ]
    }
    result = normalize_policy_statements(document)
    assert result[0]["resources"] == ["arn:aws:s3:::my-bucket"]


def test_wildcard_action_and_resource_become_single_item_lists():
    """AdministratorAccess 형태 — "*"/"*" 도 리스트로 정규화된다."""
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    result = normalize_policy_statements(document)
    assert result[0]["actions"] == ["*"]
    assert result[0]["resources"] == ["*"]


def test_non_string_items_in_action_list_are_filtered_out():
    document = {
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", 123, None], "Resource": "*"}]
    }
    result = normalize_policy_statements(document)
    assert result[0]["actions"] == ["s3:GetObject"]


# ---------------------------------------------------------------------------
# Effect — Allow/Deny 그대로 보존
# ---------------------------------------------------------------------------
def test_allow_effect_is_preserved_verbatim():
    document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    assert normalize_policy_statements(document)[0]["effect"] == "Allow"


def test_deny_effect_is_preserved_verbatim():
    document = {"Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]}
    assert normalize_policy_statements(document)[0]["effect"] == "Deny"


def test_missing_effect_is_none_not_fabricated():
    document = {"Statement": [{"Action": "s3:GetObject", "Resource": "*"}]}
    assert normalize_policy_statements(document)[0]["effect"] is None


# ---------------------------------------------------------------------------
# Condition — 원문 그대로 보존
# ---------------------------------------------------------------------------
def test_condition_is_preserved_as_is():
    condition = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
    document = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": condition,
            }
        ]
    }
    result = normalize_policy_statements(document)
    assert result[0]["condition"] == condition


def test_missing_condition_is_none():
    document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    assert normalize_policy_statements(document)[0]["condition"] is None


# ---------------------------------------------------------------------------
# Statement 가 배열이 아니라 단일 객체인 경우 (IAM 이 허용하는 축약 표기)
# ---------------------------------------------------------------------------
def test_single_statement_object_not_wrapped_in_array_is_handled():
    document = {
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    }
    result = normalize_policy_statements(document)
    assert len(result) == 1
    assert result[0]["actions"] == ["s3:GetObject"]


# ---------------------------------------------------------------------------
# NotAction/NotResource — 아직 지원하지 않음 (값을 지어내지 않는다)
# ---------------------------------------------------------------------------
def test_not_action_only_statement_yields_empty_actions():
    document = {
        "Statement": [{"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}]
    }
    result = normalize_policy_statements(document)
    assert result[0]["actions"] == []
    assert result[0]["effect"] == "Deny"  # 나머지 필드는 정상 처리됨


def test_not_resource_only_statement_yields_empty_resources():
    document = {
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "*"}]
    }
    result = normalize_policy_statements(document)
    assert result[0]["resources"] == []


# ---------------------------------------------------------------------------
# 방어적 입력 처리 — 크래시 없이 빈 결과
# ---------------------------------------------------------------------------
def test_missing_statement_key_returns_empty_list():
    assert normalize_policy_statements({"Version": "2012-10-17"}) == []


def test_non_dict_document_returns_empty_list():
    assert normalize_policy_statements(None) == []  # type: ignore[arg-type]
    assert normalize_policy_statements("not-a-dict") == []  # type: ignore[arg-type]
    assert normalize_policy_statements([]) == []  # type: ignore[arg-type]


def test_statement_list_with_non_dict_items_skips_them():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            "not-a-statement",
            None,
        ]
    }
    result = normalize_policy_statements(document)
    assert len(result) == 1
    assert result[0]["actions"] == ["s3:GetObject"]


def test_empty_statement_list_returns_empty_list():
    assert normalize_policy_statements({"Statement": []}) == []


# ---------------------------------------------------------------------------
# 실제 AWSConnector.get_policy_document() 출력 형태와의 호환성
# ---------------------------------------------------------------------------
def test_compatible_with_administrator_access_shaped_document():
    """AWSConnector.get_policy_document() 가 반환하는 것과 동일한 형태
    (URL-디코딩까지 끝난 순수 dict)를 그대로 입력으로 받는다."""
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    result = normalize_policy_statements(document)
    assert result == [
        {"effect": "Allow", "actions": ["*"], "resources": ["*"], "condition": None}
    ]


def test_compatible_with_read_only_shaped_document_multiple_actions():
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadOnly",
                "Effect": "Allow",
                "Action": ["s3:Get*", "s3:List*"],
                "Resource": "*",
            }
        ],
    }
    result = normalize_policy_statements(document)
    assert result[0]["actions"] == ["s3:Get*", "s3:List*"]
    assert result[0]["resources"] == ["*"]
