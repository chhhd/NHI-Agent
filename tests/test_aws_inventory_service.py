"""agents/aws_inventory_service.py::build_aws_nhi_input_from_connector() 검증.

흐름: get_caller_identity() → list_access_keys() → 현재 사용 중인
access_key_id 와 일치하는 키 선택 → get_access_key_last_used() →
list_attached_user_policies() → (Policy 별) get_policy_document() →
normalize_policy_statements() → analyze_policy_permissions() →
AWSNHIInput 조립.

신원·Access Key 조회 실패는 감춰지지 않고 그대로 전파되어야 한다. Policy
조회 실패는 다르다 — 신원은 이미 확정됐으므로 전체를 중단시키지 않고
`AWSNHIInput.policy_fetch_errors` 에 사유만 남긴 채 계속 진행해야 한다.
Deny/Resource/Condition 에 따른 실제 권한 상쇄 계산은 아직 없다.
"""

from __future__ import annotations

from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

from agents.aws_inventory_service import (
    _derive_nhi_name,
    _select_current_access_key,
    build_aws_nhi_input_from_connector,
    collect_policy_permissions,
)
from connectors.aws_connector import AWSConnector
from connectors.base_connector import (
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)
from core.nhi_models import NHIType


def _dummy_session(access_key_id: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key="dummy-secret",
        region_name="us-east-1",
    )


@pytest.fixture(scope="module")
def sts_client():
    return _dummy_session("AKIAFIXTURESESSION00").client("sts")


@pytest.fixture(scope="module")
def iam_client():
    return _dummy_session("AKIAFIXTURESESSION00").client("iam")


def _connector(sts_client, iam_client, *, current_access_key_id: str) -> AWSConnector:
    return AWSConnector(
        session=_dummy_session(current_access_key_id),
        sts_client=sts_client,
        iam_client=iam_client,
    )


def _stub_no_attached_policies(iam_stub, *, user_name="ci-deploy-user"):
    iam_stub.add_response(
        "list_attached_user_policies",
        {"AttachedPolicies": [], "IsTruncated": False},
        {"UserName": user_name, "MaxItems": 100},
    )


def _encoded_document(document) -> str:
    import json
    import urllib.parse

    return urllib.parse.quote(json.dumps(document))


# ---------------------------------------------------------------------------
# 정상 흐름 — end-to-end (Policy 없음)
# ---------------------------------------------------------------------------
def test_happy_path_assembles_aws_nhi_input(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")
    create_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    last_used_date = datetime(2024, 6, 1, tzinfo=timezone.utc)

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {
                "Account": "123456789012",
                "UserId": "AIDAEXAMPLE123456789",
                "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user",
            },
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": create_date,
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {
                "UserName": "ci-deploy-user",
                "AccessKeyLastUsed": {
                    "LastUsedDate": last_used_date,
                    "ServiceName": "s3",
                    "Region": "us-east-1",
                },
            },
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        _stub_no_attached_policies(iam_stub)

        nhi = build_aws_nhi_input_from_connector(connector)

    assert nhi.nhi_id == "aws-123456789012-AKIACURRENTKEY00000"
    assert nhi.nhi_name == "ci-deploy-user"
    assert nhi.nhi_type is NHIType.CLOUD_SERVICE_ACCOUNT
    assert nhi.owner is None
    assert nhi.active is True
    assert nhi.access_key_id == "AKIACURRENTKEY00000"
    assert nhi.created_at == create_date
    assert nhi.last_used_at == last_used_date
    assert nhi.raw_scopes == []
    assert nhi.policy_fetch_errors == []


def test_inactive_current_key_is_reflected_as_inactive(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Inactive",
                        "CreateDate": datetime(2022, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        _stub_no_attached_policies(iam_stub)

        nhi = build_aws_nhi_input_from_connector(connector)

    assert nhi.active is False
    assert nhi.last_used_at is None  # 한 번도 안 쓰인 키 — 오류 아님


def test_selects_matching_key_not_first_or_most_active(sts_client, iam_client):
    """IAM User 는 키를 최대 2개 가질 수 있다 — 목록 순서나 Status 가 아니라
    실제로 지금 쓰이는 access_key_id 로 정확히 골라야 한다."""
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    # 목록 첫 번째이자 Active 지만, 지금 쓰이는 키가 아니다.
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIAOLDKEY0000000000",
                        "Status": "Active",
                        "CreateDate": datetime(2020, 1, 1, tzinfo=timezone.utc),
                    },
                    # 두 번째이고 Inactive 지만, 실제로 지금 인증에 쓰이는 키다.
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Inactive",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    },
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        _stub_no_attached_policies(iam_stub)

        nhi = build_aws_nhi_input_from_connector(connector)

    assert nhi.access_key_id == "AKIACURRENTKEY00000"
    assert nhi.active is False  # Inactive 인 "현재 키" 의 상태를 정확히 반영


# ---------------------------------------------------------------------------
# 정상 흐름 — Policy 연결됨
# ---------------------------------------------------------------------------
def test_happy_path_with_single_attached_policy_populates_raw_scopes(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        iam_stub.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {
                        "PolicyName": "AmazonS3ReadOnlyAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                    }
                ],
                "IsTruncated": False,
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        iam_stub.add_response(
            "get_policy",
            {
                "Policy": {
                    "PolicyName": "AmazonS3ReadOnlyAccess",
                    "Arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                    "DefaultVersionId": "v1",
                }
            },
            {"PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
        )
        iam_stub.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": _encoded_document(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:ListBucket"],
                                    "Resource": "*",
                                }
                            ],
                        }
                    ),
                    "VersionId": "v1",
                }
            },
            {"PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess", "VersionId": "v1"},
        )

        nhi = build_aws_nhi_input_from_connector(connector)

    assert set(nhi.raw_scopes) == {"s3:GetObject", "s3:ListBucket"}
    assert nhi.policy_fetch_errors == []


def test_multiple_policies_are_aggregated_into_raw_scopes(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        iam_stub.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {"PolicyName": "PolicyA", "PolicyArn": "arn:aws:iam::aws:policy/PolicyA"},
                    {"PolicyName": "PolicyB", "PolicyArn": "arn:aws:iam::aws:policy/PolicyB"},
                ],
                "IsTruncated": False,
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        iam_stub.add_response(
            "get_policy",
            {"Policy": {"PolicyName": "PolicyA", "Arn": "arn:aws:iam::aws:policy/PolicyA", "DefaultVersionId": "v1"}},
            {"PolicyArn": "arn:aws:iam::aws:policy/PolicyA"},
        )
        iam_stub.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": _encoded_document(
                        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
                    ),
                    "VersionId": "v1",
                }
            },
            {"PolicyArn": "arn:aws:iam::aws:policy/PolicyA", "VersionId": "v1"},
        )
        iam_stub.add_response(
            "get_policy",
            {"Policy": {"PolicyName": "PolicyB", "Arn": "arn:aws:iam::aws:policy/PolicyB", "DefaultVersionId": "v1"}},
            {"PolicyArn": "arn:aws:iam::aws:policy/PolicyB"},
        )
        iam_stub.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": _encoded_document(
                        {"Statement": [{"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"}]}
                    ),
                    "VersionId": "v1",
                }
            },
            {"PolicyArn": "arn:aws:iam::aws:policy/PolicyB", "VersionId": "v1"},
        )

        nhi = build_aws_nhi_input_from_connector(connector)

    assert set(nhi.raw_scopes) == {"s3:GetObject", "iam:CreateUser"}
    assert nhi.policy_fetch_errors == []


def test_deny_only_policy_does_not_add_to_raw_scopes(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        iam_stub.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {"PolicyName": "DenyPolicy", "PolicyArn": "arn:aws:iam::aws:policy/DenyPolicy"}
                ],
                "IsTruncated": False,
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        iam_stub.add_response(
            "get_policy",
            {"Policy": {"PolicyName": "DenyPolicy", "Arn": "arn:aws:iam::aws:policy/DenyPolicy", "DefaultVersionId": "v1"}},
            {"PolicyArn": "arn:aws:iam::aws:policy/DenyPolicy"},
        )
        iam_stub.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": _encoded_document(
                        {"Statement": [{"Effect": "Deny", "Action": "iam:DeleteUser", "Resource": "*"}]}
                    ),
                    "VersionId": "v1",
                }
            },
            {"PolicyArn": "arn:aws:iam::aws:policy/DenyPolicy", "VersionId": "v1"},
        )

        nhi = build_aws_nhi_input_from_connector(connector)

    assert nhi.raw_scopes == []
    assert nhi.policy_fetch_errors == []


# ---------------------------------------------------------------------------
# Policy 조회 실패 — 숨기지 않되 전체를 막지도 않는다
# ---------------------------------------------------------------------------
def test_list_attached_user_policies_failure_is_recorded_not_raised(sts_client, iam_client):
    """신원은 이미 확정됐으므로 Policy 목록 조회 실패로 전체가 죽으면 안 된다."""
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        iam_stub.add_client_error(
            "list_attached_user_policies",
            service_error_code="AccessDenied",
            service_message="denied",
        )

        nhi = build_aws_nhi_input_from_connector(connector)  # 예외 없이 완료돼야 한다

    assert nhi.raw_scopes == []
    assert len(nhi.policy_fetch_errors) == 1
    assert "ListAttachedUserPolicies" in nhi.policy_fetch_errors[0]


def test_get_policy_document_failure_for_one_policy_does_not_block_others(
    sts_client, iam_client
):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {"UserName": "ci-deploy-user", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        iam_stub.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {"PolicyName": "BrokenPolicy", "PolicyArn": "arn:aws:iam::aws:policy/BrokenPolicy"},
                    {"PolicyName": "GoodPolicy", "PolicyArn": "arn:aws:iam::aws:policy/GoodPolicy"},
                ],
                "IsTruncated": False,
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        iam_stub.add_client_error(
            "get_policy",
            service_error_code="AccessDenied",
            service_message="denied",
        )
        iam_stub.add_response(
            "get_policy",
            {"Policy": {"PolicyName": "GoodPolicy", "Arn": "arn:aws:iam::aws:policy/GoodPolicy", "DefaultVersionId": "v1"}},
            {"PolicyArn": "arn:aws:iam::aws:policy/GoodPolicy"},
        )
        iam_stub.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": _encoded_document(
                        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
                    ),
                    "VersionId": "v1",
                }
            },
            {"PolicyArn": "arn:aws:iam::aws:policy/GoodPolicy", "VersionId": "v1"},
        )

        nhi = build_aws_nhi_input_from_connector(connector)

    assert nhi.raw_scopes == ["s3:GetObject"]  # GoodPolicy 는 정상 반영됨
    assert len(nhi.policy_fetch_errors) == 1
    assert "BrokenPolicy" in nhi.policy_fetch_errors[0]


# ---------------------------------------------------------------------------
# 조회 실패 전파 — 신원/Access Key 는 여전히 감춰지지 않는다
# ---------------------------------------------------------------------------
def test_get_caller_identity_failure_propagates_unmodified(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub:
        sts_stub.add_client_error(
            "get_caller_identity",
            service_error_code="InvalidClientTokenId",
            service_message="invalid",
        )
        with pytest.raises(AuthenticationError):
            build_aws_nhi_input_from_connector(connector)


def test_list_access_keys_failure_propagates_unmodified(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_client_error(
            "list_access_keys", service_error_code="AccessDenied", service_message="denied"
        )
        with pytest.raises(PermissionDeniedError):
            build_aws_nhi_input_from_connector(connector)


def test_get_access_key_last_used_failure_propagates_unmodified(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        iam_stub.add_client_error(
            "get_access_key_last_used",
            service_error_code="AccessDenied",
            service_message="denied",
        )
        with pytest.raises(PermissionDeniedError):
            build_aws_nhi_input_from_connector(connector)


def test_no_access_keys_raises_not_found_instead_of_empty_result(sts_client, iam_client):
    """빈 값으로 숨기지 않는다 — 현재 키를 찾지 못하면 예외로 드러난다."""
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response("list_access_keys", {"AccessKeyMetadata": []}, {})
        with pytest.raises(NotFoundError):
            build_aws_nhi_input_from_connector(connector)


def test_current_key_not_in_list_raises_not_found(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user"},
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIASOMEOTHERKEY0000",
                        "Status": "Active",
                        "CreateDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                    }
                ]
            },
            {},
        )
        with pytest.raises(NotFoundError):
            build_aws_nhi_input_from_connector(connector)


# ---------------------------------------------------------------------------
# collect_policy_permissions() — 직접 단위 테스트
# ---------------------------------------------------------------------------
def test_collect_policy_permissions_returns_empty_when_no_attached_policies(
    sts_client, iam_client
):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")
    with Stubber(iam_client) as iam_stub:
        _stub_no_attached_policies(iam_stub, user_name="ci-deploy-user")
        analysis, allowed_actions, errors = collect_policy_permissions(
            connector, "ci-deploy-user"
        )

    assert allowed_actions == []
    assert errors == []
    assert analysis.allow_statement_count == 0


def test_collect_policy_permissions_skips_policy_without_arn(sts_client, iam_client):
    connector = _connector(sts_client, iam_client, current_access_key_id="AKIACURRENTKEY00000")
    with Stubber(iam_client) as iam_stub:
        iam_stub.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [{"PolicyName": "NoArnPolicy"}],
                "IsTruncated": False,
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        analysis, allowed_actions, errors = collect_policy_permissions(
            connector, "ci-deploy-user"
        )

    assert allowed_actions == []
    assert len(errors) == 1
    assert "NoArnPolicy" in errors[0]


# ---------------------------------------------------------------------------
# 내부 헬퍼 — _select_current_access_key()
# ---------------------------------------------------------------------------
def test_select_current_access_key_matches_by_id():
    keys = [
        {"access_key_id": "AKIAOLD00000000000A", "status": "Active"},
        {"access_key_id": "AKIACURRENT000000AB", "status": "Inactive"},
    ]
    selected = _select_current_access_key(keys, "AKIACURRENT000000AB")
    assert selected["access_key_id"] == "AKIACURRENT000000AB"


def test_select_current_access_key_raises_when_current_id_is_none():
    with pytest.raises(NotFoundError):
        _select_current_access_key([{"access_key_id": "AKIAX"}], None)


def test_select_current_access_key_raises_when_no_match():
    with pytest.raises(NotFoundError):
        _select_current_access_key([{"access_key_id": "AKIAX"}], "AKIAY")


def test_select_current_access_key_raises_on_empty_list():
    with pytest.raises(NotFoundError):
        _select_current_access_key([], "AKIAX")


# ---------------------------------------------------------------------------
# 내부 헬퍼 — _derive_nhi_name()
# ---------------------------------------------------------------------------
def test_derive_nhi_name_parses_user_arn():
    identity = {"arn": "arn:aws:iam::123456789012:user/ci-deploy-user"}
    assert _derive_nhi_name(identity) == "ci-deploy-user"


def test_derive_nhi_name_falls_back_to_user_id_when_arn_missing():
    identity = {"user_id": "AIDAEXAMPLE123456789"}
    assert _derive_nhi_name(identity) == "AIDAEXAMPLE123456789"


def test_derive_nhi_name_falls_back_when_both_missing():
    assert _derive_nhi_name({}) == "unknown-user"
