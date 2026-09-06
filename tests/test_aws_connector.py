"""AWSConnector — GetCallerIdentity / ListAccessKeys / GetAccessKeyLastUsed /
ListAttachedUserPolicies / GetPolicyDocument 검증.

권한 변환(Statement/Action/Resource 해석)은 아직 없으므로 다루지 않는다 —
Policy 문서를 원문 구조 그대로 돌려주는지만 확인한다. 실제 AWS 호출 없이
`botocore.stub.Stubber`(성공/ClientError/페이지네이션 케이스)와
`unittest.mock`(NoCredentialsError 케이스)으로 검증한다.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber

from connectors.aws_connector import AWSConnector
from connectors.base_connector import (
    AuthenticationError,
    ConnectorError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)


def _dummy_session() -> boto3.Session:
    """실제 자격 증명 체인을 건드리지 않는 더미 세션 — Stubber 가 HTTP 전송을
    가로채므로 이 값들이 진짜 AWS 로 나가지 않는다."""
    return boto3.Session(
        aws_access_key_id="AKIATESTTESTTESTTEST",
        aws_secret_access_key="test-secret-key-value",
        region_name="us-east-1",
    )


@pytest.fixture(scope="module")
def sts_client():
    # boto3.client() 생성 자체가 서비스 모델 로딩 때문에 느리다 — 테스트마다
    # 새로 만들지 않고 모듈 전체에서 하나만 재사용한다. Stubber 는 `with` 블록
    # 단위로 매번 활성화/해제되므로 클라이언트 재사용과 무관하게 격리된다.
    return _dummy_session().client("sts")


@pytest.fixture(scope="module")
def iam_client():
    return _dummy_session().client("iam")


# ---------------------------------------------------------------------------
# current_access_key_id
# ---------------------------------------------------------------------------
def test_current_access_key_id_reflects_session_credentials():
    session = boto3.Session(
        aws_access_key_id="AKIACURRENTTESTKEY01",
        aws_secret_access_key="dummy-secret",
        region_name="us-east-1",
    )
    connector = AWSConnector(session=session, sts_client=MagicMock(), iam_client=MagicMock())

    assert connector.current_access_key_id == "AKIACURRENTTESTKEY01"


def test_current_access_key_id_is_none_without_credentials():
    session = MagicMock()
    session.get_credentials.return_value = None
    connector = AWSConnector(session=session, sts_client=MagicMock(), iam_client=MagicMock())

    assert connector.current_access_key_id is None


def test_current_access_key_id_makes_no_api_call(sts_client, iam_client):
    """자격 증명 조회는 로컬 정보라 API 호출이 전혀 없어야 한다."""
    session = boto3.Session(
        aws_access_key_id="AKIANOAPICALLNEEDED0",
        aws_secret_access_key="dummy-secret",
        region_name="us-east-1",
    )
    connector = AWSConnector(session=session, sts_client=sts_client, iam_client=iam_client)

    with Stubber(sts_client), Stubber(iam_client):
        # 아무 응답도 등록하지 않았다 — 실제로 호출되면 StubAssertionError 로 실패한다.
        assert connector.current_access_key_id == "AKIANOAPICALLNEEDED0"


# ---------------------------------------------------------------------------
# get_caller_identity()
# ---------------------------------------------------------------------------
def test_get_caller_identity_success(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(sts_client) as stubber:
        stubber.add_response(
            "get_caller_identity",
            {
                "Account": "123456789012",
                "UserId": "AIDAEXAMPLE123456789",
                "Arn": "arn:aws:iam::123456789012:user/test-user",
            },
        )
        identity = connector.get_caller_identity()

    assert identity == {
        "account": "123456789012",
        "user_id": "AIDAEXAMPLE123456789",
        "arn": "arn:aws:iam::123456789012:user/test-user",
    }


def test_get_caller_identity_no_credentials_raises_authentication_error(iam_client):
    sts_client = MagicMock()
    sts_client.get_caller_identity.side_effect = NoCredentialsError()
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)

    with pytest.raises(AuthenticationError) as error:
        connector.get_caller_identity()
    assert error.value.status_code == 401


@pytest.mark.parametrize(
    "code, expected_exc, expected_status",
    [
        ("InvalidClientTokenId", AuthenticationError, 401),
        ("SignatureDoesNotMatch", AuthenticationError, 401),
        ("AccessDenied", PermissionDeniedError, 403),
        ("Throttling", RateLimitError, 429),
    ],
)
def test_get_caller_identity_maps_aws_error_codes(
    sts_client, iam_client, code, expected_exc, expected_status
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(sts_client) as stubber:
        stubber.add_client_error(
            "get_caller_identity", service_error_code=code, service_message="denied"
        )
        with pytest.raises(expected_exc) as error:
            connector.get_caller_identity()

    assert error.value.status_code == expected_status
    assert code in str(error.value)


def test_get_caller_identity_unknown_error_code_maps_to_generic_connector_error(
    sts_client, iam_client
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(sts_client) as stubber:
        stubber.add_client_error(
            "get_caller_identity",
            service_error_code="SomeUnmappedError",
            service_message="odd failure",
        )
        with pytest.raises(ConnectorError) as error:
            connector.get_caller_identity()

    assert not isinstance(error.value, (AuthenticationError, PermissionDeniedError, RateLimitError))
    assert "SomeUnmappedError" in str(error.value)


# ---------------------------------------------------------------------------
# list_access_keys()
# ---------------------------------------------------------------------------
def test_list_access_keys_success_for_self(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    create_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "test-user",
                        "AccessKeyId": "AKIAABCDEFGHIJKLMNOP",
                        "Status": "Active",
                        "CreateDate": create_date,
                    },
                    {
                        "UserName": "test-user",
                        "AccessKeyId": "AKIAZZZZZZZZZZZZZZZZ",
                        "Status": "Inactive",
                        "CreateDate": create_date,
                    },
                ]
            },
            {},
        )
        keys = connector.list_access_keys()

    assert keys == [
        {
            "access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "status": "Active",
            "create_date": create_date.isoformat(),
            "user_name": "test-user",
        },
        {
            "access_key_id": "AKIAZZZZZZZZZZZZZZZZ",
            "status": "Inactive",
            "create_date": create_date.isoformat(),
            "user_name": "test-user",
        },
    ]


def test_list_access_keys_passes_user_name_param(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "list_access_keys", {"AccessKeyMetadata": []}, {"UserName": "someone-else"}
        )
        keys = connector.list_access_keys(user_name="someone-else")

    assert keys == []


def test_list_access_keys_empty_result_is_not_an_error(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response("list_access_keys", {"AccessKeyMetadata": []}, {})
        assert connector.list_access_keys() == []


def test_list_access_keys_access_denied_raises_permission_denied_error(sts_client, iam_client):
    """자기 자신의 키 목록 조회도 별도 IAM 권한이 필요할 수 있다 — 흔한 실패 케이스."""
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "list_access_keys", service_error_code="AccessDenied", service_message="denied"
        )
        with pytest.raises(PermissionDeniedError) as error:
            connector.list_access_keys()

    assert error.value.status_code == 403


def test_list_access_keys_no_such_entity_raises_not_found_error(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "list_access_keys",
            service_error_code="NoSuchEntity",
            service_message="user does not exist",
        )
        with pytest.raises(NotFoundError):
            connector.list_access_keys(user_name="does-not-exist")


# ---------------------------------------------------------------------------
# get_access_key_last_used()
# ---------------------------------------------------------------------------
def test_get_access_key_last_used_success(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    last_used_date = datetime(2024, 6, 1, tzinfo=timezone.utc)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "get_access_key_last_used",
            {
                "UserName": "test-user",
                "AccessKeyLastUsed": {
                    "LastUsedDate": last_used_date,
                    "ServiceName": "s3",
                    "Region": "us-east-1",
                },
            },
            {"AccessKeyId": "AKIAABCDEFGHIJKLMNOP"},
        )
        result = connector.get_access_key_last_used("AKIAABCDEFGHIJKLMNOP")

    assert result == {
        "user_name": "test-user",
        "last_used_at": last_used_date.isoformat(),
        "service_name": "s3",
        "region": "us-east-1",
    }


def test_get_access_key_last_used_never_used_is_not_an_error(sts_client, iam_client):
    """한 번도 쓰이지 않은 키는 LastUsedDate 없이 응답한다 — 오류가 아니다."""
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "get_access_key_last_used",
            {
                "UserName": "test-user",
                "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"},
            },
            {"AccessKeyId": "AKIAABCDEFGHIJKLMNOP"},
        )
        result = connector.get_access_key_last_used("AKIAABCDEFGHIJKLMNOP")

    assert result["last_used_at"] is None
    assert result["service_name"] == "N/A"


def test_get_access_key_last_used_rejects_empty_access_key_id(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with pytest.raises(ValueError):
        connector.get_access_key_last_used("")


def test_get_access_key_last_used_access_denied_raises_permission_denied_error(
    sts_client, iam_client
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "get_access_key_last_used",
            service_error_code="AccessDenied",
            service_message="denied",
        )
        with pytest.raises(PermissionDeniedError):
            connector.get_access_key_last_used("AKIAABCDEFGHIJKLMNOP")


# ---------------------------------------------------------------------------
# 노출 방지 — 자격 증명 원문이 예외 메시지에 없는지
# ---------------------------------------------------------------------------
def test_client_error_messages_never_contain_secret_key_material(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(sts_client) as stubber:
        stubber.add_client_error(
            "get_caller_identity",
            service_error_code="SignatureDoesNotMatch",
            service_message="The request signature we calculated does not match",
        )
        with pytest.raises(AuthenticationError) as error:
            connector.get_caller_identity()

    assert "test-secret-key-value" not in str(error.value)


# ---------------------------------------------------------------------------
# list_attached_user_policies()
# ---------------------------------------------------------------------------
def test_list_attached_user_policies_success(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                    {
                        "PolicyName": "AmazonS3ReadOnlyAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                    },
                ],
                "IsTruncated": False,
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        policies = connector.list_attached_user_policies("ci-deploy-user")

    assert policies == [
        {
            "policy_name": "AdministratorAccess",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        {
            "policy_name": "AmazonS3ReadOnlyAccess",
            "policy_arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        },
    ]


def test_list_attached_user_policies_requires_user_name(sts_client, iam_client):
    """ListAccessKeys 와 달리 이 API 는 UserName 을 생략해도 호출자로
    대체되지 않는다 — 필수 인자로 강제한다."""
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with pytest.raises(ValueError):
        connector.list_attached_user_policies("")


def test_list_attached_user_policies_empty_result_is_not_an_error(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "list_attached_user_policies",
            {"AttachedPolicies": [], "IsTruncated": False},
            {"UserName": "no-policies-user", "MaxItems": 100},
        )
        assert connector.list_attached_user_policies("no-policies-user") == []


def test_list_attached_user_policies_follows_pagination(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    }
                ],
                "IsTruncated": True,
                "Marker": "marker-page-2",
            },
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )
        stubber.add_response(
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
            {"UserName": "ci-deploy-user", "MaxItems": 100, "Marker": "marker-page-2"},
        )
        policies = connector.list_attached_user_policies("ci-deploy-user")

    assert [p["policy_name"] for p in policies] == [
        "AdministratorAccess",
        "AmazonS3ReadOnlyAccess",
    ]


def test_list_attached_user_policies_stops_at_max_pages(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        for page in range(2):
            stubber.add_response(
                "list_attached_user_policies",
                {
                    "AttachedPolicies": [
                        {
                            "PolicyName": f"Policy{page}",
                            "PolicyArn": f"arn:aws:iam::aws:policy/Policy{page}",
                        }
                    ],
                    "IsTruncated": True,
                    "Marker": f"marker-{page + 1}",
                },
            )
        policies = connector.list_attached_user_policies("ci-deploy-user", max_pages=2)

    assert len(policies) == 2


def test_list_attached_user_policies_stops_when_truncated_but_no_marker(sts_client, iam_client):
    """IsTruncated=True 인데 Marker 가 없는 비정상 응답에서도 무한 루프에
    빠지지 않고 안전하게 종료해야 한다."""
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {"PolicyName": "SomePolicy", "PolicyArn": "arn:aws:iam::aws:policy/SomePolicy"}
                ],
                "IsTruncated": True,
            },
        )
        policies = connector.list_attached_user_policies("ci-deploy-user")

    assert len(policies) == 1


def test_list_attached_user_policies_access_denied_raises_permission_denied_error(
    sts_client, iam_client
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "list_attached_user_policies",
            service_error_code="AccessDenied",
            service_message="denied",
        )
        with pytest.raises(PermissionDeniedError) as error:
            connector.list_attached_user_policies("ci-deploy-user")

    assert error.value.status_code == 403


def test_list_attached_user_policies_no_such_entity_raises_not_found_error(
    sts_client, iam_client
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "list_attached_user_policies",
            service_error_code="NoSuchEntity",
            service_message="user does not exist",
        )
        with pytest.raises(NotFoundError):
            connector.list_attached_user_policies("does-not-exist")


def test_list_attached_user_policies_no_credentials_raises_authentication_error(iam_client):
    iam_client_mock = MagicMock()
    iam_client_mock.list_attached_user_policies.side_effect = NoCredentialsError()
    connector = AWSConnector(sts_client=MagicMock(), iam_client=iam_client_mock)

    with pytest.raises(AuthenticationError) as error:
        connector.list_attached_user_policies("ci-deploy-user")
    assert error.value.status_code == 401


# ---------------------------------------------------------------------------
# get_policy_document()
# ---------------------------------------------------------------------------
_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}
    ],
}


def _encoded_document(document=None) -> str:
    return urllib.parse.quote(json.dumps(document if document is not None else _POLICY_DOCUMENT))


def _stub_get_policy(stubber, *, default_version_id="v2", policy_arn=_POLICY_ARN):
    stubber.add_response(
        "get_policy",
        {
            "Policy": {
                "PolicyName": "AmazonS3ReadOnlyAccess",
                "Arn": policy_arn,
                "DefaultVersionId": default_version_id,
            }
        },
        {"PolicyArn": policy_arn},
    )


def test_get_policy_document_success_decodes_url_encoded_json(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        _stub_get_policy(stubber)
        stubber.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": _encoded_document(),
                    "VersionId": "v2",
                    "IsDefaultVersion": True,
                }
            },
            {"PolicyArn": _POLICY_ARN, "VersionId": "v2"},
        )
        document = connector.get_policy_document(_POLICY_ARN)

    assert document == _POLICY_DOCUMENT


def test_get_policy_document_returns_statement_structure_unmodified(sts_client, iam_client):
    """Statement/Action/Resource 의 의미를 해석하지 않고 원문 구조 그대로 반환한다."""
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        _stub_get_policy(stubber)
        stubber.add_response(
            "get_policy_version",
            {"PolicyVersion": {"Document": _encoded_document(), "VersionId": "v2"}},
            {"PolicyArn": _POLICY_ARN, "VersionId": "v2"},
        )
        document = connector.get_policy_document(_POLICY_ARN)

    statement = document["Statement"][0]
    assert statement["Action"] == ["s3:GetObject", "s3:ListBucket"]
    assert statement["Resource"] == "*"
    assert statement["Effect"] == "Allow"


def test_get_policy_document_uses_default_version_id(sts_client, iam_client):
    """DefaultVersionId 가 아닌 다른 버전이면 stubber 의 expected_params 불일치로
    실패한다 — GetPolicyVersion 이 정확히 그 버전을 요청하는지 확인."""
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        _stub_get_policy(stubber, default_version_id="v7")
        stubber.add_response(
            "get_policy_version",
            {"PolicyVersion": {"Document": _encoded_document(), "VersionId": "v7"}},
            {"PolicyArn": _POLICY_ARN, "VersionId": "v7"},
        )
        connector.get_policy_document(_POLICY_ARN)  # 파라미터 불일치 시 여기서 예외


def test_get_policy_document_rejects_empty_policy_arn(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with pytest.raises(ValueError):
        connector.get_policy_document("")


def test_get_policy_document_missing_default_version_id_raises_connector_error(
    sts_client, iam_client
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_response(
            "get_policy",
            {"Policy": {"PolicyName": "X", "Arn": _POLICY_ARN}},  # DefaultVersionId 없음
            {"PolicyArn": _POLICY_ARN},
        )
        with pytest.raises(ConnectorError) as error:
            connector.get_policy_document(_POLICY_ARN)

    assert error.value.status_code == 502
    assert not isinstance(
        error.value, (AuthenticationError, PermissionDeniedError, RateLimitError, NotFoundError)
    )


def test_get_policy_document_malformed_document_raises_connector_error(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        _stub_get_policy(stubber)
        stubber.add_response(
            "get_policy_version",
            {"PolicyVersion": {"Document": "not%20valid%20json", "VersionId": "v2"}},
            {"PolicyArn": _POLICY_ARN, "VersionId": "v2"},
        )
        with pytest.raises(ConnectorError) as error:
            connector.get_policy_document(_POLICY_ARN)

    assert error.value.status_code == 502


def test_get_policy_document_get_policy_access_denied_raises_permission_denied_error(
    sts_client, iam_client
):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "get_policy", service_error_code="AccessDenied", service_message="denied"
        )
        with pytest.raises(PermissionDeniedError):
            connector.get_policy_document(_POLICY_ARN)


def test_get_policy_document_get_policy_not_found_raises_not_found_error(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        stubber.add_client_error(
            "get_policy", service_error_code="NoSuchEntity", service_message="policy not found"
        )
        with pytest.raises(NotFoundError):
            connector.get_policy_document(_POLICY_ARN)


def test_get_policy_document_get_policy_version_failure_propagates(sts_client, iam_client):
    connector = AWSConnector(sts_client=sts_client, iam_client=iam_client)
    with Stubber(iam_client) as stubber:
        _stub_get_policy(stubber)
        stubber.add_client_error(
            "get_policy_version",
            service_error_code="AccessDenied",
            service_message="denied",
        )
        with pytest.raises(PermissionDeniedError):
            connector.get_policy_document(_POLICY_ARN)


def test_get_policy_document_no_credentials_raises_authentication_error(iam_client):
    iam_client_mock = MagicMock()
    iam_client_mock.get_policy.side_effect = NoCredentialsError()
    connector = AWSConnector(sts_client=MagicMock(), iam_client=iam_client_mock)

    with pytest.raises(AuthenticationError) as error:
        connector.get_policy_document(_POLICY_ARN)
    assert error.value.status_code == 401


# ---------------------------------------------------------------------------
# _parse_policy_document() — 방어적 dict 입력 처리
# ---------------------------------------------------------------------------
def test_parse_policy_document_accepts_already_parsed_dict():
    from connectors.aws_connector import AWSConnector as _AWSConnector

    result = _AWSConnector._parse_policy_document(_POLICY_DOCUMENT, policy_arn=_POLICY_ARN)
    assert result == _POLICY_DOCUMENT


def test_parse_policy_document_rejects_empty_string():
    from connectors.aws_connector import AWSConnector as _AWSConnector
    from connectors.base_connector import ConnectorError as _ConnectorError

    with pytest.raises(_ConnectorError):
        _AWSConnector._parse_policy_document("", policy_arn=_POLICY_ARN)
