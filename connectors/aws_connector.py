"""AWS STS/IAM Connector.

담당 기능 (현재 단계)
  * 호출자 신원 확인 (`sts:GetCallerIdentity`)
  * IAM User Access Key 목록 조회 (`iam:ListAccessKeys`)
  * Access Key 마지막 사용 정보 조회 (`iam:GetAccessKeyLastUsed`)
  * 현재 인증에 쓰이는 Access Key ID 조회 (`current_access_key_id`, API 호출 없음 —
    boto3 세션의 자격 증명에서 바로 읽는다)
  * IAM User 에 직접 연결된 Managed Policy 목록 조회 (`iam:ListAttachedUserPolicies`)
  * Managed Policy 문서(JSON) 조회 (`iam:GetPolicy` → `iam:GetPolicyVersion`)

권한 변환(공통 Read/Write/Delete/Admin 매핑, Statement/Action/Resource 해석)은
다음 단계에서 추가한다 — 지금은 Policy 문서를 원문 구조 그대로 돌려줄 뿐이다.
Inline Policy·Group 을 통해 상속된 Policy 는 아직 다루지 않는다.

AWS 는 매 요청을 SigV4 로 서명해야 해서 다른 Connector 들처럼
`BaseConnector`(Bearer 토큰 + httpx)를 재사용할 수 없다. `boto3` 가 서명·
재시도를 이미 정확하게 처리하므로, 이 Connector 는 `BaseConnector` 를
상속하지 않고 boto3 클라이언트(`sts`/`iam`)를 감싸기만 한다. 자격 증명
자체는 이 코드가 저장하지 않고 boto3 의 표준 자격 증명 체인(환경변수 ·
`~/.aws/credentials` 프로필 · IAM 역할)에 위임한다.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from connectors.base_connector import (
    AuthenticationError,
    ConnectorError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

#: 자격 증명 자체가 유효하지 않음을 뜻하는 AWS 오류 코드 (401 상당).
_AUTH_ERROR_CODES = {
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "AuthFailure",
    "ExpiredToken",
    "ExpiredTokenException",
    "SignatureDoesNotMatch",
    "InvalidSignatureException",
    "MissingAuthenticationToken",
    "MissingAuthenticationTokenException",
}

#: 인증은 됐으나 권한이 부족함을 뜻하는 AWS 오류 코드 (403 상당).
_PERMISSION_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedAccess",
}

#: Rate Limit 을 뜻하는 AWS 오류 코드 (429 상당).
_THROTTLE_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
}

#: 대상 리소스가 없음을 뜻하는 AWS 오류 코드 (404 상당).
_NOT_FOUND_ERROR_CODES = {
    "NoSuchEntity",
    "NoSuchEntityException",
}


class AWSConnector:
    """AWS STS/IAM 조회 전용 Connector (boto3 기반, `BaseConnector` 미상속).

    현재는 조회 메서드 5개만 제공한다: `get_caller_identity()`,
    `list_access_keys()`, `get_access_key_last_used()`,
    `list_attached_user_policies()`, `get_policy_document()`. 전부 실패 시
    swallow 하지 않고 매핑된 예외를 그대로 던진다 — "성공 + 빈 결과" 와
    "조회 실패" 를 구분하는 책임은 이 Connector 를 감싸는 상위 조립
    계층의 몫이다.
    """

    provider = "aws"

    def __init__(
        self,
        *,
        profile_name: Optional[str] = None,
        region_name: Optional[str] = None,
        session: Optional[boto3.Session] = None,
        sts_client: Optional[Any] = None,
        iam_client: Optional[Any] = None,
    ) -> None:
        """세션·클라이언트를 직접 주입할 수 있게 해 테스트에서 실제 AWS 호출
        없이 `botocore.stub.Stubber` 로 대체할 수 있게 한다."""
        self._session = session or boto3.Session(
            profile_name=profile_name, region_name=region_name
        )
        self._sts = sts_client if sts_client is not None else self._session.client("sts")
        self._iam = iam_client if iam_client is not None else self._session.client("iam")

    # ------------------------------------------------------------------
    # 현재 자격 증명
    # ------------------------------------------------------------------
    @property
    def current_access_key_id(self) -> Optional[str]:
        """지금 이 Connector 가 인증에 실제로 쓰고 있는 Access Key ID.

        `get_caller_identity()` 는 신원(계정·ARN)만 알려줄 뿐 어떤 Access
        Key 로 인증했는지는 알려주지 않는다 — `list_access_keys()` 결과 중
        "지금 쓰이고 있는 키"를 골라내려면 이 값이 필요하다. 자격 증명을
        찾을 수 없으면 `None` 을 반환한다(호출만으로 예외를 던지지 않는다 —
        실제 사용 여부 확인은 `get_caller_identity()` 가 담당한다).
        """
        credentials = self._session.get_credentials()
        if credentials is None:
            return None
        # 일부 자격 증명 provider(예: 역할 위임)는 조회 시점에 갱신될 수
        # 있으므로 고정된 값을 얻기 위해 frozen 형태로 변환한다.
        frozen = credentials.get_frozen_credentials()
        return frozen.access_key

    # ------------------------------------------------------------------
    # 신원 확인
    # ------------------------------------------------------------------
    def get_caller_identity(self) -> Dict[str, Any]:
        """`sts:GetCallerIdentity` — 이 자격 증명이 누구인지 확인한다.

        별도 IAM 권한이 필요 없는 유일한 호출이라(모든 유효한 자격 증명에
        허용됨), 자격 증명 자체가 유효한지 확인하는 용도로 가장 먼저 쓰인다.
        """
        try:
            response = self._sts.get_caller_identity()
        except NoCredentialsError as exc:
            raise AuthenticationError(
                "AWS 자격 증명이 설정되지 않았습니다", status_code=401
            ) from exc
        except ClientError as exc:
            raise self._map_client_error(exc, action="sts:GetCallerIdentity") from exc
        except BotoCoreError as exc:
            raise ConnectorError(
                f"AWS STS 요청 실패 (sts:GetCallerIdentity): {exc}"
            ) from exc

        return {
            "account": response.get("Account"),
            "user_id": response.get("UserId"),
            "arn": response.get("Arn"),
        }

    # ------------------------------------------------------------------
    # Access Key
    # ------------------------------------------------------------------
    def list_access_keys(self, user_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """`iam:ListAccessKeys` — Access Key 목록을 조회한다.

        `user_name` 을 생략하면 이 자격 증명 자신의 Access Key 목록을
        조회한다. 자기 자신의 키 조회조차 별도 IAM 권한이 필요할 수 있고,
        없으면 `PermissionDeniedError` 가 그대로 올라온다 — 여기서 감추지
        않는다.
        """
        params = {"UserName": user_name} if user_name else {}
        try:
            response = self._iam.list_access_keys(**params)
        except NoCredentialsError as exc:
            raise AuthenticationError(
                "AWS 자격 증명이 설정되지 않았습니다", status_code=401
            ) from exc
        except ClientError as exc:
            raise self._map_client_error(exc, action="iam:ListAccessKeys") from exc
        except BotoCoreError as exc:
            raise ConnectorError(
                f"AWS IAM 요청 실패 (iam:ListAccessKeys): {exc}"
            ) from exc

        return [
            {
                "access_key_id": item.get("AccessKeyId"),
                "status": item.get("Status"),
                "create_date": self._iso(item.get("CreateDate")),
                "user_name": item.get("UserName"),
            }
            for item in response.get("AccessKeyMetadata", [])
        ]

    def get_access_key_last_used(self, access_key_id: str) -> Dict[str, Any]:
        """`iam:GetAccessKeyLastUsed` — 특정 Access Key 의 마지막 사용 정보를 조회한다.

        한 번도 사용되지 않은 키는 AWS 가 `LastUsedDate` 없이 응답한다 —
        이는 오류가 아니라 정상 상태이므로 `last_used_at` 이 `None` 인
        결과를 그대로 반환한다.
        """
        if not access_key_id or not access_key_id.strip():
            raise ValueError("access_key_id는 비어 있을 수 없습니다")

        try:
            response = self._iam.get_access_key_last_used(AccessKeyId=access_key_id)
        except NoCredentialsError as exc:
            raise AuthenticationError(
                "AWS 자격 증명이 설정되지 않았습니다", status_code=401
            ) from exc
        except ClientError as exc:
            raise self._map_client_error(exc, action="iam:GetAccessKeyLastUsed") from exc
        except BotoCoreError as exc:
            raise ConnectorError(
                f"AWS IAM 요청 실패 (iam:GetAccessKeyLastUsed): {exc}"
            ) from exc

        last_used = response.get("AccessKeyLastUsed") or {}
        return {
            "user_name": response.get("UserName"),
            "last_used_at": self._iso(last_used.get("LastUsedDate")),
            "service_name": last_used.get("ServiceName"),
            "region": last_used.get("Region"),
        }

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------
    def list_attached_user_policies(
        self, user_name: str, *, max_items: int = 100, max_pages: int = 20
    ) -> List[Dict[str, Any]]:
        """`iam:ListAttachedUserPolicies` — User 에 직접 연결된 Managed Policy 목록.

        `ListAccessKeys`/`GetAccessKeyLastUsed` 와 달리 이 API 는 `UserName`
        을 생략해도 호출자 자신으로 대체되지 않는다(AWS IAM API 자체의 제약 —
        self-service 대상 API 목록에 없음) — 그래서 `access_key_id` 와 달리
        기본값 없이 필수 인자로 받는다.

        Inline Policy·Group 을 통해 상속된 Policy 는 포함하지 않는다 — 이
        User 에 직접(Attached) 연결된 Managed Policy 만 대상이다. Policy
        문서(JSON) 조회·권한 변환은 다음 단계에서 추가한다 — 여기서는
        `PolicyName`/`PolicyArn` 만 반환한다.
        """
        if not user_name or not user_name.strip():
            raise ValueError("user_name은 비어 있을 수 없습니다")

        policies: List[Dict[str, Any]] = []
        marker: Optional[str] = None

        for _ in range(max_pages):
            params: Dict[str, Any] = {"UserName": user_name, "MaxItems": max_items}
            if marker:
                params["Marker"] = marker

            try:
                response = self._iam.list_attached_user_policies(**params)
            except NoCredentialsError as exc:
                raise AuthenticationError(
                    "AWS 자격 증명이 설정되지 않았습니다", status_code=401
                ) from exc
            except ClientError as exc:
                raise self._map_client_error(
                    exc, action="iam:ListAttachedUserPolicies"
                ) from exc
            except BotoCoreError as exc:
                raise ConnectorError(
                    f"AWS IAM 요청 실패 (iam:ListAttachedUserPolicies): {exc}"
                ) from exc

            policies.extend(
                {
                    "policy_name": item.get("PolicyName"),
                    "policy_arn": item.get("PolicyArn"),
                }
                for item in response.get("AttachedPolicies", [])
            )

            if not response.get("IsTruncated"):
                break
            marker = response.get("Marker")
            if not marker:
                break

        return policies

    def get_policy_document(self, policy_arn: str) -> Dict[str, Any]:
        """Managed Policy 문서(JSON)를 조회한다.

        흐름: `iam:GetPolicy` 로 `DefaultVersionId` 확인 → `iam:GetPolicyVersion`
        으로 그 버전의 `Document` 조회. IAM 이 돌려주는 `Document` 는 RFC 3986
        URL-인코딩된 JSON 문자열이라 이 메서드가 인코딩만 풀어 dict 로
        반환한다 — `Statement`/`Action`/`Resource` 의 의미(Read/Write/Delete/
        Admin 변환)는 해석하지 않는다. 그건 다음 단계의 몫이다.
        """
        if not policy_arn or not policy_arn.strip():
            raise ValueError("policy_arn은 비어 있을 수 없습니다")

        try:
            policy_response = self._iam.get_policy(PolicyArn=policy_arn)
        except NoCredentialsError as exc:
            raise AuthenticationError(
                "AWS 자격 증명이 설정되지 않았습니다", status_code=401
            ) from exc
        except ClientError as exc:
            raise self._map_client_error(exc, action="iam:GetPolicy") from exc
        except BotoCoreError as exc:
            raise ConnectorError(f"AWS IAM 요청 실패 (iam:GetPolicy): {exc}") from exc

        default_version_id = (policy_response.get("Policy") or {}).get("DefaultVersionId")
        if not default_version_id:
            raise ConnectorError(
                f"AWS 정책 응답에 DefaultVersionId 가 없습니다 (iam:GetPolicy, {policy_arn})",
                status_code=502,
            )

        try:
            version_response = self._iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=default_version_id
            )
        except NoCredentialsError as exc:
            raise AuthenticationError(
                "AWS 자격 증명이 설정되지 않았습니다", status_code=401
            ) from exc
        except ClientError as exc:
            raise self._map_client_error(exc, action="iam:GetPolicyVersion") from exc
        except BotoCoreError as exc:
            raise ConnectorError(
                f"AWS IAM 요청 실패 (iam:GetPolicyVersion): {exc}"
            ) from exc

        raw_document = (version_response.get("PolicyVersion") or {}).get("Document")
        return self._parse_policy_document(raw_document, policy_arn=policy_arn)

    # ------------------------------------------------------------------
    # 내부
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_policy_document(raw_document: Any, *, policy_arn: str) -> Dict[str, Any]:
        """IAM 의 URL-인코딩된 Policy Document 문자열을 dict 로 되돌린다.

        원문 구조(`Version`/`Statement`/...)를 그대로 보존한다 — 값을
        해석·가공하지 않는다. 실제 AWS 응답은 URL-인코딩된 JSON 문자열이지만,
        이미 dict 로 파싱돼 들어오는 경우도 방어적으로 그대로 받아들인다.
        """
        if isinstance(raw_document, dict):
            return raw_document
        if not isinstance(raw_document, str) or not raw_document.strip():
            raise ConnectorError(
                f"AWS Policy Document 가 비어 있습니다 (iam:GetPolicyVersion, {policy_arn})",
                status_code=502,
            )
        try:
            decoded = urllib.parse.unquote(raw_document)
            return json.loads(decoded)
        except (TypeError, ValueError) as exc:
            raise ConnectorError(
                f"AWS Policy Document 파싱에 실패했습니다 (iam:GetPolicyVersion, {policy_arn})",
                status_code=502,
            ) from exc

    @staticmethod
    def _iso(value: Any) -> Optional[str]:
        """boto3 가 돌려주는 `datetime` 을 코드베이스 공통 ISO8601 문자열로 맞춘다."""
        if value is None:
            return None
        isoformat = getattr(value, "isoformat", None)
        return isoformat() if callable(isoformat) else str(value)

    @staticmethod
    def _map_client_error(exc: ClientError, *, action: str) -> ConnectorError:
        """botocore `ClientError` 를 기존 Connector 들과 동일한 예외 계층으로 변환한다.

        AWS 오류 메시지에는 계정 ID·ARN 등 식별 정보는 담겨도 자격 증명
        원문(Secret Access Key)은 담기지 않는다 — 그래도 방어적으로 이
        메서드가 만드는 메시지는 AWS 가 준 `Code`/`Message` 만 사용한다.
        """
        error = getattr(exc, "response", {}).get("Error", {}) or {}
        code = error.get("Code", "Unknown")
        message = error.get("Message", str(exc))
        status_code = (getattr(exc, "response", {}).get("ResponseMetadata", {}) or {}).get(
            "HTTPStatusCode"
        )

        if code in _AUTH_ERROR_CODES:
            return AuthenticationError(
                f"AWS 인증 실패 ({action}): {code} — {message}", status_code=401
            )
        if code in _PERMISSION_ERROR_CODES:
            return PermissionDeniedError(
                f"AWS 권한 부족 ({action}): {code} — {message}", status_code=403
            )
        if code in _THROTTLE_ERROR_CODES:
            return RateLimitError(
                f"AWS Rate Limit 초과 ({action}): {code}", status_code=429
            )
        if code in _NOT_FOUND_ERROR_CODES:
            return NotFoundError(
                f"AWS 리소스를 찾을 수 없습니다 ({action}): {code} — {message}",
                status_code=404,
            )
        return ConnectorError(
            f"AWS API 오류 ({action}): {code} — {message}", status_code=status_code
        )
