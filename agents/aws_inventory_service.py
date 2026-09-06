"""AWS IAM User Access Key 결과를 NHI 인벤토리 입력으로 조립한다.

흐름:
    get_caller_identity() → list_access_keys() → 현재 사용 중인
    access_key_id 와 일치하는 키 선택 → get_access_key_last_used()
    → list_attached_user_policies() → (Policy 별) get_policy_document()
    → normalize_policy_statements() → analyze_policy_permissions()
    → AWSNHIInput 조립

여러 Managed Policy 의 Allow Action 은 하나로 합산한다 —
`analyze_policy_permissions()` 자체가 여러 Policy 에서 모은 Statement 를
한 번에 집계하도록 설계돼 있어, 별도 병합 로직 없이 전체 Statement 를
모아 한 번만 호출한다. `AWSNHIInput.raw_scopes` 에는 실제로 Allow 된
Action 문자열(중복 제거)을 담는다.

`AWSNHIInput.broad_access` 는 `analyze_policy_permissions()` 가 이미
계산한 값(Allow Statement 의 Resource 중 전체/서비스 전체급 wildcard
존재 여부)을 그대로 옮겨 담는다 — 여기서 다시 계산하지 않는다.

Deny/Resource/Condition 에 따른 실제 권한 상쇄 계산은 이번 단계에서 하지
않는다.

**조회 실패를 다루는 방식이 두 가지로 나뉜다**:
  * 신원·Access Key 조회(`get_caller_identity`/`list_access_keys`/
    `get_access_key_last_used`) 실패 — 이 NHI 를 특정할 수 없다는 뜻이라
    감추지 않고 예외를 그대로 위로 전파한다.
  * Policy 조회(`list_attached_user_policies`/`get_policy_document`) 실패 —
    신원은 이미 확정됐으므로 전체를 중단하지 않는다. 실패한 Policy 는
    건너뛰고 사유를 `AWSNHIInput.policy_fetch_errors` 에 남긴다("숨기지
    않되, 전체를 막지도 않는다").
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agents.aws_policy_normalizer import normalize_policy_statements
from agents.aws_policy_permission_analyzer import (
    AWSPolicyPermissionAnalysis,
    analyze_policy_permissions,
)
from agents.pipeline import NHIAnalysisPipeline
from connectors.aws_connector import AWSConnector
from connectors.base_connector import ConnectorError, NotFoundError
from core.aws_inventory_models import AWSNHIInput
from core.nhi_models import NHIType, NHIAnalysis


def build_aws_nhi_input_from_connector(connector: AWSConnector) -> AWSNHIInput:
    """AWS 자격 증명의 실제 신원·Access Key·Managed Policy 정보를 조회해
    `AWSNHIInput` 을 만든다."""
    identity = connector.get_caller_identity()
    access_keys = connector.list_access_keys()
    current_key = _select_current_access_key(access_keys, connector.current_access_key_id)

    access_key_id = current_key["access_key_id"]
    last_used = connector.get_access_key_last_used(access_key_id)

    account = identity.get("account") or "unknown-account"
    user_name = _derive_nhi_name(identity)

    analysis, allowed_actions, policy_fetch_errors = collect_policy_permissions(
        connector, user_name
    )

    return AWSNHIInput(
        nhi_id=f"aws-{account}-{access_key_id}",
        nhi_name=user_name,
        nhi_type=NHIType.CLOUD_SERVICE_ACCOUNT,
        owner=None,
        active=current_key.get("status") == "Active",
        access_key_id=access_key_id,
        created_at=current_key.get("create_date"),
        last_used_at=last_used.get("last_used_at"),
        raw_scopes=allowed_actions,
        policy_fetch_errors=policy_fetch_errors,
        broad_access=analysis.broad_access,
    )


def analyze_aws_nhi_from_connector(
    connector: AWSConnector,
    *,
    pipeline: Optional[NHIAnalysisPipeline] = None,
) -> Tuple[NHIAnalysis, AWSNHIInput]:
    """AWS IAM Access Key 의 실제 신원·Policy 정보를 조회해 기존 파이프라인으로 분석한다.

    구조는 `analyze_github_nhi_from_connector()`/`analyze_slack_nhi_from_connector()`
    와 동일하다 — `build_aws_nhi_input_from_connector()` 로 조립한 뒤 기존
    `NHIAnalysisPipeline.analyze_aws_nhi()` 를 그대로 재사용한다(Risk/Policy/
    Event/Scenario 로직은 GitHub/Slack 과 완전히 공유). 신원·Access Key 조회
    실패는 `build_aws_nhi_input_from_connector()` 가 그대로 전파하는 예외를
    감추지 않고 위로 올린다.

    GitHub/Slack 의 동명 함수와 달리 `NHIAnalysis` 하나만이 아니라 조립에
    쓰인 `AWSNHIInput` 도 함께 반환한다 — 호출부(`api/app.py`)가
    `access_key_id`/`broad_access`/`policy_fetch_errors` 처럼 공통
    `NHIAnalysis`/`NHIProfile` 에는 실리지 않는 AWS 고유 필드를 `provider_detail`
    로 저장하려면 원본 입력이 필요하기 때문이다.
    """
    nhi = build_aws_nhi_input_from_connector(connector)
    analysis = (pipeline or NHIAnalysisPipeline()).analyze_aws_nhi(nhi)
    return analysis, nhi


# ---------------------------------------------------------------------------
# Policy 수집·정규화·집계
# ---------------------------------------------------------------------------
def collect_policy_permissions(
    connector: AWSConnector, user_name: str
) -> Tuple[AWSPolicyPermissionAnalysis, List[str], List[str]]:
    """User 에 직접 연결된 모든 Managed Policy 를 조회해 하나로 합산한다.

    반환값: `(합산된 권한 집계, Allow 된 Action 문자열 목록(중복 제거),
    실패 사유 목록)`. 개별 Policy 문서 조회가 실패해도 전체를 중단하지
    않고 건너뛴 뒤 사유를 기록한다 — 숨기지 않는다. `ListAttachedUserPolicies`
    자체가 실패하면 그 사유 하나만 담고 나머지는 빈 결과로 반환한다.

    여러 Policy 의 Statement 를 전부 모아 `analyze_policy_permissions()`
    를 단 한 번만 호출한다 — 이 함수 자체가 여러 Statement 를 합산하도록
    만들어져 있어 별도의 병합 로직이 필요 없다.
    """
    errors: List[str] = []

    try:
        attached_policies = connector.list_attached_user_policies(user_name)
    except ConnectorError as exc:
        errors.append(f"ListAttachedUserPolicies 실패: {exc.message}")
        return AWSPolicyPermissionAnalysis(), [], errors

    all_statements: List[Dict[str, Any]] = []

    for policy in attached_policies:
        policy_arn = policy.get("policy_arn")
        policy_label = policy.get("policy_name") or policy_arn or "(알 수 없는 Policy)"

        if not policy_arn:
            errors.append(f"{policy_label}: PolicyArn 이 없어 건너뜀")
            continue

        try:
            document = connector.get_policy_document(policy_arn)
        except ConnectorError as exc:
            errors.append(f"{policy_label} 문서 조회 실패: {exc.message}")
            continue

        all_statements.extend(normalize_policy_statements(document))

    analysis = analyze_policy_permissions(all_statements)
    return analysis, list(analysis.allowed_actions), errors


# ---------------------------------------------------------------------------
# 내부
# ---------------------------------------------------------------------------
def _select_current_access_key(
    access_keys: List[Dict[str, Any]], current_access_key_id: Optional[str]
) -> Dict[str, Any]:
    """`list_access_keys()` 결과 중 지금 실제로 인증에 쓰이는 키를 고른다.

    IAM User 는 Access Key 를 최대 2개까지 가질 수 있어, "첫 번째 키"나
    "Active 인 키"를 임의로 고르면 실제로 쓰이는 키가 아닐 수 있다. 일치하는
    키가 없으면(현재 키를 확인 못 했거나 목록에 없으면) 조회 실패로 보고
    빈 값으로 넘어가지 않는다.
    """
    if not current_access_key_id:
        raise NotFoundError(
            "현재 사용 중인 Access Key ID를 확인할 수 없습니다", status_code=404
        )
    for key in access_keys:
        if key.get("access_key_id") == current_access_key_id:
            return key
    raise NotFoundError(
        f"현재 사용 중인 Access Key({current_access_key_id})가 "
        "ListAccessKeys 결과에 없습니다",
        status_code=404,
    )


def _derive_nhi_name(identity: Dict[str, Any]) -> str:
    """IAM User ARN(`arn:aws:iam::<account>:user/<name>`)에서 사용자 이름을 뽑는다.

    ARN 형식이 예상과 다르면(예: 값이 비어 있음) `user_id` 로 대체한다. 이
    이름은 `list_attached_user_policies()` 에 넘길 `UserName` 으로도 그대로
    쓰인다 — ARN 의 경로(Path) 접두어를 제외한 마지막 구간이 IAM 의
    `UserName` 과 정확히 같다.
    """
    arn = identity.get("arn") or ""
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    return str(identity.get("user_id") or "unknown-user")
