"""AWS IAM User Access Key NHI 인벤토리 입력 모델.

`core/inventory_models.py`(GitHub), `core/slack_inventory_models.py`(Slack)
와 별개의 스키마다. AWS 는 GitHub 처럼 "입력유형 → 공통유형" 매핑 테이블이
필요 없다 — IAM User Access Key 는 사실상 전부 `NHIType.CLOUD_SERVICE_ACCOUNT`
하나로 충분하므로(`agents/discovery_agent.py` 의 코드 스캔 경로도 AWS 를 이미
이 타입으로 분류한다), Slack 처럼 `core.nhi_models.NHIType` 를 그대로 쓴다.

`raw_scopes` 는 이 User 에 직접 연결된 Managed Policy 들의 Allow Action을
모은 값이다(`agents/aws_inventory_service.py::build_aws_nhi_input_from_connector()`
참고). Policy 조회가 일부 실패해도 전체를 중단하지 않고 계속 진행하므로,
그 실패 사유는 숨기지 않고 `policy_fetch_errors` 에 별도로 보존한다.
Deny/Resource/Condition 에 따른 실제 권한 상쇄 계산은 아직 하지 않는다.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from core.nhi_models import Environment, NHIType


class AWSNHIInput(BaseModel):
    """분석 대상 AWS IAM User Access Key 1건."""

    nhi_id: str = Field(..., examples=["aws-123456789012-AKIAIOSFODNN7EXAMPLE"])
    nhi_name: str = Field(..., examples=["ci-deploy-user"])
    #: GitHub/Slack 과 달리 별도 입력유형 매핑이 필요 없다 — IAM User Access
    #: Key 는 `NHIType.CLOUD_SERVICE_ACCOUNT` 로 충분하다.
    nhi_type: NHIType
    #: 관리 책임자 또는 팀. 없을 수 있으므로 None 을 허용한다.
    owner: Optional[str] = None
    environment: Environment = Environment.UNKNOWN
    #: Credential 이 살아 있는가. IAM `ListAccessKeys` 의 Status(Active/Inactive)
    #: 를 그대로 반영한다 — GitHub PAT 의 하드코딩된 값과 달리 실제 조회 결과다.
    active: bool = True
    #: 이 NHI 를 식별하는 실제 Access Key ID (예: "AKIAIOSFODNN7EXAMPLE").
    access_key_id: str = Field(..., examples=["AKIAIOSFODNN7EXAMPLE"])
    #: Access Key 발급 시각 (`ListAccessKeys` 의 CreateDate).
    created_at: Optional[datetime] = None
    #: Access Key 마지막 사용 시각 (`GetAccessKeyLastUsed` 의 LastUsedDate).
    #: 한 번도 쓰이지 않았으면 None 이며, 이는 오류가 아니라 정상 상태다.
    last_used_at: Optional[datetime] = None
    #: 이 User 에 직접 연결된 Managed Policy 들에서 실제로 Allow 된 Action
    #: 문자열(중복 제거). Policy 조회가 전혀 안 됐거나 연결된 Policy가
    #: 없으면 빈 리스트다 — Scope 를 확인 못 한 것과 실제로 권한이 없는
    #: 것을 이 필드만으로는 구분할 수 없으므로, 조회 실패 여부는
    #: `policy_fetch_errors` 를 함께 봐야 한다.
    raw_scopes: List[str] = Field(default_factory=list)
    #: Policy 조회 중 실패한 항목의 사유. 비어 있으면 전부 성공했다는 뜻이다
    #: (연결된 Policy가 하나도 없는 것과는 다르다 — 그 경우도 빈 리스트지만
    #: 실패는 없었다는 뜻). 개별 Policy 문서 조회 실패는 전체를 중단시키지
    #: 않고 계속 진행하며, 실패한 항목만 여기 쌓인다.
    policy_fetch_errors: List[str] = Field(default_factory=list)
    #: 연결된 Policy 의 Allow Statement 중 Resource 가 전체/서비스 전체급
    #: wildcard(`"*"`, `"arn:...:*"`)인 것이 하나라도 있으면 True. GitHub의
    #: 저장소 개수·Slack의 채널 개수처럼 "몇 개에 접근 가능한가"를 세는 대신,
    #: AWS는 Resource가 ARN/와일드카드라 개수 자체가 의미 없어 이 이진값만
    #: 위험 근거로 쓴다(`graph/blast_radius.py` 참고).
    broad_access: bool = False
