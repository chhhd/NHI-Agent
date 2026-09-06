"""GitHub NHI 인벤토리 입력 모델.

분석 대상 NHI 를 **코드 스캔 없이 직접** 받는 경로의 입력 스키마다.
(스캔 경로의 입력은 `core/models.py` 의 `SecretFinding` 이다.)

FastAPI 진입점에서 Pydantic 이 이 모델로 요청을 검증하므로, 잘못된 값은
분석 함수까지 내려오지 않고 API 입구에서 422 로 걸러진다.

환경 구분과 위험 등급 같은 공통 열거형은 `core/nhi_models.py` 것을 그대로 쓴다.
입력 계층에서 같은 개념을 다시 정의하면 매핑 표가 하나 더 생기기 때문이다.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.nhi_models import Environment, NHIType


class GitHubNHIType(str, Enum):
    """GitHub 환경에서 인벤토리로 관리되는 NHI 유형."""

    GITHUB_APP = "GITHUB_APP"
    PERSONAL_ACCESS_TOKEN = "PERSONAL_ACCESS_TOKEN"
    ACTIONS_CREDENTIAL = "ACTIONS_CREDENTIAL"


#: 입력 유형 → 시스템 공통 NHI 유형
GITHUB_NHI_TYPE_MAP: Dict[GitHubNHIType, NHIType] = {
    GitHubNHIType.GITHUB_APP: NHIType.GITHUB_APP,
    GitHubNHIType.PERSONAL_ACCESS_TOKEN: NHIType.GITHUB_MACHINE_USER,
    GitHubNHIType.ACTIONS_CREDENTIAL: NHIType.GITHUB_ACTIONS_CREDENTIAL,
}


class RepositoryInfo(BaseModel):
    """NHI 가 접근할 수 있는 저장소 1건."""

    name: str = Field(..., examples=["acme/backend"])
    #: public / private / internal
    visibility: str = Field(default="private", examples=["private"])
    #: 민감한 코드·운영 설정을 포함한 저장소인가
    is_sensitive: bool = False

    @property
    def is_private(self) -> bool:
        return self.visibility.strip().lower() != "public"


class GitHubNHIInput(BaseModel):
    """분석 대상 GitHub NHI 1건.

    리스트·딕셔너리 기본값은 `default_factory` 로 만든다.
    가변 객체를 기본값으로 공유하면 인스턴스 간에 데이터가 섞인다.
    """

    nhi_id: str = Field(..., examples=["github-app-001"])
    nhi_name: str = Field(..., examples=["deployment-automation-app"])
    nhi_type: GitHubNHIType
    #: 관리 책임자 또는 팀. 없을 수 있으므로 None 을 허용한다 (Owner 미지정 판정 근거).
    owner: Optional[str] = None
    environment: Environment = Environment.UNKNOWN
    #: Credential 이 살아 있는가
    active: bool = True
    #: 실제 라이브 API 호출(예: GitHub App Installation Token 발급 +
    #: 저장소 조회)로 이 NHI 가 살아있음을 검증했는가.
    #: None = 검증을 시도하지 않음/해당 없음 (PAT 등 기존 경로는 항상 None).
    #: True = 검증 성공, False = 검증 시도했으나 실패 — 폐기로 단정하지 않고
    #: "상태 불명"으로 보수적으로 평가한다(`agents/inventory_adapter.py` 참고).
    credential_verified: Optional[bool] = None
    #: GitHub App Installation ID (`GitHubAppConnector.list_installations()`
    #: 의 `installation_id`). PAT/Actions Credential 경로는 설치 개념이
    #: 없으므로 항상 None이다.
    installation_id: Optional[str] = None
    #: GitHub API가 돌려준 설치 대상 계정. 보안 책임자(owner)와는 다른 개념이다.
    account: Dict[str, Any] = Field(default_factory=dict)
    repositories: List[RepositoryInfo] = Field(default_factory=list)
    #: all / selected. 조직 설치 목록 API는 선택 방식만 주고 저장소 이름은 주지 않는다.
    repository_selection: Optional[str] = None
    #: repositories 목록이 실제 접근 저장소 전체를 포함하는지 여부.
    repository_inventory_complete: bool = True
    #: 페이지 제한/항목 파싱 실패 없이 조직 App 설치 목록 전체를 수집했는지 여부.
    inventory_is_complete: bool = True
    collection_source: str = "manual_inventory"
    collection_evidence: List[str] = Field(default_factory=list)
    subscribed_events: List[str] = Field(default_factory=list)
    suspended_at: Optional[datetime] = None
    #: GitHub App 권한 (자원: 수준). 예: {"contents": "write", "administration": "write"}
    raw_permissions: Dict[str, str] = Field(default_factory=dict)
    #: Classic PAT / OAuth Token 의 평면 Scope. 예: ["repo", "workflow", "admin:repo_hook"]
    #: App 권한과 표기 체계가 달라 별도로 받는다(둘 다 있으면 합쳐서 변환한다).
    raw_scopes: List[str] = Field(default_factory=list)
    last_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_rotated_at: Optional[datetime] = None

    @property
    def nhi_type_common(self) -> NHIType:
        """시스템 공통 NHI 유형."""
        return GITHUB_NHI_TYPE_MAP.get(self.nhi_type, NHIType.UNKNOWN_NHI)

    @property
    def scopes(self) -> List[str]:
        """Scope Translation 에 넘길 원본 Scope 목록.

        App 권한 `{"contents": "write"}` 은 `"contents:write"` 로 펼치고,
        Classic PAT Scope(`"repo"`)는 그대로 쓴다. 둘 다 GitHub 매핑 테이블이 처리한다.
        """
        scopes = [scope.strip() for scope in self.raw_scopes if scope and scope.strip()]
        scopes += [
            f"{resource.strip()}:{level.strip().lower()}"
            for resource, level in self.raw_permissions.items()
            if resource and resource.strip() and level and level.strip().lower() != "none"
        ]
        return scopes


class SaaSAccessResource(BaseModel):
    """SaaS NHI가 접근하는 공급자 중립 자원."""

    name: str
    resource_type: str = "service"
    is_sensitive: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SaaSNHIInput(BaseModel):
    """Microsoft/Google 등 SaaS API에서 발견한 NHI 표준 입력.

    공급자 응답 원문이나 Credential 값은 담지 않는다. 분석에 필요한 식별자,
    Scope, Owner, 접근 자원과 시간 정보만 보관한다.
    """

    provider: str = Field(..., min_length=1, examples=["microsoft"])
    nhi_id: str = Field(..., min_length=1)
    nhi_name: str = Field(..., min_length=1)
    nhi_type: NHIType = NHIType.GENERIC_SERVICE_ACCOUNT
    owner: Optional[str] = None
    environment: Environment = Environment.UNKNOWN
    active: Optional[bool] = None
    raw_scopes: List[str] = Field(default_factory=list)
    resources: List[SaaSAccessResource] = Field(default_factory=list)
    connected_services: List[str] = Field(default_factory=list)
    account: Dict[str, Any] = Field(default_factory=dict)
    last_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_rotated_at: Optional[datetime] = None
