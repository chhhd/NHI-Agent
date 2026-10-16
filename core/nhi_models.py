"""분석 계층 데이터 모델 — NHI 분석 / 위험 점수화 표준 스키마.

탐지 계층의 `SecretFinding` 또는 NHI 인벤토리 입력을 받아
`NHIAnalysis` (NHI 식별 + 문맥 + 권한 + 위험도 + 정책 + 조치 권고) 를 만든다.

원문 Secret 은 이 계층에 절대 들어오지 않는다. 분석은 마스킹된 값과
메타데이터(경로/변수명/Scope/검증 결과)만으로 수행한다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    """ISO8601 문자열 → tz-aware datetime. 파싱 실패 시 None."""
    if not value:
        return None
    try:
        text = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def days_since(value: Optional[str], *, now: Optional[datetime] = None) -> Optional[int]:
    """주어진 시각으로부터 경과 일수. 파싱 불가 시 None."""
    dt = parse_dt(value)
    if dt is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return max(0, (reference - dt).days)


# ---------------------------------------------------------------------------
# 열거형
# ---------------------------------------------------------------------------
class NHIType(str, Enum):
    """Non-Human Identity 유형."""

    SLACK_BOT = "SLACK_BOT"
    SLACK_USER_TOKEN = "SLACK_USER_TOKEN"
    SLACK_APP = "SLACK_APP"
    SLACK_WEBHOOK = "SLACK_WEBHOOK"
    GITHUB_MACHINE_USER = "GITHUB_MACHINE_USER"
    GITHUB_APP = "GITHUB_APP"
    GITHUB_ACTIONS_CREDENTIAL = "GITHUB_ACTIONS_CREDENTIAL"
    MICROSOFT_SERVICE_PRINCIPAL = "MICROSOFT_SERVICE_PRINCIPAL"
    GOOGLE_OAUTH_CLIENT = "GOOGLE_OAUTH_CLIENT"
    GITLAB_SERVICE_ACCOUNT = "GITLAB_SERVICE_ACCOUNT"
    CLOUD_SERVICE_ACCOUNT = "CLOUD_SERVICE_ACCOUNT"
    AI_AGENT_CREDENTIAL = "AI_AGENT_CREDENTIAL"
    NOTION_INTEGRATION = "NOTION_INTEGRATION"
    PAYMENT_SERVICE_ACCOUNT = "PAYMENT_SERVICE_ACCOUNT"
    MAIL_SERVICE_ACCOUNT = "MAIL_SERVICE_ACCOUNT"
    REGISTRY_SERVICE_ACCOUNT = "REGISTRY_SERVICE_ACCOUNT"
    SIGNING_KEY = "SIGNING_KEY"
    GENERIC_SERVICE_ACCOUNT = "GENERIC_SERVICE_ACCOUNT"
    UNKNOWN_NHI = "UNKNOWN_NHI"


class AnalysisSource(str, Enum):
    """분석 대상이 어디서 들어왔는가.

    * CODE_SCAN — 저장소 스캔에서 탐지된 Secret (Scanner 경로)
    * INVENTORY — GitHub NHI 목록/메타데이터로 직접 입력된 NHI (Agent 경로)

    같은 위험 점수 체계를 쓰지만 "노출 위치" 의 의미가 달라 일부 규칙이 갈린다.
    코드에서 발견된 Secret 은 평문 노출 자체가 위반이고, 인벤토리 입력은
    접근 가능 범위가 노출 면적이다.
    """

    CODE_SCAN = "code_scan"
    INVENTORY = "inventory"


class PermissionLevel(str, Enum):
    """서비스별 Scope 를 변환한 공통 권한."""

    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ADMIN = "ADMIN"


#: 권한 강도 순위 (클수록 위험)
PERMISSION_RANK: Dict[PermissionLevel, int] = {
    PermissionLevel.READ: 1,
    PermissionLevel.WRITE: 2,
    PermissionLevel.DELETE: 3,
    PermissionLevel.ADMIN: 4,
}


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    """접근 가능한 데이터의 민감도."""

    RESTRICTED = "restricted"      # 결제/인증/개인식별정보
    CONFIDENTIAL = "confidential"  # 고객 데이터, 내부 운영 데이터
    INTERNAL = "internal"          # 일반 내부 데이터
    PUBLIC = "public"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecommendedAction(str, Enum):
    TOKEN_REVOCATION = "TOKEN_REVOCATION"              # 즉시 폐기
    TOKEN_ROTATION = "TOKEN_ROTATION"                  # 재발급
    SCOPE_REDUCTION = "SCOPE_REDUCTION"                # 권한 축소
    ASSIGN_OWNER = "ASSIGN_OWNER"                      # 소유자 지정
    SPLIT_TOKEN_PER_PROJECT = "SPLIT_TOKEN_PER_PROJECT"  # 프로젝트별 분리
    MOVE_TO_ENV_VAR = "MOVE_TO_ENV_VAR"                # 환경변수/시크릿 매니저 이전
    DISABLE_INACTIVE_NHI = "DISABLE_INACTIVE_NHI"      # 비활성 NHI 중지
    REQUEST_REAPPROVAL = "REQUEST_REAPPROVAL"          # 재승인 요청
    MONITOR = "MONITOR"                                # 관찰 유지


class PolicyOutcome(str, Enum):
    """정책 엔진 최종 판단."""

    AUTO_REMEDIATION = "AUTO_REMEDIATION"    # 자동 조치 가능
    HUMAN_REVIEW = "HUMAN_REVIEW"            # 담당자 검토 필요
    EXCEPTION_APPROVED = "EXCEPTION_APPROVED"  # 예외 정책으로 허용
    MONITOR = "MONITOR"                      # 위반 없음 — 관찰


class SecurityEventType(str, Enum):
    """감사 로그·런타임 신호에서 추출한 공급자 중립 보안 이벤트."""

    HIGH_RISK_SCOPE_GRANTED = "HIGH_RISK_SCOPE_GRANTED"
    STALE_PERMISSION = "STALE_PERMISSION"
    UNUSED_HIGH_PRIVILEGE = "UNUSED_HIGH_PRIVILEGE"
    OWNER_MISSING = "OWNER_MISSING"
    TOKEN_REPLAY = "TOKEN_REPLAY"
    REVOKED_CREDENTIAL_USE = "REVOKED_CREDENTIAL_USE"
    TERMINATED_AGENT_CREDENTIAL_USE = "TERMINATED_AGENT_CREDENTIAL_USE"
    UNDECLARED_PERMISSION_USE = "UNDECLARED_PERMISSION_USE"
    CROSS_PROJECT_CREDENTIAL_USE = "CROSS_PROJECT_CREDENTIAL_USE"


# ---------------------------------------------------------------------------
# 외부 입력 신호
# ---------------------------------------------------------------------------
@dataclass
class AnalysisSignals:
    """코드 스캔만으로는 알 수 없는 외부 사실.

    CMDB / IAM / 감사 로그 / Repository 메타데이터에서 주입한다.
    전부 선택 값이며, 없으면 분석은 보수적(중간 위험)으로 처리한다.
    """

    repository: str = ""
    repository_public: Optional[bool] = None
    project: Optional[str] = None
    #: NHI 를 사용하는 AI Agent 의 상태 (active / terminated / unknown)
    agent_status: Optional[str] = None
    agent_name: Optional[str] = None
    #: 조직에서 확정한 소유자 (있으면 Discovery 추정보다 우선)
    owner: Optional[str] = None
    #: NHI 에 승인된 권한 (초과 행위 판정 기준). 예: ["READ"]
    declared_permissions: List[str] = field(default_factory=list)
    #: 감사 로그에서 관측된 실제 행위. 예: ["chat:write", "delete_repo"]
    observed_actions: List[str] = field(default_factory=list)
    #: 폐기 처리 이후에도 호출이 관측되었는가
    token_used_after_revocation: Optional[bool] = None
    #: 자격 증명이 실제로 폐기된 시각. last_used_at과 순서를 비교할 때만 사용한다.
    revoked_at: Optional[str] = None
    #: Runtime gateway가 탈취 token/proof 재사용을 탐지했는가
    token_replay_suspected: Optional[bool] = None
    #: token이 호출 주체의 key/certificate에 암호학적으로 바인딩되었는가
    sender_constrained: Optional[bool] = None
    #: DPoP, mTLS, SPIFFE 등 적용된 sender constraint 방식
    token_binding_method: Optional[str] = None
    #: 이상행동 상관분석용 출처. 인증 주체를 결정하는 근거로 사용하지 않는다.
    request_source_ip: Optional[str] = None
    request_user_agent: Optional[str] = None
    #: 동일 Credential 을 함께 쓰는 프로젝트 목록
    shared_projects: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    expires_at: Optional[str] = None
    last_rotated_at: Optional[str] = None
    #: 승인된 예외 정책
    exception_id: Optional[str] = None
    exception_reason: Optional[str] = None
    exception_expires_at: Optional[str] = None
    #: 정책 대상에서 제외할 정책 ID 목록 (예외 범위)
    exempted_policies: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "AnalysisSignals":
        if not data:
            return cls()
        known = {f for f in cls.__dataclass_fields__ if f != "extra"}
        kwargs = {k: v for k, v in data.items() if k in known}
        signals = cls(**kwargs)
        # 알려지지 않은 키는 extra 로 모은다. 중첩된 extra 는 펼쳐서 병합한다.
        nested = data.get("extra")
        if isinstance(nested, dict):
            signals.extra.update(nested)
        signals.extra.update(
            {k: v for k, v in data.items() if k not in known and k != "extra"}
        )
        return signals

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Agent 산출물
# ---------------------------------------------------------------------------
@dataclass
class NHIProfile:
    """Discovery Agent 산출 — Credential 이 어떤 NHI 에 연결되는가."""

    nhi_id: str
    nhi_name: str
    nhi_type: NHIType = NHIType.UNKNOWN_NHI
    provider: str = "unknown"
    secret_type: str = ""
    secret_name: str = ""
    is_bot: bool = False
    is_service_account: bool = False
    linked_ai_agent: Optional[str] = None
    owner: Optional[str] = None
    owner_candidates: List[str] = field(default_factory=list)
    owner_source: Optional[str] = None
    account: Dict[str, Any] = field(default_factory=dict)
    identified: bool = False
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    #: Credential ↔ NHI 관계
    credential_fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["nhi_type"] = self.nhi_type.value
        return data


@dataclass
class ContextInsight:
    """Context Analysis Agent 산출 — 어디서 어떻게 쓰이는 Secret 인가."""

    environment: Environment = Environment.UNKNOWN
    is_test_or_example: bool = False
    in_use: Optional[bool] = None
    data_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    variable_name: Optional[str] = None
    hardcoded_in_source: bool = False
    project_hint: Optional[str] = None
    path_signals: List[str] = field(default_factory=list)
    code_signals: List[str] = field(default_factory=list)
    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["environment"] = self.environment.value
        data["data_sensitivity"] = self.data_sensitivity.value
        return data


@dataclass
class ScopeMapping:
    """원본 Scope 1건 → 공통 권한 변환 결과."""

    raw_scope: str
    permission: Optional[PermissionLevel]
    description: str = ""
    inferred: bool = False   # 규칙 테이블이 아닌 휴리스틱으로 판정

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_scope": self.raw_scope,
            "permission": self.permission.value if self.permission else None,
            "description": self.description,
            "inferred": self.inferred,
        }


@dataclass
class PermissionProfile:
    """Scope Translation Agent 산출 — 공통 권한 집합."""

    raw_scopes: List[str] = field(default_factory=list)
    permissions: List[PermissionLevel] = field(default_factory=list)
    mappings: List[ScopeMapping] = field(default_factory=list)
    unknown_scopes: List[str] = field(default_factory=list)
    #: Scope 를 확인하지 못해 Secret 유형 기준으로 가정했는가
    assumed: bool = False

    @property
    def highest(self) -> Optional[PermissionLevel]:
        if not self.permissions:
            return None
        return max(self.permissions, key=lambda p: PERMISSION_RANK[p])

    def has(self, level: PermissionLevel) -> bool:
        return level in self.permissions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_scopes": self.raw_scopes,
            "permissions": [p.value for p in self.permissions],
            "highest_permission": self.highest.value if self.highest else None,
            "mappings": [m.to_dict() for m in self.mappings],
            "unknown_scopes": self.unknown_scopes,
            "assumed": self.assumed,
        }


@dataclass
class UsageAnalysisResult:
    """승인된 권한과 관측 행위를 비교한 사용 분석 결과.

    관측 로그가 없다는 사실을 정상 사용으로 해석하지 않는다. ``evidence``에
    미관측/미확인 상태를 명시해 이후 정책과 보고서가 근거를 잃지 않게 한다.
    """

    declared_permissions: List[PermissionLevel] = field(default_factory=list)
    #: approved_signal / granted_scope / assumed_scope / unavailable
    permission_baseline_source: str = "unavailable"
    #: 승인 기준과 관측 행위가 모두 있어 초과 여부를 판정할 수 있는가.
    permission_comparison_complete: bool = False
    observed_permissions: List[PermissionLevel] = field(default_factory=list)
    observed_actions: List[str] = field(default_factory=list)
    unexpected_permissions: List[PermissionLevel] = field(default_factory=list)
    #: 완전한 사용 이력과 신뢰 가능한 권한 기준이 모두 있을 때만 채운다.
    unused_permissions: List[PermissionLevel] = field(default_factory=list)
    #: active / inactive_warning / stale / orphaned_candidate / unknown
    activity_status: str = "unknown"
    mutation_observed: bool = False
    #: None은 사용 로그 자체가 미제공/불완전함을 의미한다.
    usage_observed: Optional[bool] = None
    used_after_revocation: Optional[bool] = None
    replay_suspected: Optional[bool] = None
    last_used_at: Optional[str] = None
    sender_constrained: Optional[bool] = None
    token_binding_method: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    data_complete: bool = False
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    analyzed_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "declared_permissions": [item.value for item in self.declared_permissions],
            "permission_baseline_source": self.permission_baseline_source,
            "permission_comparison_complete": self.permission_comparison_complete,
            "observed_permissions": [item.value for item in self.observed_permissions],
            "observed_actions": list(self.observed_actions),
            "unexpected_permissions": [item.value for item in self.unexpected_permissions],
            "unused_permissions": [item.value for item in self.unused_permissions],
            "activity_status": self.activity_status,
            "mutation_observed": self.mutation_observed,
            "usage_observed": self.usage_observed,
            "used_after_revocation": self.used_after_revocation,
            "replay_suspected": self.replay_suspected,
            "last_used_at": self.last_used_at,
            "sender_constrained": self.sender_constrained,
            "token_binding_method": self.token_binding_method,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "data_complete": self.data_complete,
            "confidence": self.confidence,
            "sources": list(self.sources),
            "evidence": list(self.evidence),
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class SecurityEvent:
    """Usage Analysis에서 추출한 단일 보안 이벤트."""

    event_id: str
    event_type: SecurityEventType
    severity: RiskLevel
    title: str
    detail: str
    #: observed는 감사/런타임 직접 관측, derived/control_gap은 규칙으로 파생된 상태다.
    origin: str = "observed"
    confidence: float = 1.0
    source: Optional[str] = None
    source_event_id: Optional[str] = None
    occurred_at: Optional[str] = None
    #: 권한을 확인할 수 없는 이벤트는 None이며 JSON에서는 null로 보존한다.
    access_level: Optional[PermissionLevel] = None
    evidence: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "origin": self.origin,
            "confidence": self.confidence,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "occurred_at": self.occurred_at,
            "access_level": self.access_level.value if self.access_level else None,
            "evidence": list(self.evidence),
            "attributes": dict(self.attributes),
            "observed_at": self.observed_at,
        }


@dataclass
class ScenarioMatch:
    """추출된 이벤트가 조직의 공격/오용 시나리오와 일치한 결과."""

    scenario_id: str
    name: str
    severity: RiskLevel
    confidence: float
    reason: str
    event_ids: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    matched: bool = True
    forced_critical: bool = False
    category: str = "usage_anomaly"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class RiskFactor:
    """위험 점수 평가 영역 1건."""

    area: str
    label: str
    score: int
    max_score: int
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    """규칙 기반 Risk Scoring 결과."""

    score: int = 0
    level: RiskLevel = RiskLevel.LOW
    base_score: int = 0
    factors: List[RiskFactor] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    forced_critical: bool = False
    forced_rules: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "base_score": self.base_score,
            "factors": [f.to_dict() for f in self.factors],
            "reasons": self.reasons,
            "forced_critical": self.forced_critical,
            "forced_rules": self.forced_rules,
        }


@dataclass
class PolicyViolation:
    policy_id: str
    name: str
    detail: str
    severity: RiskLevel = RiskLevel.MEDIUM
    remediable: bool = True   # 자동 조치로 해소 가능한 위반인가

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class PolicyEvaluation:
    """Policy Engine 판단 결과."""

    outcome: PolicyOutcome = PolicyOutcome.MONITOR
    violations: List[PolicyViolation] = field(default_factory=list)
    auto_remediable: bool = False
    human_review_required: bool = False
    exception_applied: Optional[Dict[str, Any]] = None
    evidence: List[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "violations": [v.to_dict() for v in self.violations],
            "auto_remediable": self.auto_remediable,
            "human_review_required": self.human_review_required,
            "exception_applied": self.exception_applied,
            "evidence": self.evidence,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class Recommendation:
    action: RecommendedAction
    priority: int              # 1 이 가장 시급
    rationale: str
    target: str = ""
    automatable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["action"] = self.action.value
        return data


@dataclass
class BlastRadiusReport:
    """Credential 하나가 손상됐을 때의 영향 범위."""

    connected_services: List[str] = field(default_factory=list)
    accessible_resources: int = 0
    resource_samples: List[str] = field(default_factory=list)
    #: 정확한 접근 자원 개수 대신 "광범위한 접근"만 신호로 쓰는 provider(AWS)
    #: 용 플래그. GitHub/Slack 등 다른 provider 는 이 값을 설정하지 않으므로
    #: 항상 기본값 False 다 — `accessible_resources` 개수 기반 판단과는 별개다.
    broad_access: bool = False
    can_read: bool = False
    can_write: bool = False
    can_delete: bool = False
    external_transfer_possible: bool = False
    cross_project_impact: bool = False
    affected_projects: List[str] = field(default_factory=list)
    sensitive_data_access: bool = False
    impact_score: int = 0     # 0~100
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["connected_service_count"] = len(self.connected_services)
        return data


@dataclass
class PermissionUsageResult:
    """Result of analyzing granted permissions against observed usage.

    `UsageAnalysisResult`(위)와는 별개의, 더 단순한 권한 사용률 비교 결과다 —
    이름이 같은 클래스가 두 곳에서 각각 정의되어 있던 것을 병합하며 이름
    충돌을 피하려고 이 클래스만 `PermissionUsageResult` 로 옮겼다
    (`agents/usage_analysis_agent.py::PermissionUsageAgent` 산출물).
    """

    granted_permissions: List[PermissionLevel] = field(default_factory=list)
    used_permissions: List[PermissionLevel] = field(default_factory=list)
    unused_permissions: List[PermissionLevel] = field(default_factory=list)
    days_since_last_used: Optional[int] = None
    usage_status: str = "unknown"
    excessive_permission: bool = False
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "granted_permissions": [p.value for p in self.granted_permissions],
            "used_permissions": [p.value for p in self.used_permissions],
            "unused_permissions": [p.value for p in self.unused_permissions],
            "days_since_last_used": self.days_since_last_used,
            "usage_status": self.usage_status,
            "excessive_permission": self.excessive_permission,
            "evidence": self.evidence,
        }


@dataclass
class PermissionUsageEvent:
    """A security event involving an NHI resource access.

    `SecurityEvent`(위)와는 별개의, `agents/event_extraction_agent.py` 전용
    이벤트 형태다 — 이름 충돌을 피하려고 `PermissionUsageEvent` 로 옮겼다.
    """

    event_id: str
    nhi_id: str
    event_type: str
    resource_type: str
    access_level: Optional[PermissionLevel]
    event_risk: RiskLevel = RiskLevel.LOW
    event_count: int = 1
    timestamp: str = field(default_factory=_utcnow)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "nhi_id": self.nhi_id,
            "event_type": self.event_type,
            "resource_type": self.resource_type,
            "access_level": self.access_level.value if self.access_level else None,
            "event_risk": self.event_risk.value,
            "event_count": self.event_count,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
        }


@dataclass
class PermissionUsageScenarioMatch:
    """A risk scenario matched by security events.

    `ScenarioMatch`(위)와는 별개의, `agents/scenario_mapping_agent.py`/
    `agents/recommendation_agent.py` 전용 시나리오 매칭 결과다 — 이름 충돌을
    피하려고 `PermissionUsageScenarioMatch` 로 옮겼다.
    """

    scenario_id: str
    scenario_name: str
    severity: RiskLevel = RiskLevel.MEDIUM
    matched_events: List[str] = field(default_factory=list)
    matched_reason: str = ""
    risk_addition: int = 0
    recommended_action: RecommendedAction = RecommendedAction.MONITOR

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "severity": self.severity.value,
            "matched_events": self.matched_events,
            "matched_reason": self.matched_reason,
            "risk_addition": self.risk_addition,
            "recommended_action": self.recommended_action.value,
        }


@dataclass
class ChangePreviewSnapshot:
    """Change Preview가 가정 상태를 재구성하기 위한 최소 입력 스냅샷.

    화면에 노출되는 필드가 아니라 `agents/dry_run_service.py`가 "조치를 적용하면
    어떻게 바뀔지"를 같은 정책/위험도/영향범위 엔진으로 재실행할 때만 쓰는
    재현(replay)용 입력이다. `AnalysisSignals.to_dict()`와 `SecretFinding`의
    비민감 필드 일부만 담으며, 원문 Secret 값은 애초에 이 계층에 들어오지 않으므로
    여기에도 없다.
    """

    signals: Dict[str, Any] = field(default_factory=dict)
    finding: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"signals": dict(self.signals), "finding": dict(self.finding)}


@dataclass
class NHIAnalysis:
    """분석 계층 최종 산출물 — NHI 1건에 대한 전체 분석."""

    fingerprint: str
    repository: str
    file_path: str
    line_number: int
    masked_value: str
    profile: NHIProfile
    context: ContextInsight
    permissions: PermissionProfile
    risk: RiskAssessment
    policy: PolicyEvaluation
    usage_analysis: UsageAnalysisResult = field(default_factory=UsageAnalysisResult)
    security_events: List[SecurityEvent] = field(default_factory=list)
    scenario_matches: List[ScenarioMatch] = field(default_factory=list)
    recommendations: List[Recommendation] = field(default_factory=list)
    blast_radius: BlastRadiusReport = field(default_factory=BlastRadiusReport)
    analyzed_at: str = field(default_factory=_utcnow)
    #: 코드 스캔 결과인가, NHI 인벤토리 입력인가
    source: AnalysisSource = AnalysisSource.CODE_SCAN
    #: 기존 권한 사용률 기반 Event/Scenario 매핑 산출물 — `usage_analysis`/
    #: `scenario_matches`(위)와는 별개의 병렬 경로다 (`agents/pipeline.py::_assess()` 참고).
    permission_usage: PermissionUsageResult = field(default_factory=PermissionUsageResult)
    events: List[PermissionUsageEvent] = field(default_factory=list)
    permission_scenario_matches: List[PermissionUsageScenarioMatch] = field(default_factory=list)
    #: Change Preview 재현용 입력 스냅샷 (내부용, 7장 참고). 비어 있으면(과거
    #: 저장된 분석) Change Preview가 `estimated`/`unknown`으로 보수적 처리한다.
    replay_snapshot: ChangePreviewSnapshot = field(default_factory=ChangePreviewSnapshot)

    @property
    def recommended_action(self) -> RecommendedAction:
        if not self.recommendations:
            return RecommendedAction.MONITOR
        return min(self.recommendations, key=lambda r: r.priority).action

    def to_dict(self) -> Dict[str, Any]:
        """요약 필드를 앞에 두고 세부 근거를 뒤에 붙인다."""
        return {
            "nhi_name": self.profile.nhi_name,
            "nhi_type": self.profile.nhi_type.value,
            "owner": self.profile.owner,
            "environment": self.context.environment.value,
            "permissions": [p.value for p in self.permissions.permissions],
            "risk_score": self.risk.score,
            "risk_level": self.risk.level.value,
            "risk_reasons": self.risk.reasons,
            "recommended_action": self.recommended_action.value,
            # ---- 세부 근거 ----
            "source": self.source.value,
            "fingerprint": self.fingerprint,
            "repository": self.repository,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "masked_value": self.masked_value,
            "discovery": self.profile.to_dict(),
            "context_analysis": self.context.to_dict(),
            "permission_detail": self.permissions.to_dict(),
            "usage_analysis": self.usage_analysis.to_dict(),
            "security_events": [event.to_dict() for event in self.security_events],
            "scenario_matches": [match.to_dict() for match in self.scenario_matches],
            "risk_detail": self.risk.to_dict(),
            "policy": self.policy.to_dict(),
            "recommendations": [r.to_dict() for r in self.recommendations],
            "blast_radius": self.blast_radius.to_dict(),
            "permission_usage": self.permission_usage.to_dict(),
            "events": [event.to_dict() for event in self.events],
            "permission_scenario_matches": [
                match.to_dict() for match in self.permission_scenario_matches
            ],
            "analyzed_at": self.analyzed_at,
            # 화면에 표시할 필드가 아니다 — Change Preview 재현 전용(위 docstring 참고).
            "replay_snapshot": self.replay_snapshot.to_dict(),
        }


@dataclass
class NHIAnalysisReport:
    """스캔 1회 분석 결과 묶음."""

    repository: str
    analyses: List[NHIAnalysis] = field(default_factory=list)
    graph: Optional[Dict[str, Any]] = None
    generated_at: str = field(default_factory=_utcnow)

    def summary(self) -> Dict[str, Any]:
        counts = {level.value: 0 for level in RiskLevel}
        for analysis in self.analyses:
            counts[analysis.risk.level.value] += 1
        unknown = sum(
            1 for a in self.analyses if a.profile.nhi_type is NHIType.UNKNOWN_NHI
        )
        review = sum(1 for a in self.analyses if a.policy.human_review_required)
        return {
            "total": len(self.analyses),
            "by_risk_level": counts,
            "unknown_nhi": unknown,
            "human_review_required": review,
            "max_risk_score": max((a.risk.score for a in self.analyses), default=0),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "summary": self.summary(),
            "analyses": [a.to_dict() for a in self.analyses],
            "graph": self.graph,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Change Preview — 조치를 적용하기 전 가정 상태 비교 (실제 변경 없음)
# ---------------------------------------------------------------------------
class ImpactConfidence(str, Enum):
    """Change Preview 항목 1건의 근거 수준.

    실제로 조치를 적용해 검증한 값이 아니므로 "confirmed(확인됨)"라는 표현은
    쓰지 않는다. 같은 규칙 기반 엔진으로 재계산했는지, 재검증 없이 과거 값을
    추정으로 유지했는지, 아예 판단할 근거가 없는지만 구분한다.
    """

    #: 가정 상태를 입력으로 같은 정책/위험도/영향범위 엔진을 재실행해 얻은 값.
    CALCULATED = "calculated"
    #: 재검증 없이는 알 수 없어 과거 값·휴리스틱을 그대로 쓴 값(명시적으로 표시).
    ESTIMATED = "estimated"
    #: 판단할 근거 자체가 없음(데이터 없음·조회 실패 등).
    UNKNOWN = "unknown"


@dataclass
class ImpactItem:
    """서비스 의존성 또는 영향받을 수 있는 작업 1건."""

    name: str
    confidence: ImpactConfidence
    detail: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "confidence": self.confidence.value,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass
class ChangePreviewResult:
    """Dry-run 조치 1건의 적용 전·후 비교 (실제 Credential/권한 변경 없음).

    `risk`/`policy`/`blast_radius`의 before·after는 둘 다 같은
    `RiskScoringAgent`/`PolicyEvidenceAgent`/`BlastRadiusCalculator`를 재사용해
    계산한다 — after는 조치가 바꾸는 입력만 가정으로 바꾼 뒤 재실행한 결과다.
    가정에 쓸 입력 자체가 없으면(`NHIAnalysis.replay_snapshot` 미보유 등)
    `applicable=False`로 표시하고 after 값은 before를 그대로 복사한다.
    """

    target_nhi_id: str
    action: RecommendedAction
    generated_at: str = field(default_factory=_utcnow)
    #: 이 조치에 대해 가정 상태를 계산할 수 있었는가.
    applicable: bool = True
    not_applicable_reason: Optional[str] = None

    permissions_before: PermissionProfile = field(default_factory=PermissionProfile)
    permissions_after: PermissionProfile = field(default_factory=PermissionProfile)
    risk_before: RiskAssessment = field(default_factory=RiskAssessment)
    risk_after: RiskAssessment = field(default_factory=RiskAssessment)
    policy_before: PolicyEvaluation = field(default_factory=PolicyEvaluation)
    policy_after: PolicyEvaluation = field(default_factory=PolicyEvaluation)
    blast_radius_before: BlastRadiusReport = field(default_factory=BlastRadiusReport)
    blast_radius_after: BlastRadiusReport = field(default_factory=BlastRadiusReport)

    #: policy_id 목록 — 가정 상태에서 해소/신규/유지된 위반.
    resolved_violations: List[str] = field(default_factory=list)
    new_violations: List[str] = field(default_factory=list)
    unchanged_violations: List[str] = field(default_factory=list)

    #: 이 Credential과 연결된 서비스가 받는 영향 (연결 끊김·권한 변경 등).
    service_dependency_impact: List[ImpactItem] = field(default_factory=list)
    #: 조치 적용 시 영향받을 수 있는 운영 작업(예: 이 Credential을 쓰는 CI Job).
    affected_operations: List[ImpactItem] = field(default_factory=list)

    #: 근거 수준별 설명 — UI는 이 셋을 그대로 "계산됨/추정/확인불가" 섹션으로 보여준다.
    calculated_notes: List[str] = field(default_factory=list)
    estimated_notes: List[str] = field(default_factory=list)
    unknown_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_nhi_id": self.target_nhi_id,
            "recommended_action": self.action.value,
            "generated_at": self.generated_at,
            "applicable": self.applicable,
            "not_applicable_reason": self.not_applicable_reason,
            "permissions_before": self.permissions_before.to_dict(),
            "permissions_after": self.permissions_after.to_dict(),
            "risk_before": self.risk_before.to_dict(),
            "risk_after": self.risk_after.to_dict(),
            "policy_before": self.policy_before.to_dict(),
            "policy_after": self.policy_after.to_dict(),
            "blast_radius_before": self.blast_radius_before.to_dict(),
            "blast_radius_after": self.blast_radius_after.to_dict(),
            "policy_diff": {
                "resolved_violations": list(self.resolved_violations),
                "new_violations": list(self.new_violations),
                "unchanged_violations": list(self.unchanged_violations),
            },
            "service_dependency_impact": [
                item.to_dict() for item in self.service_dependency_impact
            ],
            "affected_operations": [
                item.to_dict() for item in self.affected_operations
            ],
            "data_quality": {
                "calculated_notes": list(self.calculated_notes),
                "estimated_notes": list(self.estimated_notes),
                "unknown_notes": list(self.unknown_notes),
            },
        }
