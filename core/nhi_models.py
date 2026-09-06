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
class UsageAnalysisResult:
    """Result of analyzing granted permissions against observed usage."""

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
class SecurityEvent:
    """A security event involving an NHI resource access."""

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
class ScenarioMatch:
    """A risk scenario matched by security events."""

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
    recommendations: List[Recommendation] = field(default_factory=list)
    blast_radius: BlastRadiusReport = field(default_factory=BlastRadiusReport)
    analyzed_at: str = field(default_factory=_utcnow)
    #: 코드 스캔 결과인가, NHI 인벤토리 입력인가
    source: AnalysisSource = AnalysisSource.CODE_SCAN
    usage_analysis: UsageAnalysisResult = field(default_factory=UsageAnalysisResult)
    events: List[SecurityEvent] = field(default_factory=list)
    scenario_matches: List[ScenarioMatch] = field(default_factory=list)

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
            "risk_detail": self.risk.to_dict(),
            "policy": self.policy.to_dict(),
            "recommendations": [r.to_dict() for r in self.recommendations],
            "blast_radius": self.blast_radius.to_dict(),
            "usage_analysis": self.usage_analysis.to_dict(),
            "events": [event.to_dict() for event in self.events],
            "scenario_matches": [match.to_dict() for match in self.scenario_matches],
            "analyzed_at": self.analyzed_at,
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
