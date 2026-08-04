"""Backend·Database·Dashboard 가 공유하는 운영 엔티티.

Scanner/Agent 의 계산 모델과 운영 상태 모델을 분리한다. 예를 들어
``SecretFinding.status`` 는 재스캔 결과이고, 여기의 ``FindingStatus`` 는
관리자가 처리하는 장기 lifecycle 상태다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConnectorStatus(str, Enum):
    PENDING = "PENDING"
    CONFIGURED = "CONFIGURED"
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"


class FindingStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    RESCAN_PENDING = "RESCAN_PENDING"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    RECURRENCE = "RECURRENCE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    EXCEPTION = "EXCEPTION"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    SLA_OVERDUE = "SLA_OVERDUE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


@dataclass
class ProjectRecord:
    name: str
    repository: str
    project_id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    policy_enabled: bool = True
    schedule_enabled: bool = False
    schedule_cron: Optional[str] = None
    status: str = "ACTIVE"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectorRecord:
    provider: str
    name: str
    connector_id: str = field(default_factory=lambda: str(uuid4()))
    project_id: Optional[str] = None
    status: ConnectorStatus = ConnectorStatus.PENDING
    base_url: Optional[str] = None
    secret_ref: Optional[str] = None
    last_checked_at: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class FindingRecord:
    repository: str
    fingerprint: str
    secret_type: str
    provider: str
    file_path: str
    line_number: int
    masked_value: str
    severity: str
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    project_id: Optional[str] = None
    nhi_id: Optional[str] = None
    nhi_name: Optional[str] = None
    owner: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    status: FindingStatus = FindingStatus.NEW
    assigned_to: Optional[str] = None
    sla_due_at: Optional[str] = None
    first_detected_at: str = field(default_factory=utcnow)
    last_detected_at: str = field(default_factory=utcnow)
    resolved_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


# 아래 엔티티는 현재 기존 분석 테이블과 Action/Audit 저장소가 실제 레코드 역할을
# 한다. 명시적 모델을 둬 API/향후 PostgreSQL ORM 의 공통 계약으로 사용한다.
@dataclass
class OwnerRecord:
    owner_id: str
    name: str
    owner_type: str = "TEAM"
    contact: Optional[str] = None


@dataclass
class PermissionRecord:
    credential_fingerprint: str
    permission: str
    raw_scope: str
    source: str
    inferred: bool = False


@dataclass
class ActivityRecord:
    nhi_id: str
    action: str
    resource: str
    occurred_at: str
    provider: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessmentRecord:
    analysis_id: str
    fingerprint: str
    score: int
    level: str
    factors: List[Dict[str, Any]]
    scoring_version: str


@dataclass
class RecommendationRecord:
    analysis_id: str
    action: str
    priority: int
    rationale: str
    automatable: bool


@dataclass
class ApprovalRequestRecord:
    action_id: str
    status: str
    requested_at: str
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None


@dataclass
class RemediationActionRecord:
    action_id: str
    action_type: str
    before_state: Dict[str, Any]
    after_state: Dict[str, Any]
    status: str


@dataclass
class VerificationResultRecord:
    action_id: str
    verified: bool
    checked_at: str
    detail: Dict[str, Any]


@dataclass
class AuditEventRecord:
    event_id: str
    event_type: str
    actor: str
    target: str
    occurred_at: str
    detail: Dict[str, Any]
