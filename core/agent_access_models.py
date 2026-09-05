"""회사 AI Agent의 승인된 API 접근 기준선과 실제 호출 판정 모델.

AI Agent(업무 주체)와 NHI/API Credential(인증 주체)을 분리한다. 요청이 어떤
Agent 이름을 주장하는지만 보지 않고, 실제 인증된 Agent·NHI·Credential과 승인된
권한·자원 범위를 함께 비교하기 위한 공급자 중립 계약이다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from core.nhi_models import PermissionLevel, RiskLevel


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentLifecycleStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"
    UNKNOWN = "UNKNOWN"


class AgentAccessOutcome(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


class AgentAccessGrant(BaseModel):
    """특정 Agent가 특정 NHI를 통해 사용할 수 있는 권한·자원 묶음."""

    grant_id: str = Field(default_factory=lambda: str(uuid4()))
    provider: str = Field(..., min_length=1, max_length=100)
    nhi_id: str = Field(..., min_length=1, max_length=300)
    credential_fingerprints: List[str] = Field(default_factory=list, max_length=100)
    credential_inventory_complete: bool = False
    permissions: List[PermissionLevel] = Field(default_factory=list, max_length=100)
    resources: List[str] = Field(default_factory=list, max_length=5000)
    sensitive_resources: List[str] = Field(default_factory=list, max_length=1000)
    permission_inventory_complete: bool = False
    resource_inventory_complete: bool = False
    source: str = Field(default="manual", min_length=1, max_length=200)

    @field_validator("credential_fingerprints")
    @classmethod
    def _fingerprints_are_references(cls, values: List[str]) -> List[str]:
        pattern = re.compile(r"^(?:sha256|nhi|jkt):[A-Za-z0-9:._-]{4,300}$")
        if any(not pattern.fullmatch(value) for value in values):
            raise ValueError(
                "credential_fingerprints에는 원문 Credential이 아닌 "
                "sha256:/nhi:/jkt: 식별자만 허용됩니다."
            )
        return list(dict.fromkeys(values))


class AgentAccessProfile(BaseModel):
    """회사가 승인한 AI Agent의 접근 기준선.

    ``inventory_complete=false``는 아직 모든 NHI 연결을 수집하지 못했다는 뜻이다.
    이때 목록에 없는 접근은 정상으로 허용하지도, 곧바로 공격으로 확정하지도 않고
    REVIEW로 보낸다.
    """

    agent_id: str = Field(..., min_length=1, max_length=200)
    display_name: str = Field(..., min_length=1, max_length=300)
    owner: Optional[str] = Field(default=None, max_length=300)
    status: AgentLifecycleStatus = AgentLifecycleStatus.ACTIVE
    environment: str = Field(default="unknown", min_length=1, max_length=50)
    grants: List[AgentAccessGrant] = Field(default_factory=list, max_length=500)
    require_sender_constraint: bool = True
    allowed_binding_methods: List[str] = Field(
        default_factory=lambda: ["DPoP", "mTLS"], max_length=20
    )
    inventory_complete: bool = False
    source: str = Field(default="manual", min_length=1, max_length=200)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utcnow)
    updated_at: str = Field(default_factory=_utcnow)


class AgentApiObservation(BaseModel):
    """API Gateway/Audit Log가 전달하는 한 번의 Agent API 호출 사실.

    ``credential_fingerprint``에는 원문 Token이 아니라 해시/내부 참조만 넣는다.
    IP와 User-Agent는 상관분석 보조 정보이며 인증 근거가 아니다.
    """

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=300)
    claimed_agent_id: str = Field(..., min_length=1, max_length=200)
    authenticated_agent_id: Optional[str] = Field(default=None, max_length=200)
    provider: str = Field(..., min_length=1, max_length=100)
    nhi_id: str = Field(..., min_length=1, max_length=300)
    credential_fingerprint: Optional[str] = Field(
        default=None,
        pattern=r"^(?:sha256|nhi|jkt):[A-Za-z0-9:._-]{4,300}$",
        description="원문 Credential 금지. sha256:/nhi:/jkt: 형식의 식별자만 허용",
    )
    action: str = Field(..., min_length=1, max_length=500)
    permission: Optional[PermissionLevel] = None
    resource: Optional[str] = Field(default=None, max_length=1000)
    resource_sensitive: bool = False
    sender_constrained: Optional[bool] = None
    binding_method: Optional[str] = Field(default=None, max_length=100)
    sender_proof_valid: Optional[bool] = None
    token_replay_suspected: bool = False
    source_ip: Optional[str] = Field(default=None, max_length=100)
    user_agent: Optional[str] = Field(default=None, max_length=500)
    occurred_at: str = Field(default_factory=_utcnow)


class AgentThreatFinding(BaseModel):
    rule_id: str
    category: str
    severity: RiskLevel
    title: str
    detail: str
    evidence: List[str] = Field(default_factory=list)
    blocking: bool = False


class AgentAccessDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    agent_id: str
    outcome: AgentAccessOutcome
    overall_severity: Optional[RiskLevel] = None
    matched_grant_id: Optional[str] = None
    findings: List[AgentThreatFinding] = Field(default_factory=list)
    observation: AgentApiObservation
    evaluated_at: str = Field(default_factory=_utcnow)


__all__ = [
    "AgentAccessDecision",
    "AgentAccessGrant",
    "AgentAccessOutcome",
    "AgentAccessProfile",
    "AgentApiObservation",
    "AgentLifecycleStatus",
    "AgentThreatFinding",
]
