"""추천 조치를 승인·실행·검증 가능한 작업으로 관리하는 모델."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    CANCELLED = "CANCELLED"


@dataclass
class ActionRequest:
    """Recommendation 을 영속적인 처리 작업으로 바꾼 레코드."""

    analysis_id: str
    credential_fingerprint: str
    action_type: str
    target: str
    rationale: str
    risk_level: str
    requires_approval: bool
    idempotency_key: str
    action_id: str = field(default_factory=lambda: str(uuid4()))
    status: ActionStatus = ActionStatus.PROPOSED
    provider: str = "unknown"
    secret_ref: Optional[str] = None
    demo_workspace: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionRequest":
        return cls(
            action_id=str(data["action_id"]),
            analysis_id=str(data["analysis_id"]),
            credential_fingerprint=str(data["credential_fingerprint"]),
            action_type=str(data["action_type"]),
            target=str(data.get("target", "")),
            rationale=str(data.get("rationale", "")),
            risk_level=str(data.get("risk_level", "")),
            requires_approval=bool(data.get("requires_approval", True)),
            idempotency_key=str(data["idempotency_key"]),
            status=ActionStatus(data.get("status", ActionStatus.PROPOSED.value)),
            provider=str(data.get("provider", "unknown")),
            secret_ref=data.get("secret_ref"),
            demo_workspace=bool(data.get("demo_workspace", False)),
            approved_by=data.get("approved_by"),
            approved_at=data.get("approved_at"),
            error_message=data.get("error_message"),
            result=data.get("result"),
            created_at=str(data.get("created_at") or _utcnow()),
            updated_at=str(data.get("updated_at") or _utcnow()),
        )
