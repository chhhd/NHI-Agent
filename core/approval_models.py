"""Human Approval 기본 흐름 — Dry-run 결과에 대한 승인/거부 최소 레코드.

`agents/dry_run_service.py` 가 계산한 `recommended_action` 을 사람이
승인/거부하는 흐름의 상태만 남긴다. 실제 Credential 폐기/회전 등 권한
변경은 이 모델이 다루지 않는다 — 승인이 나도 자동으로 실행되지 않는다
(실행 엔진 연결은 이후 별도 단계).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ApprovalRequest:
    """특정 NHI 의 recommended_action 에 대한 승인 요청 1건."""

    target_nhi_id: str
    recommended_action: str
    approval_id: str = field(default_factory=lambda: str(uuid4()))
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: str = field(default_factory=_utcnow)
    #: 승인/거부가 결정된 시각. 대기 중(PENDING)이면 None.
    decided_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["id"] = data.pop("approval_id")
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        return cls(
            approval_id=str(data.get("id") or data["approval_id"]),
            target_nhi_id=data["target_nhi_id"],
            recommended_action=data["recommended_action"],
            status=ApprovalStatus(data.get("status", ApprovalStatus.PENDING.value)),
            created_at=data.get("created_at") or _utcnow(),
            decided_at=data.get("decided_at"),
        )
