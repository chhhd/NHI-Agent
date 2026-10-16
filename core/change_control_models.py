"""변경 승인(Change Control) 모델 — 승인 등급·상태·요청 레코드.

`agents/dry_run_service.py::build_change_preview()`(위험도·권한·정책·서비스
영향 분석 엔진, 이번 설계에서 손대지 않는다)가 계산한 "적용 전·후 비교"를
그대로 승인 대상으로 쓴다. 이 모듈은 "그 비교 결과를 누가 요청하고, 누가
승인하고, 승인 등급에 따라 무엇이 필요한지, 적용·롤백 상태를 어떻게
추적하는지"만 다룬다 — 실제 Credential 변경은 `backend/services/
change_control_service.py::ChangeExecutor`(그중 `InventoryStateExecutor`,
내부 상태만 바꾸고 외부 Provider는 호출하지 않음)의 책임이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from core.nhi_models import RecommendedAction


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalTier(str, Enum):
    """권한 중요도에 따른 승인 등급. 등급이 무엇을 요구하는지는
    `backend/services/change_control_service.py::ChangeControlService`가
    집행한다 — 이 값 자체는 분류일 뿐이다.
    """

    LOW = "LOW"            # 자동 승인(미리보기·감사 기록은 그대로 남는다)
    MEDIUM = "MEDIUM"      # 승인 1건 필요(요청자와 다른 사람)
    HIGH = "HIGH"          # 승인 1건 필요(요청자와 다른 사람) — MEDIUM과 집행 차이는 없고 중요도 표시만 다름
    CRITICAL = "CRITICAL"  # 승인 + 영향도 확인(impact_acknowledged) 필수


#: 조치(`RecommendedAction`)별 승인 등급. 조치 자체의 되돌리기 어려움·파급력을
#: 기준으로 정한 값이며, 관리자 역할 분리(ADMIN/SECURITY 등)는 이번 단계에서
#: 도입하지 않는다(관리자 인증 체계 전환은 보류 대상) — 그래서 모든 등급이
#: "승인자 ≠ 요청자"라는 같은 직무분리 규칙을 요구하고, CRITICAL만 영향도
#: 확인이라는 조건이 하나 더 붙는다.
TIER_FOR_ACTION: Dict[RecommendedAction, ApprovalTier] = {
    RecommendedAction.MONITOR: ApprovalTier.LOW,
    RecommendedAction.ASSIGN_OWNER: ApprovalTier.LOW,
    RecommendedAction.REQUEST_REAPPROVAL: ApprovalTier.LOW,
    RecommendedAction.SCOPE_REDUCTION: ApprovalTier.MEDIUM,
    RecommendedAction.MOVE_TO_ENV_VAR: ApprovalTier.MEDIUM,
    RecommendedAction.SPLIT_TOKEN_PER_PROJECT: ApprovalTier.MEDIUM,
    RecommendedAction.DISABLE_INACTIVE_NHI: ApprovalTier.MEDIUM,
    RecommendedAction.TOKEN_ROTATION: ApprovalTier.HIGH,
    RecommendedAction.TOKEN_REVOCATION: ApprovalTier.CRITICAL,
}


def tier_for_action(action: RecommendedAction) -> ApprovalTier:
    return TIER_FOR_ACTION.get(action, ApprovalTier.HIGH)  # 모르는 조치는 보수적으로 HIGH


class ChangeStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    #: 적용 진행 중 — 동시 적용 요청 중 하나만 이 상태로 전이에 성공한다
    #: (`storage.transition_change_request()`의 원자적 CAS). 정상적으로는
    #: 아주 짧게만 머물고 `APPLIED`/`FAILED`로 넘어간다.
    APPLYING = "APPLYING"
    APPLIED = "APPLIED"
    #: 실행기가 적용에 실패함 — 상태는 전혀 바뀌지 않았다(안전하게 유지).
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"


#: 사람이 직접 요청할 수 있는 종료 상태가 아니라, apply()/rollback() 내부에서만
#: 거쳐가는 과도 상태 — API로 노출되긴 하지만 외부에서 이 값으로 직접 전이를
#: 요청할 수는 없다.
TRANSIENT_STATUSES = frozenset({ChangeStatus.APPLYING, ChangeStatus.ROLLING_BACK})


class ChangeError(ValueError):
    """변경 요청이 현재 정책·상태에서 허용되지 않는다."""


class ChangeNotAllowed(ChangeError):
    """요청 내용 자체가 잘못되었다(예: Change Preview를 계산할 수 없음)."""


class StateConflict(ChangeError):
    """대상 상태가 요청 시점과 다르거나 이미 처리됐다."""


class SeparationOfDutiesError(ChangeError):
    """요청자와 승인자가 같다."""


class ChangeExecutionError(ChangeError):
    """실행기가 적용·롤백에 실패했다."""


@dataclass
class ChangeRequest:
    nhi_id: str
    change_type: RecommendedAction
    requested_by: str
    reason: str
    tier: ApprovalTier
    #: `build_change_preview()`가 계산한 적용 전·후 비교 전체(`to_dict()`) —
    #: 위험도·권한·정책·서비스 영향 분석을 그대로 보존한다.
    preview: Dict[str, Any]
    idempotency_key: str
    change_id: str = field(default_factory=lambda: str(uuid4()))
    status: ChangeStatus = ChangeStatus.PENDING_APPROVAL
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    decision_reason: str = ""
    impact_acknowledged: bool = False
    applied_at: Optional[str] = None
    #: 적용 결과(`ChangeExecutor.apply()`가 반환한 dict) — 실제 Provider를
    #: 호출했는지 여부가 항상 `provider_call` 키로 들어 있다(현재는
    #: 전부 `"not_configured"`, 즉 내부 상태만 바뀌었다는 뜻).
    executor_result: Dict[str, Any] = field(default_factory=dict)
    rollback_expires_at: Optional[str] = None
    rolled_back_at: Optional[str] = None
    failure_reason: str = ""
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_id": self.change_id,
            "nhi_id": self.nhi_id,
            "change_type": self.change_type.value,
            "requested_by": self.requested_by,
            "reason": self.reason,
            "tier": self.tier.value,
            "preview": self.preview,
            "idempotency_key": self.idempotency_key,
            "status": self.status.value,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "decision_reason": self.decision_reason,
            "impact_acknowledged": self.impact_acknowledged,
            "applied_at": self.applied_at,
            "executor_result": self.executor_result,
            "rollback_expires_at": self.rollback_expires_at,
            "rolled_back_at": self.rolled_back_at,
            "failure_reason": self.failure_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChangeRequest":
        return cls(
            nhi_id=data["nhi_id"],
            change_type=RecommendedAction(data["change_type"]),
            requested_by=data["requested_by"],
            reason=data.get("reason", ""),
            tier=ApprovalTier(data["tier"]),
            preview=data.get("preview") or {},
            idempotency_key=data["idempotency_key"],
            change_id=data["change_id"],
            status=ChangeStatus(data["status"]),
            approved_by=data.get("approved_by"),
            approved_at=data.get("approved_at"),
            decision_reason=data.get("decision_reason", ""),
            impact_acknowledged=bool(data.get("impact_acknowledged", False)),
            applied_at=data.get("applied_at"),
            executor_result=data.get("executor_result") or {},
            rollback_expires_at=data.get("rollback_expires_at"),
            rolled_back_at=data.get("rolled_back_at"),
            failure_reason=data.get("failure_reason", ""),
            created_at=data.get("created_at", _utcnow()),
            updated_at=data.get("updated_at", _utcnow()),
        )


__all__ = [
    "TIER_FOR_ACTION",
    "TRANSIENT_STATUSES",
    "ApprovalTier",
    "ChangeError",
    "ChangeExecutionError",
    "ChangeNotAllowed",
    "ChangeRequest",
    "ChangeStatus",
    "SeparationOfDutiesError",
    "StateConflict",
    "tier_for_action",
]
