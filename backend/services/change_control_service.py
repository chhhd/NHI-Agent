"""변경 승인 서비스 — Change Preview 미리보기 · 승인 등급 · 적용 · 롤백.

`agents/dry_run_service.py::build_change_preview()`(위험도·권한·정책·서비스
영향 분석 엔진)는 전혀 수정하지 않고 그대로 재사용한다. 이 서비스가 새로
하는 일은:

    1. 그 비교 결과를 승인 대기 요청(`ChangeRequest`)으로 만들고
    2. 조치 중요도에 따른 승인 등급(LOW~CRITICAL)을 매겨
    3. 요청자와 다른 사람의 승인을 거쳐야만 적용하고(직무 분리)
    4. 적용 후에도 유효 기간 내에는 롤백할 수 있게 하는 것뿐이다.

`ChangeExecutor`(Provider 연동 지점)의 기본 구현 `InventoryStateExecutor`는
**우리 NHI Lifecycle 상태만** 바꾼다 — 실제 GitHub/Slack/AWS API를 호출하거나
Credential을 바꾸는 코드는 이 파일 어디에도 없다. `apply()`/`rollback()`의
반환값에는 항상 `provider_call: "not_configured"`가 들어가, API 응답과 감사
로그에서 "내부 상태만 바뀌었다"와 "실제 Provider에 적용됐다"를 혼동하지 않게
한다(현재는 전자만 가능하다).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Protocol

from agents.dry_run_service import build_change_preview, get_latest_analysis_snapshot
from core.change_control_models import (
    ApprovalTier,
    ChangeError,
    ChangeExecutionError,
    ChangeNotAllowed,
    ChangeRequest,
    ChangeStatus,
    SeparationOfDutiesError,
    StateConflict,
    tier_for_action,
)
from core.nhi_lifecycle_models import NHILifecycleEventType, NHILifecycleStatus
from core.nhi_models import RecommendedAction
from storage.base import Storage

logger = logging.getLogger(__name__)

#: Lifecycle 상태 전이로 표현되는 조치 — "되돌릴 수 없게 서비스가 끊긴다"는
#: 인상을 주는 조치만 여기 둔다. 나머지는 상태를 바꾸지 않고 이벤트만 남긴다.
_DEACTIVATING_ACTIONS = frozenset(
    {RecommendedAction.TOKEN_REVOCATION, RecommendedAction.DISABLE_INACTIVE_NHI}
)

#: 아무 내부 상태도 바꾸지 않는 조치(Change Preview의 `_effect_noop`과 대응).
_NOOP_ACTIONS = frozenset(
    {RecommendedAction.MONITOR, RecommendedAction.REQUEST_REAPPROVAL}
)

#: 적용 후 롤백 가능 기간(시간) — team 설계의 "유예 시간" 개념을 그대로 가져왔다.
DEFAULT_ROLLBACK_GRACE_HOURS = 24


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ChangeExecutor(Protocol):
    """Provider 연동 지점 — 실제로는 `InventoryStateExecutor`만 존재한다."""

    name: str

    def apply(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]: ...

    def rollback(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]: ...


class InventoryStateExecutor:
    """기본(유일한) 실행기 — NHI Lifecycle 상태만 바꾸고 외부 Provider는 호출하지 않는다.

    `TOKEN_REVOCATION`/`DISABLE_INACTIVE_NHI`는 Lifecycle을 `DEACTIVATED`로
    전이시킨다(해당 NHI의 Credential을 더 이상 쓰지 않는다는 관리적 결정을
    남긴다는 뜻 — 실제 Provider의 Credential을 폐기하지는 않는다). 나머지
    조치는 상태를 바꾸지 않고 `PERMISSION_CHANGED` Timeline 이벤트만 남긴다
    (`record_nhi_permission_change()` — 이미 NHI Lifecycle 단계에서 만든
    바로 그 Primitive다). `MONITOR`/`REQUEST_REAPPROVAL`은 아무것도 하지 않는다.
    """

    name = "inventory-state"

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def apply(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "executor": self.name,
            "provider_call": "not_configured",
            "scope": "internal_only",
        }
        action = change.change_type
        self.storage.initialize_nhi_lifecycle(change.nhi_id, actor=change.approved_by or "change-control")

        if action in _DEACTIVATING_ACTIONS:
            state = self.storage.get_nhi_lifecycle_state(change.nhi_id)
            current = NHILifecycleStatus(state["status"]) if state else None
            if current is NHILifecycleStatus.DEACTIVATED:
                result["lifecycle_status"] = current.value
                result["already_in_target_state"] = True
                return result
            updated = self.storage.update_nhi_lifecycle_status(
                change.nhi_id,
                NHILifecycleStatus.DEACTIVATED,
                event_type=NHILifecycleEventType.DEACTIVATED,
                actor=change.approved_by or "change-control",
                note=f"ChangeControlService 적용: {action.value}",
                detail={"change_id": change.change_id, "change_type": action.value},
            )
            result["lifecycle_status"] = updated["status"]
            # PATCH /nhi/{id}/lifecycle(수동 전이)과 같은 감사 이벤트 유형을 남긴다 —
            # Lifecycle 상태가 누가/무엇으로 바뀌었는지와 무관하게 /audit 조회에서
            # 같은 방식으로 추적돼야 한다(감사 기록 일관성).
            self.storage.append_audit_event(
                "NHI_LIFECYCLE_STATUS_CHANGED",
                actor=change.approved_by or "change-control",
                target=change.nhi_id,
                detail={
                    "from_status": state["status"] if state else None,
                    "to_status": updated["status"],
                    "event_type": NHILifecycleEventType.DEACTIVATED.value,
                    "change_id": change.change_id,
                    "source": "change_control_apply",
                },
            )
        elif action in _NOOP_ACTIONS:
            result["lifecycle_event"] = "NOOP"
        else:
            self.storage.record_nhi_permission_change(
                change.nhi_id,
                actor=change.approved_by or "change-control",
                note=f"ChangeControlService 적용: {action.value}",
                detail={"change_id": change.change_id, "change_type": action.value},
            )
            result["lifecycle_event"] = "PERMISSION_CHANGED"
            self.storage.append_audit_event(
                "NHI_PERMISSION_CHANGED",
                actor=change.approved_by or "change-control",
                target=change.nhi_id,
                detail={"change_id": change.change_id, "change_type": action.value, "source": "change_control_apply"},
            )
        return result

    def rollback(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "executor": self.name,
            "provider_call": "not_configured",
            "scope": "internal_only",
        }
        action = change.change_type

        if action in _DEACTIVATING_ACTIONS:
            state = self.storage.get_nhi_lifecycle_state(change.nhi_id)
            current = NHILifecycleStatus(state["status"]) if state else None
            if current is NHILifecycleStatus.ACTIVE:
                result["lifecycle_status"] = current.value
                result["already_in_target_state"] = True
                return result
            updated = self.storage.update_nhi_lifecycle_status(
                change.nhi_id,
                NHILifecycleStatus.ACTIVE,
                event_type=NHILifecycleEventType.REACTIVATED,
                actor=change.approved_by or "change-control",
                note=f"ChangeControlService 롤백: {action.value}",
                detail={"change_id": change.change_id, "rollback_of": action.value},
            )
            result["lifecycle_status"] = updated["status"]
            self.storage.append_audit_event(
                "NHI_LIFECYCLE_STATUS_CHANGED",
                actor=change.approved_by or "change-control",
                target=change.nhi_id,
                detail={
                    "from_status": state["status"] if state else None,
                    "to_status": updated["status"],
                    "event_type": NHILifecycleEventType.REACTIVATED.value,
                    "change_id": change.change_id,
                    "source": "change_control_rollback",
                },
            )
        elif action in _NOOP_ACTIONS:
            result["lifecycle_event"] = "NOOP"
        else:
            self.storage.record_nhi_permission_change(
                change.nhi_id,
                actor=change.approved_by or "change-control",
                note=f"ChangeControlService 롤백: {action.value}",
                detail={"change_id": change.change_id, "rollback_of": action.value},
            )
            self.storage.append_audit_event(
                "NHI_PERMISSION_CHANGED",
                actor=change.approved_by or "change-control",
                target=change.nhi_id,
                detail={"change_id": change.change_id, "rollback_of": action.value, "source": "change_control_rollback"},
            )
            result["lifecycle_event"] = "PERMISSION_CHANGED"
        return result


class ChangeControlService:
    def __init__(
        self,
        storage: Storage,
        *,
        executor: Optional[ChangeExecutor] = None,
        rollback_grace_hours: int = DEFAULT_ROLLBACK_GRACE_HOURS,
    ) -> None:
        self.storage = storage
        self.executor = executor or InventoryStateExecutor(storage)
        self.rollback_grace_hours = rollback_grace_hours

    # -- 조회 ------------------------------------------------------------
    def get(self, change_id: str) -> ChangeRequest:
        data = self.storage.get_change_request(change_id)
        if data is None:
            raise KeyError(change_id)
        return ChangeRequest.from_dict(data)

    def list(
        self, *, nhi_id: Optional[str] = None, status: Optional[ChangeStatus] = None, limit: int = 100
    ) -> list[ChangeRequest]:
        rows = self.storage.list_change_requests(
            nhi_id=nhi_id, status=status.value if status else None, limit=limit
        )
        return [ChangeRequest.from_dict(row) for row in rows]

    # -- 1. 미리보기 + 승인 요청 생성 -------------------------------------
    def propose(
        self,
        nhi_id: str,
        *,
        requested_by: str,
        reason: str,
        idempotency_key: str,
        impact_acknowledged: bool = False,
    ) -> ChangeRequest:
        """최신 분석의 추천 조치를 Change Preview로 재계산해 승인 요청을 만든다.

        `idempotency_key`가 이미 쓰인 적 있으면(재시도 등) 새로 만들지 않고
        기존 요청을 그대로 반환한다 — `storage.create_change_request()`가
        이 검사를 원자적으로 수행한다(아래에서 호출).
        """
        if self.storage.get_nhi_record(nhi_id) is None:
            raise ChangeNotAllowed(f"NHI 를 찾을 수 없습니다: {nhi_id}")

        snapshot = get_latest_analysis_snapshot(self.storage, nhi_id)
        if snapshot is None:
            raise ChangeNotAllowed(
                "이 NHI 에는 Change Preview 를 계산할 분석 이력이 없습니다 — 먼저 분석을 수행하세요."
            )
        preview = build_change_preview(nhi_id, snapshot)
        if not preview.applicable:
            raise ChangeNotAllowed(
                f"Change Preview 를 계산할 수 없어 변경을 제안할 수 없습니다: {preview.not_applicable_reason}"
            )

        tier = tier_for_action(preview.action)
        if tier is ApprovalTier.CRITICAL and not impact_acknowledged:
            raise ChangeNotAllowed(
                "CRITICAL 등급 변경은 impact_acknowledged=true 로 영향도를 확인해야 제안할 수 있습니다."
            )

        status = ChangeStatus.PENDING_APPROVAL
        approved_by = None
        approved_at = None
        if tier is ApprovalTier.LOW:
            status = ChangeStatus.APPROVED
            approved_by = "system-auto-approval"
            approved_at = _utcnow()

        change = ChangeRequest(
            nhi_id=nhi_id,
            change_type=preview.action,
            requested_by=requested_by,
            reason=reason,
            tier=tier,
            preview=preview.to_dict(),
            idempotency_key=idempotency_key,
            status=status,
            approved_by=approved_by,
            approved_at=approved_at,
            impact_acknowledged=impact_acknowledged,
        )
        saved = self.storage.create_change_request(change.to_dict())
        return ChangeRequest.from_dict(saved)

    # -- 2. 승인/거부 ------------------------------------------------------
    def approve(self, change_id: str, *, approved_by: str) -> ChangeRequest:
        change = self.get(change_id)
        if change.status is not ChangeStatus.PENDING_APPROVAL:
            raise StateConflict(f"현재 상태({change.status.value})에서는 승인할 수 없습니다.")
        if approved_by == change.requested_by:
            raise SeparationOfDutiesError("요청자와 승인자가 같을 수 없습니다 — 직무 분리 위반.")

        ok = self.storage.transition_change_request(
            change_id,
            expected_status=ChangeStatus.PENDING_APPROVAL.value,
            new_status=ChangeStatus.APPROVED.value,
            fields={"approved_by": approved_by, "approved_at": _utcnow()},
        )
        if not ok:
            raise StateConflict("동시에 처리되어 더 이상 승인할 수 없는 상태입니다.")
        return self.get(change_id)

    def reject(self, change_id: str, *, actor: str, reason: str = "") -> ChangeRequest:
        change = self.get(change_id)
        if change.status is not ChangeStatus.PENDING_APPROVAL:
            raise StateConflict(f"현재 상태({change.status.value})에서는 거부할 수 없습니다.")
        ok = self.storage.transition_change_request(
            change_id,
            expected_status=ChangeStatus.PENDING_APPROVAL.value,
            new_status=ChangeStatus.REJECTED.value,
            fields={"decision_reason": reason},
        )
        if not ok:
            raise StateConflict("동시에 처리되어 더 이상 거부할 수 없는 상태입니다.")
        return self.get(change_id)

    # -- 3. 적용 -----------------------------------------------------------
    def apply(self, change_id: str, *, actor: str) -> ChangeRequest:
        """승인된 변경만 적용한다. 이미 적용된 변경은 다시 실행하지 않고
        그대로 반환한다(중복 실행 방지) — 실패하면 상태는 `FAILED`로만
        바뀌고, 실행기가 실제로 어떤 내부 상태를 바꿨는지는 전혀 건드리지
        않은 채로 남는다(실패 시 안전한 상태 유지).
        """
        change = self.get(change_id)
        if change.status is ChangeStatus.APPLIED:
            return change  # 이미 끝난 요청 — 재실행하지 않고 그대로 반환(멱등)
        if change.status is not ChangeStatus.APPROVED:
            raise StateConflict(f"현재 상태({change.status.value})에서는 적용할 수 없습니다.")

        nhi = self.storage.get_nhi_record(change.nhi_id)
        if nhi is None:
            raise ChangeError(f"NHI 를 찾을 수 없습니다: {change.nhi_id}")

        # 동시 적용 요청 중 정확히 하나만 이 전이에 성공한다 — 나머지는
        # 아래에서 바로 재조회해 "이미 처리됨"을 그대로 돌려준다.
        claimed = self.storage.transition_change_request(
            change_id,
            expected_status=ChangeStatus.APPROVED.value,
            new_status=ChangeStatus.APPLYING.value,
            fields={},
        )
        if not claimed:
            return self.get(change_id)

        try:
            result = self.executor.apply(change, nhi)
        except Exception as exc:  # noqa: BLE001 - 실행기 실패는 전부 FAILED 로 안전하게 처리
            logger.exception("ChangeControlService.apply 실패 (change_id=%s)", change_id)
            self.storage.transition_change_request(
                change_id,
                expected_status=ChangeStatus.APPLYING.value,
                new_status=ChangeStatus.FAILED.value,
                fields={"failure_reason": str(exc)},
            )
            raise ChangeExecutionError(f"변경 적용에 실패했습니다: {exc}") from exc

        now = _utcnow()
        rollback_expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=self.rollback_grace_hours)
        ).isoformat()
        self.storage.transition_change_request(
            change_id,
            expected_status=ChangeStatus.APPLYING.value,
            new_status=ChangeStatus.APPLIED.value,
            fields={
                "applied_at": now,
                "rollback_expires_at": rollback_expires_at,
                "executor_result": result,
            },
        )
        return self.get(change_id)

    # -- 4. 롤백 -----------------------------------------------------------
    def rollback(self, change_id: str, *, actor: str) -> ChangeRequest:
        change = self.get(change_id)
        if change.status is not ChangeStatus.APPLIED:
            raise StateConflict(f"현재 상태({change.status.value})에서는 롤백할 수 없습니다.")
        if change.rollback_expires_at and _utcnow() > change.rollback_expires_at:
            raise StateConflict(
                f"롤백 가능 기간({change.rollback_expires_at})이 지나 더 이상 롤백할 수 없습니다."
            )

        nhi = self.storage.get_nhi_record(change.nhi_id)
        if nhi is None:
            raise ChangeError(f"NHI 를 찾을 수 없습니다: {change.nhi_id}")

        claimed = self.storage.transition_change_request(
            change_id,
            expected_status=ChangeStatus.APPLIED.value,
            new_status=ChangeStatus.ROLLING_BACK.value,
            fields={},
        )
        if not claimed:
            return self.get(change_id)

        try:
            result = self.executor.rollback(change, nhi)
        except Exception as exc:  # noqa: BLE001
            logger.exception("ChangeControlService.rollback 실패 (change_id=%s)", change_id)
            # 실패하면 원래의 안전한 기지 상태(APPLIED)로 되돌린다 — ROLLING_BACK에
            # 머물거나 잘못 ROLLED_BACK 으로 넘어가지 않는다.
            self.storage.transition_change_request(
                change_id,
                expected_status=ChangeStatus.ROLLING_BACK.value,
                new_status=ChangeStatus.APPLIED.value,
                fields={"failure_reason": str(exc)},
            )
            raise ChangeExecutionError(f"롤백에 실패했습니다: {exc}") from exc

        self.storage.transition_change_request(
            change_id,
            expected_status=ChangeStatus.ROLLING_BACK.value,
            new_status=ChangeStatus.ROLLED_BACK.value,
            fields={"rolled_back_at": _utcnow(), "executor_result": result},
        )
        return self.get(change_id)


__all__ = [
    "ChangeControlService",
    "ChangeExecutor",
    "DEFAULT_ROLLBACK_GRACE_HOURS",
    "InventoryStateExecutor",
]
