"""NHI 데이터 aging(DAS) 실행기 — 기준일을 넘긴 NHI 에 대해 종료·파기 **승인 요청**을 만든다.

`LifecycleService` 는 노후화 신호(`STALE_UNUSED`, `DISPOSAL_DUE` 등)를 계산해 보여 주기만 한다.
이 서비스는 그 신호를 변경 승인 흐름으로 연결한다.

- 장기 미사용(`STALE_UNUSED`, 기본 90일) → Token 폐기(종료) 승인 요청
- 종료 후 보존 기간 경과(`DISPOSAL_DUE`, 기본 30일) → Token 파기 승인 요청

**자동으로 종료·파기하지 않는다.** 요청은 `force_approval=True` 로 만들어 위험 등급이 LOW 여도
사람의 승인을 거친다(파기는 추가로 증적이 필요하다). 같은 NHI·같은 유형의 승인 대기 요청이
이미 있으면 새로 만들지 않아 여러 번 실행해도 중복되지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from backend.services.change_control_service import ChangeControlService, ChangeError
from backend.services.lifecycle_service import LifecycleError, LifecycleService
from backend.services.nhi_state import is_demo
from core.governance_models import ChangeStatus, ChangeType, LifecycleStage
from storage.base import Storage

#: aging 신호 → 제안할 변경
_SIGNAL_TO_CHANGE = {
    "STALE_UNUSED": ChangeType.TOKEN_REVOKE,
    "DISPOSAL_DUE": ChangeType.TOKEN_DISPOSE,
}
_ELIGIBLE_STAGE = {
    ChangeType.TOKEN_REVOKE: {
        LifecycleStage.REGISTERED,
        LifecycleStage.ACTIVE,
    },
    ChangeType.TOKEN_DISPOSE: {LifecycleStage.DEACTIVATED},
}
AGING_ACTOR = "aging-policy"


class NHIAgingService:
    def __init__(
        self,
        storage: Storage,
        *,
        changes: Optional[ChangeControlService] = None,
        lifecycle: Optional[LifecycleService] = None,
    ) -> None:
        self.storage = storage
        self.changes = changes or ChangeControlService(storage)
        self.lifecycle = lifecycle or self.changes.lifecycle

    def candidates(self, *, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """제안 대상 NHI 와 근거 신호(변경 없이 계산만)."""
        moment = now or datetime.now(timezone.utc)
        result: List[Dict[str, Any]] = []
        for nhi in self.storage.list_nhi_records(limit=5000):
            item = self.lifecycle._describe(nhi, moment, 0)
            stage = LifecycleStage(item["stage"])
            for flag in item["aging"]:
                change_type = _SIGNAL_TO_CHANGE.get(flag["code"])
                if change_type is None or stage not in _ELIGIBLE_STAGE[change_type]:
                    continue
                result.append(
                    {
                        "nhi_id": item["nhi_id"],
                        "nhi_name": item["nhi_name"],
                        "stage": stage.value,
                        "signal": flag["code"],
                        "message": flag["message"],
                        "change_type": change_type.value,
                        "days_since_last_use": item["days_since_last_use"],
                        "days_in_stage": item["days_in_stage"],
                        "demo_workspace": item["demo_workspace"],
                    }
                )
                break  # NHI 당 가장 시급한 신호 하나만
        return result

    def run(
        self,
        *,
        triggered_by: str,
        create_changes: bool = True,
        nhi_ids: Optional[Iterable[str]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        wanted = set(nhi_ids) if nhi_ids is not None else None
        items: List[Dict[str, Any]] = []
        counts = {"proposed": 0, "already_pending": 0, "failed": 0, "dry_run": 0}
        for candidate in self.candidates(now=now):
            if wanted is not None and candidate["nhi_id"] not in wanted:
                continue
            item = dict(candidate)
            if not create_changes:
                item["outcome"] = "DRY_RUN"
                counts["dry_run"] += 1
                items.append(item)
                continue
            change_type = ChangeType(candidate["change_type"])
            pending = self.storage.list_change_requests(
                status=ChangeStatus.PENDING_APPROVAL, nhi_id=candidate["nhi_id"], limit=100
            )
            existing = next((c for c in pending if c.change_type is change_type), None)
            if existing is not None:
                item.update(outcome="ALREADY_PENDING", change_id=existing.change_id)
                counts["already_pending"] += 1
                items.append(item)
                continue
            try:
                change = self.changes.propose(
                    candidate["nhi_id"],
                    change_type,
                    requested_by=AGING_ACTOR,
                    reason=f"[aging] {candidate['message']} (실행: {triggered_by})",
                    source="aging-policy",
                    force_approval=True,
                )
            except (ChangeError, LifecycleError, KeyError) as exc:
                item.update(outcome="FAILED", error=str(exc))
                counts["failed"] += 1
            else:
                item.update(
                    outcome="PROPOSED",
                    change_id=change.change_id,
                    tier=change.tier.value,
                    status=change.status.value,
                )
                counts["proposed"] += 1
            items.append(item)
        if create_changes:
            self.storage.append_audit_event(
                "AGING_RUN",
                actor=triggered_by,
                target="all-nhi" if wanted is None else ",".join(sorted(wanted))[:200],
                detail={**counts, "candidates": len(items)},
            )
        return {"dry_run": not create_changes, "counts": counts, "items": items}


__all__ = ["AGING_ACTOR", "NHIAgingService"]
