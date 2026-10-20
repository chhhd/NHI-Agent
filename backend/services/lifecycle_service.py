"""NHI 생명주기 관리 (DAS: Digital Aging System).

등록 → 사용 → 사용 중지 → 폐기 완료 4단계로 NHI를 가시화한다.

- 단계 전이는 `STAGE_TRANSITIONS` 로 검증하고 모든 전이를 타임라인에 남긴다.
- 사용 중지·폐기 완료는 변경 승인 흐름으로 처리하고 권한 변경은 이벤트로 남긴다.
- 사람이 직접 옮길 수 있는 전이는 등록 → 사용 활성화다. 폐기 완료에는 파기 증적이 필수다.
- 노후화(aging) 신호를 계산해 어느 단계에서 무엇을 해야 하는지 알려 준다.
  "잊혀질 권리"의 핵심인 보존 기간 경과 후 파기 누락을 잡아낸다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.services.nhi_state import (
    GOVERNANCE_LOCK,
    days_between,
    is_demo,
    load_nhi,
    parse_dt,
    save_nhi,
    snapshot,
)
from core.config import GovernanceSettings, get_settings
from core.governance_models import (
    STAGE_LABELS,
    STAGE_TRANSITIONS,
    ChangeStatus,
    ControlState,
    CredentialState,
    LifecycleEvent,
    LifecycleStage,
    utcnow,
)
from storage.base import Storage
from core.destruction_models import DestructionEvidence, evidence_digest

#: 단계 전이를 단독으로 허용하는 안전한 수동 전이. 나머지는 변경 승인 흐름을 거쳐야 한다.
_MANUAL_ADVANCE = {
    LifecycleStage.REGISTERED: LifecycleStage.ACTIVE,
}


class LifecycleError(ValueError):
    """허용되지 않은 생명주기 전이."""


def _flag(code: str, severity: str, message: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


class LifecycleService:
    def __init__(
        self, storage: Storage, settings: Optional[GovernanceSettings] = None
    ) -> None:
        self.storage = storage
        self.settings = settings or get_settings().governance

    # ------------------------------------------------------------------
    # 등록 / 전이
    # ------------------------------------------------------------------
    def ensure_tracked(
        self, nhi_id: str, *, actor: str = "system", at: Optional[str] = None
    ) -> bool:
        """처음 관측된 NHI 를 생성 단계로 등록한다 (이미 추적 중이면 아무것도 하지 않는다).

        Owner 가 지정되고 신원이 확정된 NHI 는 거버넌스 게이트를 통과한 것으로 보고
        곧바로 사용 단계로 올린다. 아니면 생성 단계에 머물며 활성화 조건을 안내한다.
        """
        with GOVERNANCE_LOCK:
            nhi = load_nhi(self.storage, nhi_id)
            if nhi.get("lifecycle_stage"):
                return self._auto_activate(nhi, actor=actor)
            moment = at or utcnow()
            nhi.update(
                {
                    "lifecycle_stage": LifecycleStage.REGISTERED.value,
                    "credential_state": CredentialState.ACTIVE.value,
                    "control_state": ControlState.NORMAL.value,
                    "credential_version": int(nhi.get("credential_version") or 1),
                    "first_seen_at": nhi.get("first_seen_at") or moment,
                    "stage_entered_at": moment,
                }
            )
            save_nhi(self.storage, nhi)
            self._log(
                nhi,
                LifecycleStage.REGISTERED,
                "DISCOVERED",
                actor,
                {"owner": nhi.get("owner"), "identified": nhi.get("identified")},
                at=moment,
            )
            self._auto_activate(nhi, actor=actor)
            return True

    def _auto_activate(self, nhi: Dict[str, Any], *, actor: str) -> bool:
        if nhi.get("lifecycle_stage") != LifecycleStage.REGISTERED.value:
            return False
        if not (nhi.get("owner") and nhi.get("identified")):
            return False
        self._move(
            nhi,
            LifecycleStage.ACTIVE,
            "AUTO_ACTIVATED",
            actor,
            {"reason": "Owner 지정 및 신원 확정 — 거버넌스 게이트 통과"},
        )
        return True

    def advance(self, nhi_id: str, *, actor: str, reason: str = "") -> Dict[str, Any]:
        """사람이 직접 옮길 수 있는 안전한 전이 (등록→사용)."""
        with GOVERNANCE_LOCK:
            nhi = load_nhi(self.storage, nhi_id)
            current = LifecycleStage(snapshot(nhi)["lifecycle_stage"])
            target = _MANUAL_ADVANCE.get(current)
            if target is None:
                raise LifecycleError(
                    f"{STAGE_LABELS[current]} 단계에서는 수동으로 단계를 올릴 수 없습니다. "
                    "종료·파기는 변경 승인 요청으로 진행하세요."
                )
            if current is LifecycleStage.REGISTERED and not nhi.get("owner"):
                raise LifecycleError("Owner 가 지정되지 않은 NHI 는 활성화할 수 없습니다.")
            self._move(nhi, target, "STAGE_ADVANCED", actor, {"reason": reason})
            return self.view(nhi_id)

    def transition(
        self,
        nhi_id: str,
        target: LifecycleStage,
        *,
        event_type: str,
        actor: str,
        detail: Optional[Dict[str, Any]] = None,
        change_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """변경 승인 흐름이 쓰는 검증된 전이. NHI 레코드를 저장한다."""
        with GOVERNANCE_LOCK:
            nhi = load_nhi(self.storage, nhi_id)
            self._move(
                nhi, target, event_type, actor, detail or {},
                change_id=change_id, extra=extra,
            )
            return nhi

    def _move(
        self,
        nhi: Dict[str, Any],
        target: LifecycleStage,
        event_type: str,
        actor: str,
        detail: Dict[str, Any],
        *,
        change_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        current = LifecycleStage(snapshot(nhi)["lifecycle_stage"])
        if target not in STAGE_TRANSITIONS[current]:
            raise LifecycleError(
                f"허용되지 않은 생명주기 전이입니다: {current.value} -> {target.value}"
            )
        detail = dict(detail)
        if extra and "lifecycle_stage" in extra:
            raise LifecycleError("extra로 생명주기 상태를 변경할 수 없습니다.")
        if target is LifecycleStage.DECOMMISSIONED:
            raw = detail.get("destruction_evidence")
            if not isinstance(raw, dict) or not raw:
                raise LifecycleError("폐기 완료 전환에는 파기 증적(destruction_evidence)이 필수입니다.")
            try:
                evidence = DestructionEvidence.from_dict(raw)
                evidence.validate()
            except ValueError as exc:
                raise LifecycleError(str(exc)) from exc
            previous = self.storage.list_lifecycle_events(nhi_id=nhi["nhi_id"], limit=1)
            previous_id = previous[0]["event_id"] if previous else None
            detail.update(
                destruction_evidence=evidence.to_dict(),
                previous_event_id=previous_id,
                evidence_digest=evidence_digest(evidence.to_dict(), previous_id),
            )
        moment = utcnow()
        nhi["lifecycle_stage"] = target.value
        nhi["stage_entered_at"] = moment
        if target is LifecycleStage.DEACTIVATED:
            nhi["terminated_at"] = moment
        elif target is LifecycleStage.DECOMMISSIONED:
            nhi["disposed_at"] = moment
        elif target is LifecycleStage.ACTIVE:
            nhi.pop("terminated_at", None)
        nhi.update(extra or {})
        save_nhi(self.storage, nhi)
        self._log(
            nhi, target, event_type, actor, {**detail, "from": current.value},
            change_id=change_id, at=moment,
        )

    def record(
        self,
        nhi: Dict[str, Any],
        event_type: str,
        actor: str,
        detail: Dict[str, Any],
        *,
        change_id: Optional[str] = None,
    ) -> None:
        """단계 이동 없이 현재 단계에 이벤트만 남긴다 (교체, 격리, 롤백 등)."""
        stage = LifecycleStage(snapshot(nhi)["lifecycle_stage"])
        self._log(nhi, stage, event_type, actor, detail, change_id=change_id)

    def _log(
        self,
        nhi: Dict[str, Any],
        stage: LifecycleStage,
        event_type: str,
        actor: str,
        detail: Dict[str, Any],
        *,
        change_id: Optional[str] = None,
        at: Optional[str] = None,
    ) -> None:
        event = LifecycleEvent(
            nhi_id=nhi["nhi_id"],
            stage=stage.value,
            event_type=event_type,
            actor=actor,
            detail=detail,
            change_id=change_id,
            demo_workspace=is_demo(nhi),
        )
        if at:
            event.occurred_at = at
        self.storage.append_lifecycle_event(event)
        self.storage.append_audit_event(
            "NHI_LIFECYCLE_EVENT", actor=actor, target=nhi["nhi_id"],
            detail={
                "event_id": event.event_id, "stage": stage.value,
                "event_type": event_type, "change_id": change_id,
                "evidence_digest": detail.get("evidence_digest"),
            },
        )

    # ------------------------------------------------------------------
    # 조회
    # ------------------------------------------------------------------
    def timeline(self, nhi_id: str, *, limit: int = 200) -> List[Dict[str, Any]]:
        events = self.storage.list_lifecycle_events(nhi_id=nhi_id, limit=limit)
        return list(reversed(events))  # 오래된 순

    def view(self, nhi_id: str, *, now: Optional[datetime] = None) -> Dict[str, Any]:
        nhi = load_nhi(self.storage, nhi_id)
        pending = self.storage.list_change_requests(
            status=ChangeStatus.PENDING_APPROVAL, nhi_id=nhi_id, limit=50
        )
        item = self._describe(nhi, now or datetime.now(timezone.utc), len(pending))
        item["timeline"] = self.timeline(nhi_id)
        item["pending_changes"] = [change.to_dict() for change in pending]
        return item

    def report(self, *, now: Optional[datetime] = None) -> Dict[str, Any]:
        moment = now or datetime.now(timezone.utc)
        pending_by_nhi: Dict[str, int] = {}
        for change in self.storage.list_change_requests(
            status=ChangeStatus.PENDING_APPROVAL, limit=500
        ):
            pending_by_nhi[change.nhi_id] = pending_by_nhi.get(change.nhi_id, 0) + 1

        items = [
            self._describe(nhi, moment, pending_by_nhi.get(nhi["nhi_id"], 0))
            for nhi in self.storage.list_nhi_records(limit=500)
        ]
        stages = []
        for stage in LifecycleStage:
            members = [item for item in items if item["stage"] == stage.value]
            stages.append(
                {
                    "stage": stage.value,
                    "label": STAGE_LABELS[stage],
                    "count": len(members),
                    "nhi_ids": [item["nhi_id"] for item in members],
                }
            )
        alerts = [
            {**flag, "nhi_id": item["nhi_id"], "nhi_name": item["nhi_name"]}
            for item in items
            for flag in item["aging"]
        ]
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts.sort(key=lambda alert: severity_rank.get(alert["severity"], 9))
        return {
            "stages": stages,
            "items": items,
            "alerts": alerts,
            "total": len(items),
            "policy": {
                "retention_days": self.settings.retention_days,
                "stale_days": self.settings.stale_days,
                "rotation_days": self.settings.rotation_days,
                "expiry_warning_days": self.settings.expiry_warning_days,
                "permission_observation_days": self.settings.permission_observation_days,
                "rotation_grace_hours": self.settings.rotation_grace_hours,
            },
        }

    # ------------------------------------------------------------------
    # 노후화 판정
    # ------------------------------------------------------------------
    def _describe(
        self, nhi: Dict[str, Any], now: datetime, pending_changes: int
    ) -> Dict[str, Any]:
        state = snapshot(nhi)
        stage = LifecycleStage(state["lifecycle_stage"])
        entered = nhi.get("stage_entered_at") or nhi.get("first_seen_at")
        aging = self._aging_flags(nhi, state, stage, now)
        return {
            "nhi_id": nhi["nhi_id"],
            "nhi_name": nhi.get("nhi_name"),
            "nhi_type": nhi.get("nhi_type"),
            "provider": nhi.get("provider"),
            "owner": nhi.get("owner"),
            "environment": nhi.get("environment"),
            "risk_level": nhi.get("risk_level"),
            "demo_workspace": bool(nhi.get("demo_workspace")),
            "stage": stage.value,
            "stage_label": STAGE_LABELS[stage],
            "stage_entered_at": entered,
            "days_in_stage": days_between(entered, now),
            "age_days": days_between(
                nhi.get("created_at") or nhi.get("first_seen_at"), now
            ),
            "days_since_last_use": days_between(nhi.get("last_used_at"), now),
            "days_since_rotation": days_between(nhi.get("last_rotated_at"), now),
            "expires_at": nhi.get("expires_at"),
            "credential_state": state["credential_state"],
            "control_state": state["control_state"],
            "credential_version": state["credential_version"],
            "permissions": state["permissions"],
            "allowed_next_stages": sorted(
                target.value for target in STAGE_TRANSITIONS[stage]
            ),
            "manual_advance_to": (
                _MANUAL_ADVANCE[stage].value if stage in _MANUAL_ADVANCE else None
            ),
            "pending_change_count": pending_changes,
            "aging": aging,
            "next_step": aging[0]["message"] if aging else self._default_next_step(stage),
        }

    def _aging_flags(
        self,
        nhi: Dict[str, Any],
        state: Dict[str, Any],
        stage: LifecycleStage,
        now: datetime,
    ) -> List[Dict[str, str]]:
        cfg = self.settings
        flags: List[Dict[str, str]] = []
        in_stage = days_between(nhi.get("stage_entered_at") or nhi.get("first_seen_at"), now)
        unused = days_between(nhi.get("last_used_at"), now)
        rotated = days_between(
            nhi.get("last_rotated_at") or nhi.get("created_at") or nhi.get("first_seen_at"),
            now,
        )

        if stage is LifecycleStage.DECOMMISSIONED:
            return flags
        if state["control_state"] == ControlState.QUARANTINED.value:
            flags.append(_flag(
                "QUARANTINED", "HIGH",
                "실시간 통제로 격리됨 — 원인 확인 후 폐기 또는 격리 해제를 결정하세요.",
            ))
        if stage is LifecycleStage.DEACTIVATED:
            if in_stage is not None and in_stage >= cfg.retention_days:
                flags.append(_flag(
                    "DISPOSAL_DUE", "HIGH",
                    f"종료 후 {in_stage}일 경과(보존 {cfg.retention_days}일) — 파기 승인을 요청하세요.",
                ))
            return flags
        if not nhi.get("owner"):
            flags.append(_flag("OWNERLESS", "HIGH", "Owner 가 없습니다. 책임자를 지정하세요."))
        if stage is LifecycleStage.REGISTERED and in_stage is not None and in_stage >= 7:
            flags.append(_flag(
                "CREATION_STALLED", "MEDIUM",
                f"생성 후 {in_stage}일째 활성화되지 않았습니다. Owner 지정 후 활성화하거나 종료하세요.",
            ))
        expires = parse_dt(nhi.get("expires_at"))
        if expires is not None:
            remaining = (expires - now).days
            if remaining < 0:
                flags.append(_flag(
                    "EXPIRED", "HIGH", f"만료일이 {-remaining}일 지났습니다. 교체 또는 종료하세요."
                ))
            elif remaining <= cfg.expiry_warning_days:
                flags.append(_flag(
                    "EXPIRING_SOON", "MEDIUM", f"만료까지 {remaining}일 — 교체를 준비하세요."
                ))
        if unused is not None and unused >= cfg.stale_days:
            flags.append(_flag(
                "STALE_UNUSED", "MEDIUM",
                f"{unused}일간 사용 기록이 없습니다. 종료(폐기)를 검토하세요.",
            ))
        if rotated is not None and rotated >= cfg.rotation_days:
            flags.append(_flag(
                "ROTATION_OVERDUE", "MEDIUM",
                f"마지막 교체 후 {rotated}일 경과(기준 {cfg.rotation_days}일) — Token 교체를 요청하세요.",
            ))
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        flags.sort(key=lambda flag: severity_rank.get(flag["severity"], 9))
        return flags

    @staticmethod
    def _default_next_step(stage: LifecycleStage) -> str:
        return {
            LifecycleStage.REGISTERED: "Owner 지정 후 활성화하세요.",
            LifecycleStage.ACTIVE: "정상 — 정기 점검 대상입니다.",
            LifecycleStage.DEACTIVATED: "보존 기간 동안 유지한 뒤 파기하세요.",
            LifecycleStage.DECOMMISSIONED: "파기 완료 — Secret material 이 제거되었습니다.",
        }[stage]
