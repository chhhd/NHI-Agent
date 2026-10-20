"""변경 승인 서비스 — 영향도 미리보기 · 중요도별 승인 · 적용 · 롤백.

Token 폐기/교체/권한 변경은 서비스 중단을 일으킬 수 있으므로 적용 전에

    1. 변경 전·후 형상(permissions, scopes, 상태, 버전)과 영향 범위를 계산해 보여 주고
    2. 권한 중요도에 따라 승인 등급(LOW~CRITICAL)을 정하고
    3. 관리자가 승인한 뒤에만 적용하며
    4. 적용 후에도 서비스 연속성을 위해 변경 전 형상으로 롤백할 수 있게 한다.

승인 등급별 규칙
    LOW       자동 승인 (미리보기와 감사 기록은 남는다)
    MEDIUM    관리자 승인
    HIGH      요청자와 다른 관리자의 승인 (직무 분리)
    CRITICAL  직무 분리 + 영향도 확인(acknowledge_impact) 필수

실행기(`ChangeExecutor`)는 Provider 연동 지점이다. 기본 구현은 NHI 인벤토리 상태만
바꾸고 외부 Provider 를 호출하지 않는다 — 실제 Token 폐기는 GitHub/Slack 어댑터를
연결해야 일어난다.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol

from backend.services.lifecycle_service import LifecycleError, LifecycleService
from backend.services.nhi_state import (
    GOVERNANCE_LOCK,
    is_demo,
    load_nhi,
    load_nhi_with_credentials,
    parse_dt,
    save_nhi,
    snapshot,
)
from core.config import GovernanceSettings, get_settings
from core.destruction_models import DestructionEvidence, evidence_digest
from core.governance_models import (
    ApprovalTier,
    ChangeRequest,
    ChangeStatus,
    ChangeType,
    ControlState,
    CredentialState,
    LifecycleStage,
    utcnow,
)
from storage.base import Storage

logger = logging.getLogger(__name__)

PERMISSION_RANK = {"READ": 1, "WRITE": 2, "DELETE": 3, "ADMIN": 4}
_NON_PRODUCTION = {"development", "staging", "test"}
_TIER_ORDER = [ApprovalTier.LOW, ApprovalTier.MEDIUM, ApprovalTier.HIGH, ApprovalTier.CRITICAL]

#: 등급별로 승인할 수 있는 역할(개인 키로 신원이 확정된 승인자에만 적용된다).
#: CRITICAL 은 보안 담당자(SECURITY)만 승인할 수 있다.
_APPROVER_ROLES = {
    ApprovalTier.MEDIUM: frozenset({"ADMIN", "SECURITY"}),
    ApprovalTier.HIGH: frozenset({"ADMIN", "SECURITY"}),
    ApprovalTier.CRITICAL: frozenset({"SECURITY"}),
}

#: 변경 유형별로 "충돌 여부"를 판단할 때 비교하는 형상 필드.
_RELEVANT_FIELDS = {
    ChangeType.TOKEN_REVOKE: ("lifecycle_stage", "credential_state"),
    ChangeType.TOKEN_ROTATE: ("credential_version",),
    ChangeType.SCOPE_CHANGE: ("permissions", "raw_scopes", "lifecycle_stage"),
    ChangeType.TOKEN_DISPOSE: ("lifecycle_stage", "credential_state"),
    ChangeType.QUARANTINE: ("control_state",),
}

#: 롤백 시 되돌려야 하는 부가 필드 (제안 시점 값을 `rollback.restore` 에 보관한다).
#: 변경이 건드리지 않는 필드는 담지 않아 이후 다른 변경을 덮어쓰지 않는다.
_RESTORE_META = {
    ChangeType.TOKEN_REVOKE: ("stage_entered_at", "terminated_at"),
    ChangeType.TOKEN_ROTATE: ("last_rotated_at", "previous_credential_expires_at"),
    ChangeType.SCOPE_CHANGE: ("stage_entered_at",),
    ChangeType.TOKEN_DISPOSE: (),
    ChangeType.QUARANTINE: (),
}

_CHANGE_LABELS = {
    ChangeType.TOKEN_REVOKE: "Token 폐기",
    ChangeType.TOKEN_ROTATE: "Token 교체",
    ChangeType.SCOPE_CHANGE: "권한 변경",
    ChangeType.TOKEN_DISPOSE: "Token 파기",
    ChangeType.QUARANTINE: "실시간 통제 격리",
}


class ChangeError(ValueError):
    """변경 요청이 현재 정책·상태에서 허용되지 않는다 (HTTP 409/422 에 대응)."""


class ChangeNotAllowed(ChangeError):
    """요청 내용 자체가 잘못되었다 (HTTP 422)."""


class StateConflict(ChangeError):
    """대상 상태가 제안 시점과 달라졌거나 이미 처리되었다 (HTTP 409)."""


class SeparationOfDutiesError(ChangeError):
    """요청자와 승인자가 같다 (HTTP 403)."""


class ApproverNotAuthorized(ChangeError):
    """승인자의 역할이 이 변경 등급을 승인하기에 부족하다 (HTTP 403)."""


class ChangeExecutionError(ChangeError):
    """실행기(Provider 연동)가 변경을 적용하지 못했다 (HTTP 502)."""


class ChangeExecutor(Protocol):
    """Provider 연동 지점 — 실제 Token 폐기/교체/권한 변경을 수행한다."""

    name: str

    def apply(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def rollback(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        ...


class InventoryStateExecutor:
    """기본 실행기 — 인벤토리 상태만 바꾸고 외부 Provider 는 호출하지 않는다."""

    name = "inventory-state"

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def apply(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {"executor": self.name, "provider_call": "not_configured"}
        if change.change_type is ChangeType.TOKEN_DISPOSE:
            destroyed = 0
            record = load_nhi_with_credentials(self.storage, nhi["nhi_id"])
            for credential in record.get("credentials", []):
                for secret_id in self.storage.list_encrypted_secret_ids(
                    credential["fingerprint"]
                ):
                    self.storage.delete_encrypted_secret(secret_id)
                    self.storage.append_audit_event(
                        "SECRET_DESTROYED",
                        actor=change.approved_by or "change-control",
                        target=secret_id,
                        detail={"change_id": change.change_id, "nhi_id": nhi["nhi_id"]},
                    )
                    destroyed += 1
            result["secret_material_destroyed"] = destroyed
        return result

    def rollback(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        return {"executor": self.name, "provider_call": "not_configured"}


class ChangeControlService:
    def __init__(
        self,
        storage: Storage,
        *,
        executor: Optional[ChangeExecutor] = None,
        lifecycle: Optional[LifecycleService] = None,
        settings: Optional[GovernanceSettings] = None,
    ) -> None:
        self.storage = storage
        self.settings = settings or get_settings().governance
        self.executor = executor or InventoryStateExecutor(storage)
        self.lifecycle = lifecycle or LifecycleService(storage, self.settings)

    # ------------------------------------------------------------------
    # 미리보기
    # ------------------------------------------------------------------
    def preview(
        self, nhi_id: str, change_type: ChangeType, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """저장 없이 변경 전·후 형상, 영향도, 승인 등급, 롤백 계획을 계산한다."""
        nhi = load_nhi(self.storage, nhi_id)
        return self._plan(nhi, change_type, dict(params or {}))

    # ------------------------------------------------------------------
    # 제안
    # ------------------------------------------------------------------
    def propose(
        self,
        nhi_id: str,
        change_type: ChangeType,
        *,
        requested_by: str,
        reason: str = "",
        params: Optional[Dict[str, Any]] = None,
        source: str = "operator",
        requested_verified: bool = False,
        force_approval: bool = False,
    ) -> ChangeRequest:
        """변경을 제안한다.

        ``force_approval`` 은 LOW 등급이어도 자동 승인하지 않고 사람의 승인을 요구한다.
        aging 정책처럼 시스템이 스스로 만든 종료·파기 제안이 사람 없이 적용되지 않게 한다.
        """
        with GOVERNANCE_LOCK:
            nhi = load_nhi(self.storage, nhi_id)
            plan = self._plan(nhi, change_type, dict(params or {}))
            if force_approval and not plan["approval"]["required"]:
                plan["approval"] = {
                    "required": True,
                    "tier": plan["tier"],
                    "separation_of_duties": False,
                    "impact_acknowledgement_required": False,
                    "reasons": list(plan["approval"].get("reasons", []))
                    + ["정책이 자동 제안한 변경은 등급과 무관하게 사람이 승인합니다."],
                }
            for existing in self.storage.list_change_requests(
                status=ChangeStatus.PENDING_APPROVAL, nhi_id=nhi_id, limit=100
            ):
                if existing.change_type is change_type:
                    raise StateConflict(
                        f"같은 NHI 에 대기 중인 {_CHANGE_LABELS[change_type]} 요청이 이미 있습니다 "
                        f"({existing.change_id})."
                    )
            change = ChangeRequest(
                nhi_id=nhi_id,
                nhi_name=nhi.get("nhi_name") or nhi_id,
                change_type=change_type,
                requested_by=requested_by,
                requested_by_verified=requested_verified,
                reason=reason,
                tier=ApprovalTier(plan["tier"]),
                approval=plan["approval"],
                params=plan["params"],
                before=plan["before"],
                after=plan["after"],
                impact=plan["impact"],
                rollback=plan["rollback"],
                source=source,
                demo_workspace=is_demo(nhi),
            )
            self.storage.save_change_request(change)
            self._audit("CHANGE_PROPOSED", requested_by, change, {"tier": change.tier.value})
            if not plan["approval"]["required"]:
                return self._approve_and_apply(
                    change,
                    actor=plan["approval"]["auto_actor"],
                    reason=plan["approval"]["auto_reason"],
                    acknowledged=True,
                )
            return change

    # ------------------------------------------------------------------
    # 승인 / 거부
    # ------------------------------------------------------------------
    def approve(
        self,
        change_id: str,
        *,
        actor: str,
        reason: str = "",
        acknowledge_impact: bool = False,
        verified: bool = False,
        roles: Optional[Iterable[str]] = None,
        destruction_evidence: Optional[Dict[str, Any]] = None,
    ) -> ChangeRequest:
        """승인하고 적용한다.

        ``verified``/``roles`` 는 개인 키로 신원이 확정된 승인자의 값이다. ``roles`` 가 주어지면
        등급별 필요 역할(CRITICAL=SECURITY)을 강제한다. 주어지지 않으면(공유 키) 역할을 확인할
        수 없으므로 검사를 건너뛰고 ``approved_by_verified=false`` 로 기록한다.
        """
        with GOVERNANCE_LOCK:
            change = self._required(change_id)
            if change.status is not ChangeStatus.PENDING_APPROVAL:
                raise StateConflict(f"승인 대기 상태가 아닙니다: {change.status.value}")
            if roles is not None:
                needed = _APPROVER_ROLES.get(change.tier)
                if needed and not (set(roles) & needed):
                    raise ApproverNotAuthorized(
                        f"{change.tier.value} 등급 변경은 {'/'.join(sorted(needed))} 역할의 "
                        f"관리자만 승인할 수 있습니다 (승인자 역할: {', '.join(sorted(roles)) or '없음'})."
                    )
            approval = change.approval
            if approval["separation_of_duties"] and actor == change.requested_by:
                raise SeparationOfDutiesError(
                    f"{change.tier.value} 등급 변경은 요청자({change.requested_by})와 "
                    "다른 관리자가 승인해야 합니다."
                )
            if approval["impact_acknowledgement_required"] and not acknowledge_impact:
                raise ChangeNotAllowed(
                    "CRITICAL 등급 변경은 변경 전·후 형상과 영향도를 확인했음을 "
                    "(acknowledge_impact=true) 명시해야 승인할 수 있습니다."
                )
            if change.change_type is ChangeType.TOKEN_DISPOSE:
                evidence = self._destruction_evidence(actor, destruction_evidence)
                change.params = {**change.params, "destruction_evidence": evidence}
            return self._approve_and_apply(
                change,
                actor=actor,
                reason=reason,
                acknowledged=acknowledge_impact,
                verified=verified,
            )

    def reject(self, change_id: str, *, actor: str, reason: str = "") -> ChangeRequest:
        with GOVERNANCE_LOCK:
            change = self._required(change_id)
            if change.status is not ChangeStatus.PENDING_APPROVAL:
                raise StateConflict(f"승인 대기 상태가 아닙니다: {change.status.value}")
            change.status = ChangeStatus.REJECTED
            change.decision_reason = reason
            change.approved_by = None
            change.updated_at = utcnow()
            self.storage.save_change_request(change)
            self._audit("CHANGE_REJECTED", actor, change, {"reason": reason})
            return change

    def _approve_and_apply(
        self,
        change: ChangeRequest,
        *,
        actor: str,
        reason: str,
        acknowledged: bool,
        verified: bool = False,
    ) -> ChangeRequest:
        nhi = load_nhi(self.storage, change.nhi_id)
        drift = self._drift(nhi, change.change_type, change.before)
        if drift:
            raise StateConflict(
                "대상 NHI 의 현재 형상이 제안 시점과 달라졌습니다 "
                f"({', '.join(drift)}). 요청을 거부하고 다시 제안하세요."
            )
        change.approved_by = actor
        change.approved_by_verified = bool(verified)
        change.approved_at = utcnow()
        change.decision_reason = reason
        change.impact_acknowledged = bool(acknowledged)
        try:
            change.apply_result = self._apply(change, nhi, actor)
        except ChangeExecutionError as exc:
            change.status = ChangeStatus.FAILED
            change.apply_result = {"error": str(exc)}
            change.updated_at = utcnow()
            self.storage.save_change_request(change)
            self._audit("CHANGE_FAILED", actor, change, {"error": str(exc)})
            raise
        except LifecycleError as exc:
            raise StateConflict(str(exc)) from exc
        change.status = ChangeStatus.APPLIED
        change.applied_at = utcnow()
        change.updated_at = change.applied_at
        change.rollback_expires_at = self._rollback_deadline(change)
        self.storage.save_change_request(change)
        self._audit(
            "CHANGE_APPLIED", actor, change,
            {
                "tier": change.tier.value,
                "change_type": change.change_type.value,
                "approver_verified": change.approved_by_verified,
                "requester_verified": change.requested_by_verified,
            },
        )
        return change

    # ------------------------------------------------------------------
    # 롤백
    # ------------------------------------------------------------------
    def rollback(self, change_id: str, *, actor: str, reason: str = "") -> ChangeRequest:
        with GOVERNANCE_LOCK:
            change = self._required(change_id)
            if change.status is not ChangeStatus.APPLIED:
                raise StateConflict(f"적용된 변경만 롤백할 수 있습니다: {change.status.value}")
            if not change.rollback.get("supported"):
                raise ChangeNotAllowed(
                    change.rollback.get("unsupported_reason") or "롤백할 수 없는 변경입니다."
                )
            deadline = parse_dt(change.rollback_expires_at)
            if deadline is not None and datetime.now(timezone.utc) > deadline:
                raise StateConflict(
                    f"롤백 가능 시간이 지났습니다 ({change.rollback_expires_at})."
                )
            nhi = load_nhi(self.storage, change.nhi_id)
            drift = self._drift(nhi, change.change_type, change.after)
            if drift:
                raise StateConflict(
                    "적용 이후 대상 NHI 에 다른 변경이 있어 롤백하면 그 변경을 덮어씁니다 "
                    f"({', '.join(drift)}). 최신 상태를 확인한 뒤 새 변경으로 처리하세요."
                )
            result = self.executor.rollback(change, nhi)
            self._restore(nhi, change)
            save_nhi(self.storage, nhi)
            self.lifecycle.record(
                nhi, "CHANGE_ROLLED_BACK", actor,
                {"change_type": change.change_type.value, "reason": reason},
                change_id=change.change_id,
            )
            change.status = ChangeStatus.ROLLED_BACK
            change.rolled_back_by = actor
            change.rolled_back_at = utcnow()
            change.rollback_reason = reason
            change.apply_result = {**(change.apply_result or {}), "rollback": result}
            change.updated_at = change.rolled_back_at
            self.storage.save_change_request(change)
            self._audit("CHANGE_ROLLED_BACK", actor, change, {"reason": reason})
            return change

    def release_quarantine(self, nhi_id: str, *, actor: str, reason: str = "") -> ChangeRequest:
        """가장 최근에 적용된 격리를 해제한다 (격리의 롤백)."""
        with GOVERNANCE_LOCK:
            for change in self.storage.list_change_requests(
                status=ChangeStatus.APPLIED, nhi_id=nhi_id, limit=100
            ):
                if change.change_type is ChangeType.QUARANTINE:
                    return self.rollback(change.change_id, actor=actor, reason=reason)
            raise StateConflict("해제할 격리가 없습니다.")

    # ------------------------------------------------------------------
    # 조회
    # ------------------------------------------------------------------
    def get(self, change_id: str) -> ChangeRequest:
        return self._required(change_id)

    def list(
        self,
        *,
        status: Optional[ChangeStatus] = None,
        nhi_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ChangeRequest]:
        return self.storage.list_change_requests(status=status, nhi_id=nhi_id, limit=limit)

    # ------------------------------------------------------------------
    # 적용 / 복원
    # ------------------------------------------------------------------
    def _apply(self, change: ChangeRequest, nhi: Dict[str, Any], actor: str) -> Dict[str, Any]:
        # 저장된 이전 요청과 내부 호출도 실행기에 도달하기 전에 증적을 검증한다.
        if change.change_type is ChangeType.TOKEN_DISPOSE:
            change.params["destruction_evidence"] = self._destruction_evidence(
                actor, change.params.get("destruction_evidence")
            )
        try:
            result = self.executor.apply(change, nhi)
        except ChangeExecutionError:
            raise
        except Exception as exc:  # 실행기 어댑터의 어떤 실패도 FAILED 로 수렴시킨다
            logger.exception("변경 실행기 오류 change=%s", change.change_id)
            raise ChangeExecutionError(f"실행기 오류: {exc}") from exc

        after = change.after
        kind = change.change_type
        common = {"change_id": change.change_id}
        if kind is ChangeType.TOKEN_REVOKE:
            nhi = self.lifecycle.transition(
                nhi["nhi_id"], LifecycleStage.DEACTIVATED,
                event_type="TOKEN_REVOKED", actor=actor,
                detail={"reason": change.reason}, change_id=change.change_id,
                extra={"credential_state": CredentialState.REVOKED.value},
            )
        elif kind is ChangeType.TOKEN_DISPOSE:
            detail = {"reason": change.reason, **result}
            evidence = change.params.get("destruction_evidence")
            if evidence:
                previous = self.storage.list_lifecycle_events(nhi_id=nhi["nhi_id"], limit=1)
                previous_id = previous[0]["event_id"] if previous else None
                detail.update(
                    destruction_evidence=evidence,
                    previous_event_id=previous_id,
                    evidence_digest=evidence_digest(evidence, previous_id),
                )
            nhi = self.lifecycle.transition(
                nhi["nhi_id"], LifecycleStage.DECOMMISSIONED,
                event_type="TOKEN_DISPOSED", actor=actor,
                detail=detail, change_id=change.change_id,
                extra={
                    "credential_state": CredentialState.DISPOSED.value,
                    "permissions": [],
                    "raw_scopes": [],
                },
            )
        elif kind is ChangeType.SCOPE_CHANGE:
            nhi.update(permissions=after["permissions"], raw_scopes=after["raw_scopes"])
            save_nhi(self.storage, nhi)
            self.lifecycle.record(
                nhi, "PERMISSION_CHANGE", actor,
                {
                    "reason": change.reason,
                    "removed": change.impact["diff"]["permissions"]["removed"],
                    "added": change.impact["diff"]["permissions"]["added"],
                },
                change_id=change.change_id,
            )
        elif kind is ChangeType.TOKEN_ROTATE:
            moment = utcnow()
            grace = int(change.params.get("grace_period_hours", 0))
            nhi["credential_version"] = after["credential_version"]
            nhi["last_rotated_at"] = moment
            if grace:
                nhi["previous_credential_expires_at"] = (
                    datetime.now(timezone.utc) + timedelta(hours=grace)
                ).isoformat()
            save_nhi(self.storage, nhi)
            self.lifecycle.record(
                nhi, "TOKEN_ROTATED", actor,
                {"version": after["credential_version"], "grace_period_hours": grace},
                change_id=change.change_id,
            )
        elif kind is ChangeType.QUARANTINE:
            nhi["control_state"] = ControlState.QUARANTINED.value
            save_nhi(self.storage, nhi)
            self.lifecycle.record(
                nhi, "QUARANTINED", actor, {"reason": change.reason}, change_id=change.change_id
            )
        return {**common, **result}

    @staticmethod
    def _destruction_evidence(actor: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """파기는 증적이 있어야만 승인된다. 수행자 기본값은 승인자이며 검증자는 반드시 달라야 한다."""
        if not raw:
            raise ChangeNotAllowed(
                "파기 승인에는 파기 증적(destruction_evidence)이 필요합니다: 방법, 수행자와 다른 "
                "검증자, 검증 방법, 인증 거부 확인 결과."
            )
        try:
            evidence = DestructionEvidence.from_dict(raw, default_performer=actor)
            evidence.validate()
        except ValueError as exc:
            raise ChangeNotAllowed(str(exc)) from exc
        return evidence.to_dict()

    def _restore(self, nhi: Dict[str, Any], change: ChangeRequest) -> None:
        before = change.before
        for name in _RELEVANT_FIELDS[change.change_type]:
            nhi[name] = before[name]
        for name, value in (change.rollback.get("restore") or {}).items():
            if value is None:
                nhi.pop(name, None)
            else:
                nhi[name] = value
        if change.change_type is ChangeType.TOKEN_DISPOSE:  # 방어: 계획 단계에서 막혀 있다
            raise ChangeNotAllowed("파기는 롤백할 수 없습니다.")

    def _rollback_deadline(self, change: ChangeRequest) -> Optional[str]:
        window = change.rollback.get("window_hours")
        if not change.rollback.get("supported") or not window:
            return None
        return (datetime.now(timezone.utc) + timedelta(hours=int(window))).isoformat()

    @staticmethod
    def _drift(nhi: Dict[str, Any], kind: ChangeType, expected: Dict[str, Any]) -> List[str]:
        current = snapshot(nhi)
        return [
            name for name in _RELEVANT_FIELDS[kind] if current[name] != expected.get(name)
        ]

    # ------------------------------------------------------------------
    # 계획 (영향도 · 승인 등급 · 롤백)
    # ------------------------------------------------------------------
    def _plan(
        self, nhi: Dict[str, Any], kind: ChangeType, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        before = snapshot(nhi)
        stage = LifecycleStage(before["lifecycle_stage"])
        after = dict(before)
        restore = {name: nhi.get(name) for name in _RESTORE_META[kind]}
        grace = None

        if before["credential_state"] == CredentialState.DISPOSED.value:
            raise ChangeNotAllowed("이미 파기된 NHI 입니다.")

        if kind is ChangeType.TOKEN_REVOKE:
            if stage in (LifecycleStage.DEACTIVATED, LifecycleStage.DECOMMISSIONED):
                raise ChangeNotAllowed("이미 종료된 NHI 입니다.")
            after.update(
                lifecycle_stage=LifecycleStage.DEACTIVATED.value,
                credential_state=CredentialState.REVOKED.value,
            )
        elif kind is ChangeType.TOKEN_ROTATE:
            if stage in (LifecycleStage.DEACTIVATED, LifecycleStage.DECOMMISSIONED):
                raise ChangeNotAllowed("종료된 NHI 의 Token 은 교체할 수 없습니다.")
            grace = int(params.get("grace_period_hours", self.settings.rotation_grace_hours))
            if grace < 0 or grace > 24 * 14:
                raise ChangeNotAllowed("grace_period_hours 는 0~336 사이여야 합니다.")
            params["grace_period_hours"] = grace
            after["credential_version"] = before["credential_version"] + 1
        elif kind is ChangeType.SCOPE_CHANGE:
            if stage is not LifecycleStage.ACTIVE:
                raise ChangeNotAllowed("사용 중인 NHI 만 권한을 변경할 수 있습니다.")
            target = params.get("target_permissions")
            if not isinstance(target, list) or any(
                str(item).upper() not in PERMISSION_RANK for item in target
            ):
                raise ChangeNotAllowed(
                    "target_permissions 는 READ/WRITE/DELETE/ADMIN 의 목록이어야 합니다."
                )
            target = sorted({str(item).upper() for item in target}, key=PERMISSION_RANK.get)
            params["target_permissions"] = target
            after["permissions"] = target
            if params.get("target_scopes") is not None:
                if not isinstance(params["target_scopes"], list):
                    raise ChangeNotAllowed("target_scopes 는 목록이어야 합니다.")
                after["raw_scopes"] = [str(item) for item in params["target_scopes"]]
            if after["permissions"] == before["permissions"] and (
                after["raw_scopes"] == before["raw_scopes"]
            ):
                raise ChangeNotAllowed("현재 권한과 동일한 변경입니다.")
        elif kind is ChangeType.TOKEN_DISPOSE:
            if stage is not LifecycleStage.DEACTIVATED:
                raise ChangeNotAllowed(
                    "파기는 종료(폐기)된 NHI 에만 요청할 수 있습니다. 먼저 Token 폐기를 진행하세요."
                )
            after.update(
                lifecycle_stage=LifecycleStage.DECOMMISSIONED.value,
                credential_state=CredentialState.DISPOSED.value,
                permissions=[],
                raw_scopes=[],
            )
        elif kind is ChangeType.QUARANTINE:
            if before["control_state"] == ControlState.QUARANTINED.value:
                raise ChangeNotAllowed("이미 격리된 NHI 입니다.")
            if stage in (LifecycleStage.DEACTIVATED, LifecycleStage.DECOMMISSIONED):
                raise ChangeNotAllowed("종료된 NHI 는 격리할 필요가 없습니다.")
            after["control_state"] = ControlState.QUARANTINED.value

        impact = self._impact(nhi, kind, before, after, params)
        tier = self._tier(nhi, kind, before, impact)
        rollback = self._rollback_plan(kind, grace, restore)
        approval = self._approval(kind, tier, impact)
        return {
            "nhi_id": nhi["nhi_id"],
            "nhi_name": nhi.get("nhi_name"),
            "change_type": kind.value,
            "label": _CHANGE_LABELS[kind],
            "params": params,
            "before": before,
            "after": after,
            "impact": impact,
            "tier": tier.value,
            "approval": approval,
            "rollback": rollback,
        }

    @staticmethod
    def _highest(permissions: List[str]) -> int:
        return max((PERMISSION_RANK.get(item, 1) for item in permissions), default=0)

    def _tier(
        self, nhi: Dict[str, Any], kind: ChangeType, before: Dict[str, Any], impact: Dict[str, Any]
    ) -> ApprovalTier:
        """권한 중요도 → 승인 등급. 높은 쪽 규칙이 이긴다."""
        environment = str(nhi.get("environment") or "unknown").lower()
        production_like = environment not in _NON_PRODUCTION
        sensitive = str(nhi.get("data_sensitivity") or "").lower() in {
            "restricted", "confidential", "sensitive",
        } or bool((nhi.get("blast_radius") or {}).get("sensitive_data_access"))
        top = self._highest(before["permissions"])
        added = impact["diff"]["permissions"]["added"]

        writes = top >= PERMISSION_RANK["WRITE"]
        if top >= PERMISSION_RANK["DELETE"] or (production_like and writes and sensitive):
            tier = ApprovalTier.CRITICAL
        elif production_like and (writes or sensitive):
            tier = ApprovalTier.HIGH
        elif sensitive and writes:
            tier = ApprovalTier.HIGH
        elif production_like or writes or sensitive:
            tier = ApprovalTier.MEDIUM
        else:
            tier = ApprovalTier.LOW  # 비운영 · 읽기 전용 · 비민감
        if kind is ChangeType.TOKEN_DISPOSE:
            tier = max(tier, ApprovalTier.HIGH, key=_TIER_ORDER.index)  # 되돌릴 수 없다
        if added and self._highest(added) > top:  # 권한 상향은 한 단계 올려 심사한다
            tier = _TIER_ORDER[min(_TIER_ORDER.index(tier) + 1, len(_TIER_ORDER) - 1)]
        return tier

    @staticmethod
    def _approval(kind: ChangeType, tier: ApprovalTier, impact: Dict[str, Any]) -> Dict[str, Any]:
        reasons = [f"현재 권한·환경 기준 승인 등급 {tier.value}"]
        if kind is ChangeType.QUARANTINE:
            return {
                "required": False,
                "tier": tier.value,
                "separation_of_duties": False,
                "impact_acknowledgement_required": False,
                "auto_actor": "control-plane:containment",
                "auto_reason": "가역적 격리 — 승인 대기 중 피해가 커지지 않도록 즉시 적용",
                "reasons": reasons + ["격리는 언제든 해제(롤백)할 수 있어 승인 없이 즉시 적용됩니다."],
            }
        if tier is ApprovalTier.LOW:
            return {
                "required": False,
                "tier": tier.value,
                "separation_of_duties": False,
                "impact_acknowledgement_required": False,
                "auto_actor": "policy:auto-low",
                "auto_reason": "LOW 등급 — 정책에 의한 자동 승인",
                "reasons": reasons + ["읽기 전용·비운영·비민감 NHI 라 자동 승인됩니다."],
            }
        if impact["service_continuity"]["will_interrupt"]:
            reasons.append("적용 즉시 서비스 호출이 실패할 수 있어 승인이 필요합니다.")
        return {
            "required": True,
            "tier": tier.value,
            "separation_of_duties": tier in (ApprovalTier.HIGH, ApprovalTier.CRITICAL),
            "impact_acknowledgement_required": tier is ApprovalTier.CRITICAL,
            "reasons": reasons,
        }

    def _rollback_plan(
        self, kind: ChangeType, grace: Optional[int], restore: Dict[str, Any]
    ) -> Dict[str, Any]:
        base = {"restore": restore}
        if kind is ChangeType.TOKEN_DISPOSE:
            return {
                **base,
                "supported": False,
                "unsupported_reason": "파기는 Secret material 을 영구 삭제하므로 롤백할 수 없습니다.",
                "strategy": "없음 — 승인 전에 폐기(종료) 상태에서 충분히 관찰하세요.",
                "steps": [],
            }
        if kind is ChangeType.TOKEN_ROTATE:
            return {
                **base,
                "supported": bool(grace),
                "unsupported_reason": None if grace else "유예 시간이 0이라 이전 Token 이 즉시 무효화됩니다.",
                "window_hours": grace,
                "strategy": "유예 시간 안에 이전 Credential 버전으로 복귀",
                "steps": [
                    "새 Token 을 쓰는 소비자에서 장애가 확인되면 롤백을 실행합니다.",
                    "이전 버전 Credential 이 다시 현재 버전이 됩니다.",
                    "유예 시간이 지나면 이전 Token 은 폐기되어 롤백할 수 없습니다.",
                ],
            }
        steps = {
            ChangeType.TOKEN_REVOKE: [
                "NHI 를 종료 단계에서 사용 단계로 되돌립니다.",
                "인벤토리 상태가 복원됩니다. 실행기가 이미 Provider 에서 Token 을 폐기했다면 "
                "재발급 어댑터가 새 Token 을 발급해야 합니다.",
            ],
            ChangeType.SCOPE_CHANGE: [
                "변경 전 permissions / raw_scopes 로 복원합니다.",
                "생명주기 단계도 변경 이전 단계로 돌아갑니다.",
            ],
            ChangeType.QUARANTINE: ["격리를 해제하고 모든 사용 요청을 다시 허용합니다."],
        }[kind]
        return {
            **base,
            "supported": True,
            "unsupported_reason": None,
            "window_hours": None,
            "strategy": "변경 전 형상으로 복원 (파기 전까지 가능)",
            "steps": steps,
        }

    # ------------------------------------------------------------------
    # 영향도
    # ------------------------------------------------------------------
    def _impact(
        self,
        nhi: Dict[str, Any],
        kind: ChangeType,
        before: Dict[str, Any],
        after: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        environment = str(nhi.get("environment") or "unknown").lower()
        production_like = environment not in _NON_PRODUCTION
        blast = nhi.get("blast_radius") or {}
        resources = blast.get("accessible_resources", blast.get("accessible_resource_count", 0))
        services = list(blast.get("connected_services") or [])
        agent = nhi.get("linked_ai_agent")

        removed = [p for p in before["permissions"] if p not in after["permissions"]]
        added = [p for p in after["permissions"] if p not in before["permissions"]]
        scopes_removed = [s for s in before["raw_scopes"] if s not in after["raw_scopes"]]
        scopes_added = [s for s in after["raw_scopes"] if s not in before["raw_scopes"]]

        effective_before = before["permissions"] if (
            before["credential_state"] == CredentialState.ACTIVE.value
            and before["control_state"] == ControlState.NORMAL.value
        ) else []
        effective_after = after["permissions"] if (
            after["credential_state"] == CredentialState.ACTIVE.value
            and after["control_state"] == ControlState.NORMAL.value
        ) else []

        dependents = [agent] if agent else []
        notes: List[str] = []
        mitigations: List[str] = []
        security: List[str] = []
        will_interrupt = False
        risk = "LOW"

        def env_risk() -> str:
            return "HIGH" if production_like and (dependents or "WRITE" in before["permissions"]
                                                  or "ADMIN" in before["permissions"]) \
                else "MEDIUM" if production_like or environment == "staging" else "LOW"

        if kind is ChangeType.TOKEN_REVOKE:
            will_interrupt = True
            risk = env_risk()
            notes.append("적용 즉시 이 Token 으로 하는 모든 호출이 실패합니다.")
            if dependents:
                notes.append(f"연결된 AI Agent({', '.join(dependents)})가 중단됩니다.")
            if services:
                notes.append(f"영향 서비스: {', '.join(services)}")
            mitigations += [
                "대체 Token 으로 교체(TOKEN_ROTATE, 유예 시간 포함)한 뒤 폐기하면 중단 없이 전환할 수 있습니다.",
                "급하지 않다면 먼저 격리(QUARANTINE)로 영향을 확인하세요.",
                "폐기는 파기 전까지 롤백할 수 있습니다.",
            ]
            security.append("노출·오남용 가능한 자격 증명이 즉시 무력화됩니다.")
            if resources:
                security.append(f"접근 가능한 리소스 {resources}개에 대한 접근이 차단됩니다.")
        elif kind is ChangeType.TOKEN_ROTATE:
            grace = int(params.get("grace_period_hours", 0))
            will_interrupt = grace == 0
            risk = "HIGH" if grace == 0 and production_like else (
                "MEDIUM" if production_like else "LOW"
            )
            if grace:
                notes.append(
                    f"새 버전 v{after['credential_version']} 발급 후 {grace}시간 동안 "
                    f"이전 버전 v{before['credential_version']} 도 유효합니다."
                )
                notes.append("유예 시간 안에 모든 소비자가 새 Token 으로 전환해야 합니다.")
            else:
                notes.append("유예 시간이 없어 이전 Token 이 즉시 무효화됩니다.")
            if dependents:
                notes.append(f"새 Token 을 배포해야 하는 소비자: {', '.join(dependents)}")
            mitigations += [
                "소비자 배포가 끝날 때까지 유예 시간을 충분히 두세요.",
                "장애 시 유예 시간 안에는 롤백으로 이전 버전에 복귀할 수 있습니다.",
            ]
            security.append("노출 가능성이 있는 이전 Token 의 유효 기간이 제한됩니다.")
        elif kind is ChangeType.SCOPE_CHANGE:
            will_interrupt = bool(removed or scopes_removed)
            top_removed = self._highest(removed)
            risk = (
                "HIGH" if removed and production_like and top_removed >= PERMISSION_RANK["WRITE"]
                else "MEDIUM" if removed or scopes_removed else "LOW"
            )
            if removed:
                notes.append(f"제거되는 권한을 쓰던 호출은 실패합니다: {', '.join(removed)}")
            if scopes_removed:
                notes.append(f"제거되는 Scope: {', '.join(scopes_removed)}")
            if added or scopes_added:
                notes.append("⚠ 권한 상향 — 최소 권한 원칙에 어긋나는지 확인하세요.")
                security.append("권한이 늘어나 Blast Radius 가 커집니다.")
            if removed:
                security.append("불필요한 권한이 제거되어 Blast Radius 가 줄어듭니다.")
            if params.get("target_scopes") is None and removed:
                notes.append("raw_scopes 는 변경하지 않았습니다. Provider 측 Scope 도 함께 조정하세요.")
            mitigations += [
                "먼저 비운영 환경에서 축소된 권한으로 동작하는지 확인하세요.",
                "적용 후 관찰 단계(권한 변경)에서 장애를 확인하고, 문제가 있으면 롤백하세요.",
            ]
        elif kind is ChangeType.TOKEN_DISPOSE:
            will_interrupt = False
            risk = "LOW"
            notes += [
                "이미 종료된 NHI 라 서비스 호출에는 영향이 없습니다.",
                "암호화 저장된 Secret material 이 영구 삭제됩니다 (복구 불가).",
            ]
            mitigations.append("보존 기간 동안 장애가 없었는지 확인한 뒤 승인하세요.")
            security.append("남은 Credential 흔적이 제거되어 재사용·유출 위험이 사라집니다.")
        elif kind is ChangeType.QUARANTINE:
            will_interrupt = True
            risk = env_risk()
            notes.append("격리 중에는 모든 사용 요청이 차단됩니다. 해제하면 즉시 복구됩니다.")
            if dependents:
                notes.append(f"연결된 AI Agent({', '.join(dependents)})의 호출이 차단됩니다.")
            mitigations.append("원인을 확인한 뒤 격리를 해제하거나 폐기를 제안하세요.")
            security.append("추가 오남용을 즉시 차단하면서 롤백 가능성을 유지합니다.")

        summary = (
            f"{_CHANGE_LABELS[kind]}: "
            + (
                f"서비스 중단 위험 {risk}"
                if will_interrupt
                else f"서비스 중단 없음(연속성 위험 {risk})"
            )
        )
        return {
            "summary": summary,
            "diff": {
                "permissions": {
                    "before": before["permissions"],
                    "after": after["permissions"],
                    "removed": removed,
                    "added": added,
                },
                "scopes": {
                    "before": before["raw_scopes"],
                    "after": after["raw_scopes"],
                    "removed": scopes_removed,
                    "added": scopes_added,
                },
                "effective_access": {"before": effective_before, "after": effective_after},
                "credential_state": {
                    "before": before["credential_state"], "after": after["credential_state"],
                },
                "control_state": {
                    "before": before["control_state"], "after": after["control_state"],
                },
                "lifecycle_stage": {
                    "before": before["lifecycle_stage"], "after": after["lifecycle_stage"],
                },
                "credential_version": {
                    "before": before["credential_version"], "after": after["credential_version"],
                },
            },
            "blast_radius": {
                "environment": environment,
                "connected_services": services,
                "accessible_resource_count": resources,
                "resource_samples": list(blast.get("resource_samples") or [])[:8],
                "linked_ai_agent": agent,
                "owner": nhi.get("owner"),
            },
            "service_continuity": {
                "risk": risk,
                "will_interrupt": will_interrupt,
                "dependents": dependents,
                "notes": notes,
                "mitigations": mitigations,
            },
            "security_effect": security,
        }

    # ------------------------------------------------------------------
    def _required(self, change_id: str) -> ChangeRequest:
        change = self.storage.get_change_request(change_id)
        if change is None:
            raise KeyError(change_id)
        return change

    def _audit(
        self, event_type: str, actor: str, change: ChangeRequest, detail: Dict[str, Any]
    ) -> None:
        payload = {
            "nhi_id": change.nhi_id,
            "change_type": change.change_type.value,
            **detail,
        }
        if change.demo_workspace:
            payload["demo_workspace"] = True
        self.storage.append_audit_event(
            event_type, actor=actor, target=change.change_id, detail=payload
        )
