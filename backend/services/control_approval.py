"""실시간 통제의 승인 대기(REQUIRE_APPROVAL) 요청을 사람의 결정으로 마무리한다.

흐름: Gateway 요청 보류 → 관리자 승인 → 1회용·단기 허가(grant) 발급 →
Gateway 가 같은 요청을 허가와 함께 재시도 → 통과. 결정 없이 `approval_ttl` 이 지나면
자동 거부(EXPIRED)된다.

허가 원문은 승인 응답으로 한 번만 돌려주고 저장소에는 SHA-256 digest 만 남긴다.
허가는 원래 요청의 Agent · NHI · Credential · 행위 · 자원에 묶여 다른 요청에는 쓸 수 없고,
`compare_and_set` 으로 한 번만 사용된다(동시 재시도 포함).
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from storage.base import Storage

#: 허가가 묶이는 요청 필드. 하나라도 다르면 다른 요청으로 본다.
BINDING_FIELDS = (
    "claimed_agent_id",
    "authenticated_agent_id",
    "provider",
    "nhi_id",
    "credential_fingerprint",
    "action",
    "permission",
    "resource",
)

#: Credential 탈취·위장이 의심되는 규칙. 차단 후 Credential 교체 승인을 요청한다.
CONTAINMENT_RULES = frozenset(
    {
        "TOKEN_REPLAY_SUSPECTED",
        "SENDER_PROOF_INVALID",
        "UNAPPROVED_CREDENTIAL",
        "CLAIMED_IDENTITY_MISMATCH",
    }
)


class ApprovalError(ValueError):
    """승인 흐름이 허용하지 않는 요청 (HTTP 409 에 대응)."""


def _digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def binding_of(observation: Dict[str, Any]) -> Dict[str, Any]:
    return {name: observation.get(name) for name in BINDING_FIELDS}


class ControlApprovalService:
    def __init__(
        self,
        storage: Storage,
        *,
        approval_ttl_seconds: int = 900,
        grant_ttl_seconds: int = 300,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.storage = storage
        self.approval_ttl = timedelta(seconds=max(1, approval_ttl_seconds))
        self.grant_ttl = timedelta(seconds=max(1, grant_ttl_seconds))
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # -- 보류 열기 ------------------------------------------------------
    def open_hold(
        self,
        *,
        decision_id: str,
        observation: Dict[str, Any],
        rule_ids: List[str],
        event_seq: Optional[int],
    ) -> Dict[str, Any]:
        now = self._clock()
        approval = {
            "decision_id": decision_id,
            "status": "PENDING",
            "agent_id": observation.get("claimed_agent_id"),
            "nhi_id": observation.get("nhi_id"),
            "rule_ids": list(rule_ids),
            "event_seq": event_seq,
            "binding": binding_of(observation),
            "requested_at": now.isoformat(),
            "expires_at": (now + self.approval_ttl).isoformat(),
        }
        self.storage.save_control_approval(approval)
        return self._public(self.storage.get_control_approval(decision_id) or approval)

    def get(self, decision_id: str) -> Optional[Dict[str, Any]]:
        approval = self.storage.get_control_approval(decision_id)
        return self._public(approval) if approval else None

    def list_holds(
        self, *, status: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        # 만료는 읽는 시점에 반영되므로 상태 필터는 반영 후에 적용한다.
        items = [
            self._public(item)
            for item in self.storage.list_control_approvals(limit=max(limit * 5, 100))
        ]
        if status:
            items = [item for item in items if item["status"] == status]
        return items[:limit]

    # -- 관리자 결정 ------------------------------------------------------
    def approve(
        self, decision_id: str, *, actor: str, reason: str, verified: bool = False
    ) -> Tuple[Dict[str, Any], str]:
        approval = self._pending(decision_id)
        now = self._clock()
        token = f"{decision_id}.{secrets.token_urlsafe(32)}"
        updated = {
            **approval,
            "status": "APPROVED",
            "decided_by": actor,
            "decided_by_verified": bool(verified),
            "decided_at": now.isoformat(),
            "reason": reason,
            "grant_digest": _digest(token),
            "grant_expires_at": (now + self.grant_ttl).isoformat(),
        }
        if not self.storage.compare_and_set_control_approval(
            decision_id, expected_status="PENDING", approval=updated
        ):
            raise ApprovalError("다른 관리자가 이미 이 요청을 결정했습니다.")
        self.storage.append_audit_event(
            "REALTIME_HOLD_APPROVED",
            actor=actor,
            target=decision_id,
            detail={
                "reason": reason,
                "actor_verified": bool(verified),
                "agent_id": approval.get("agent_id"),
                "nhi_id": approval.get("nhi_id"),
                "grant_expires_at": updated["grant_expires_at"],
            },
        )
        return self._public(updated), token

    def reject(
        self, decision_id: str, *, actor: str, reason: str, verified: bool = False
    ) -> Dict[str, Any]:
        approval = self._pending(decision_id)
        updated = {
            **approval,
            "status": "REJECTED",
            "decided_by": actor,
            "decided_by_verified": bool(verified),
            "decided_at": self._clock().isoformat(),
            "reason": reason,
        }
        if not self.storage.compare_and_set_control_approval(
            decision_id, expected_status="PENDING", approval=updated
        ):
            raise ApprovalError("다른 관리자가 이미 이 요청을 결정했습니다.")
        self.storage.append_audit_event(
            "REALTIME_HOLD_REJECTED",
            actor=actor,
            target=decision_id,
            detail={
                "reason": reason,
                "actor_verified": bool(verified),
                "agent_id": approval.get("agent_id"),
            },
        )
        return self._public(updated)

    # -- Gateway 재시도 ----------------------------------------------------
    def redeem(
        self, token: str, observation: Dict[str, Any], *, event_id: str
    ) -> Dict[str, Any]:
        """허가를 검증하고 한 번만 소비한다. 실패 사유는 `ApprovalError` 로 알린다."""
        decision_id = token.split(".", 1)[0]
        approval = self.storage.get_control_approval(decision_id)
        if not approval or not hmac.compare_digest(
            str(approval.get("grant_digest") or ""), _digest(token)
        ):
            raise ApprovalError("유효하지 않은 승인 허가입니다.")
        if approval["status"] == "USED":
            raise ApprovalError("이미 사용된 1회용 승인 허가입니다.")
        if approval["status"] != "APPROVED":
            raise ApprovalError("승인되지 않은 요청의 허가입니다.")
        now = self._clock()
        expires = _parse(approval.get("grant_expires_at"))
        if expires is not None and now >= expires:
            raise ApprovalError("승인 허가의 유효 시간이 지났습니다.")
        mismatched = [
            name
            for name, value in (approval.get("binding") or {}).items()
            if value != observation.get(name)
        ]
        if mismatched:
            raise ApprovalError("승인된 요청과 다른 요청입니다: " + ", ".join(mismatched))
        if not self.storage.compare_and_set_control_approval(
            decision_id,
            expected_status="APPROVED",
            approval={
                **approval,
                "status": "USED",
                "used_at": now.isoformat(),
                "used_by_event_id": event_id,
            },
        ):
            raise ApprovalError("이미 사용된 1회용 승인 허가입니다.")
        self.storage.append_audit_event(
            "REALTIME_GRANT_REDEEMED",
            actor=str(observation.get("authenticated_agent_id") or "unverified-agent"),
            target=decision_id,
            detail={"retry_event_id": event_id},
        )
        return self._public(self.storage.get_control_approval(decision_id) or approval)

    # -- 내부 -------------------------------------------------------------
    def _pending(self, decision_id: str) -> Dict[str, Any]:
        approval = self.storage.get_control_approval(decision_id)
        if approval is None:
            raise KeyError(decision_id)
        if approval["status"] != "PENDING":
            raise ApprovalError(f"이미 결정된 요청입니다: {approval['status']}")
        expires = _parse(approval.get("expires_at"))
        if expires is not None and self._clock() >= expires:
            self.storage.compare_and_set_control_approval(
                decision_id,
                expected_status="PENDING",
                approval={**approval, "status": "EXPIRED"},
            )
            raise ApprovalError(
                "승인 대기 시간이 지나 자동 거부되었습니다. Gateway 가 다시 요청해야 합니다."
            )
        return approval

    def _public(self, approval: Dict[str, Any]) -> Dict[str, Any]:
        """digest 를 숨기고, 만료는 읽는 시점에 반영한 사본을 돌려준다."""
        view = copy.deepcopy(approval)
        view.pop("grant_digest", None)
        now = self._clock()
        if view["status"] == "PENDING":
            expires = _parse(view.get("expires_at"))
            if expires is not None and now >= expires:
                view["status"] = "EXPIRED"
        elif view["status"] == "APPROVED":
            expires = _parse(view.get("grant_expires_at"))
            if expires is not None and now >= expires:
                view["status"] = "GRANT_EXPIRED"
        return view


__all__ = [
    "ApprovalError",
    "BINDING_FIELDS",
    "CONTAINMENT_RULES",
    "ControlApprovalService",
    "binding_of",
]
