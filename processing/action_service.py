"""Recommendation 을 승인 가능한 ActionRequest 로 전환한다."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable, List

from core.action_models import ActionRequest, ActionStatus
from core.nhi_models import NHIAnalysis, RecommendedAction, Recommendation
from storage.base import Storage


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ActionService:
    """조치 생성과 안전한 상태 전이를 담당한다."""

    _TRANSITIONS = {
        ActionStatus.PROPOSED: {
            ActionStatus.PENDING_APPROVAL,
            ActionStatus.APPROVED,
            ActionStatus.CANCELLED,
        },
        ActionStatus.PENDING_APPROVAL: {
            ActionStatus.APPROVED,
            ActionStatus.CANCELLED,
        },
        ActionStatus.APPROVED: {
            ActionStatus.EXECUTING,
            ActionStatus.CANCELLED,
        },
        ActionStatus.EXECUTING: {
            ActionStatus.SUCCEEDED,
            ActionStatus.FAILED,
        },
        ActionStatus.SUCCEEDED: {ActionStatus.VERIFYING},
        ActionStatus.VERIFYING: {
            ActionStatus.VERIFIED,
            ActionStatus.FAILED,
        },
        ActionStatus.FAILED: {
            ActionStatus.APPROVED,
            ActionStatus.CANCELLED,
        },
    }

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def create_from_analysis(
        self,
        analysis_id: str,
        analysis: NHIAnalysis,
        *,
        policy_version: str = "1.0",
    ) -> List[ActionRequest]:
        actions: List[ActionRequest] = []
        for recommendation in analysis.recommendations:
            if recommendation.action is RecommendedAction.MONITOR:
                continue
            action = self._build_action(
                analysis_id, analysis, recommendation, policy_version=policy_version
            )
            actions.append(self.storage.create_action(action))
        return actions

    @staticmethod
    def _build_action(
        analysis_id: str,
        analysis: NHIAnalysis,
        recommendation: Recommendation,
        *,
        policy_version: str,
    ) -> ActionRequest:
        requires_approval = (
            analysis.policy.human_review_required or not recommendation.automatable
        )
        status = (
            ActionStatus.PENDING_APPROVAL
            if requires_approval
            else ActionStatus.APPROVED
        )
        material = "|".join(
            [
                analysis.fingerprint,
                recommendation.action.value,
                recommendation.target,
                recommendation.rationale,
                policy_version,
            ]
        )
        idempotency_key = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return ActionRequest(
            analysis_id=analysis_id,
            credential_fingerprint=analysis.fingerprint,
            action_type=recommendation.action.value,
            target=recommendation.target,
            rationale=recommendation.rationale,
            risk_level=analysis.risk.level.value,
            requires_approval=requires_approval,
            idempotency_key=idempotency_key,
            status=status,
            provider=analysis.profile.provider,
        )

    def approve(self, action_id: str, *, actor: str) -> ActionRequest:
        action = self._required(action_id)
        self._transition(action, ActionStatus.APPROVED)
        action.approved_by = actor
        action.approved_at = _utcnow()
        self.storage.update_action(action)
        self.storage.append_audit_event(
            "ACTION_APPROVED",
            actor=actor,
            target=action.action_id,
            detail={"action_type": action.action_type},
        )
        return action

    def cancel(self, action_id: str, *, actor: str, reason: str = "") -> ActionRequest:
        action = self._required(action_id)
        self._transition(action, ActionStatus.CANCELLED)
        action.result = {"cancel_reason": reason}
        self.storage.update_action(action)
        self.storage.append_audit_event(
            "ACTION_CANCELLED",
            actor=actor,
            target=action.action_id,
            detail={"action_type": action.action_type, "reason": reason},
        )
        return action

    def transition(
        self, action_id: str, status: ActionStatus, *, actor: str
    ) -> ActionRequest:
        """실행 어댑터가 사용할 일반 상태 전이."""
        action = self._required(action_id)
        self._transition(action, status)
        self.storage.update_action(action)
        self.storage.append_audit_event(
            "ACTION_STATUS_CHANGED",
            actor=actor,
            target=action.action_id,
            detail={"status": status.value, "action_type": action.action_type},
        )
        return action

    def _required(self, action_id: str) -> ActionRequest:
        action = self.storage.get_action(action_id)
        if action is None:
            raise KeyError(action_id)
        return action

    def _transition(self, action: ActionRequest, status: ActionStatus) -> None:
        allowed: Iterable[ActionStatus] = self._TRANSITIONS.get(action.status, set())
        if status not in allowed:
            raise ValueError(
                f"허용되지 않은 조치 상태 전이입니다: {action.status.value} -> {status.value}"
            )
        action.status = status
        action.updated_at = _utcnow()
