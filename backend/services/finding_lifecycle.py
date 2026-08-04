"""Finding lifecycle 상태 전이 규칙."""

from __future__ import annotations

from typing import Dict, Set

from backend.models.entities import FindingStatus


ALLOWED_TRANSITIONS: Dict[FindingStatus, Set[FindingStatus]] = {
    FindingStatus.NEW: {
        FindingStatus.TRIAGED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.EXCEPTION,
        FindingStatus.NEEDS_REVIEW,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.TRIAGED: {
        FindingStatus.ASSIGNED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.EXCEPTION,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.ASSIGNED: {
        FindingStatus.REMEDIATION_IN_PROGRESS,
        FindingStatus.NEEDS_REVIEW,
    },
    FindingStatus.REMEDIATION_IN_PROGRESS: {
        FindingStatus.CREDENTIAL_REVOKED,
        FindingStatus.RESCAN_PENDING,
        FindingStatus.NEEDS_REVIEW,
    },
    FindingStatus.CREDENTIAL_REVOKED: {FindingStatus.RESCAN_PENDING},
    FindingStatus.RESCAN_PENDING: {
        FindingStatus.RESOLVED,
        FindingStatus.REOPENED,
        FindingStatus.RECURRENCE,
    },
    FindingStatus.RESOLVED: {
        FindingStatus.REOPENED,
        FindingStatus.RECURRENCE,
    },
    FindingStatus.REOPENED: {
        FindingStatus.TRIAGED,
        FindingStatus.ASSIGNED,
        FindingStatus.REMEDIATION_IN_PROGRESS,
    },
    FindingStatus.RECURRENCE: {
        FindingStatus.TRIAGED,
        FindingStatus.ASSIGNED,
        FindingStatus.REMEDIATION_IN_PROGRESS,
    },
    FindingStatus.NEEDS_REVIEW: {
        FindingStatus.TRIAGED,
        FindingStatus.ASSIGNED,
        FindingStatus.EXCEPTION,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.SLA_OVERDUE: {
        FindingStatus.ASSIGNED,
        FindingStatus.REMEDIATION_IN_PROGRESS,
        FindingStatus.NEEDS_REVIEW,
    },
    FindingStatus.FALSE_POSITIVE: {FindingStatus.REOPENED},
    FindingStatus.EXCEPTION: {FindingStatus.REOPENED, FindingStatus.RESOLVED},
    FindingStatus.ACCEPTED_RISK: {FindingStatus.REOPENED, FindingStatus.RESOLVED},
}


def validate_transition(current: FindingStatus, target: FindingStatus) -> None:
    if current == target:
        return
    if target is FindingStatus.SLA_OVERDUE and current not in {
        FindingStatus.RESOLVED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.EXCEPTION,
        FindingStatus.ACCEPTED_RISK,
    }:
        return
    if target not in ALLOWED_TRANSITIONS.get(current, set()):
        raise ValueError(
            f"허용되지 않은 Finding 상태 전이입니다: {current.value} -> {target.value}"
        )
