"""Extract security signals from existing NHI analysis results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional, Set

from core.nhi_models import (
    AnalysisSignals,
    BlastRadiusReport,
    ContextInsight,
    NHIProfile,
    PERMISSION_RANK,
    PermissionLevel,
    PermissionProfile,
    RiskLevel,
    SecurityEvent,
    UsageAnalysisResult,
)


class EventExtractionAgent:
    """Create provider-independent security events from analysis evidence."""

    def extract(
        self,
        profile: NHIProfile,
        permissions: PermissionProfile,
        usage_analysis: UsageAnalysisResult,
        signals: Optional[AnalysisSignals] = None,
        context: Optional[ContextInsight] = None,
        blast_radius: Optional[BlastRadiusReport] = None,
    ) -> List[SecurityEvent]:
        """Extract currently provable event types without scoring or scenarios."""
        del context  # Reserved for future context-specific evidence; no inference here.
        signals = signals or AnalysisSignals()
        events: List[SecurityEvent] = []
        emitted: Set[str] = set()
        granted = self._permissions(permissions.permissions)
        unused = self._permissions(usage_analysis.unused_permissions)
        used = self._permissions(usage_analysis.used_permissions)

        def emit(
            event_type: str,
            *,
            resource_type: str,
            access_level: Optional[PermissionLevel],
            risk: RiskLevel,
            evidence: str,
        ) -> None:
            if event_type in emitted:
                return
            emitted.add(event_type)
            events.append(
                SecurityEvent(
                    event_id=f"{profile.nhi_id}:{event_type}",
                    nhi_id=profile.nhi_id,
                    event_type=event_type,
                    resource_type=resource_type,
                    access_level=access_level,
                    event_risk=risk,
                    event_count=1,
                    timestamp=signals.last_used_at or _utcnow(),
                    evidence=[evidence],
                )
            )

        high_privilege = granted & {PermissionLevel.ADMIN, PermissionLevel.DELETE}
        if high_privilege:
            level = self._highest(high_privilege)
            emit(
                "HIGH_RISK_SCOPE_GRANTED",
                resource_type="permission_scope",
                access_level=level,
                risk=RiskLevel.CRITICAL if level is PermissionLevel.ADMIN else RiskLevel.HIGH,
                evidence=f"NHI is granted high-privilege permission {level.value}.",
            )

        if usage_analysis.usage_status in {"stale", "orphaned_candidate"}:
            emit(
                "STALE_PERMISSION",
                resource_type="permission_scope",
                access_level=self._highest(granted),
                risk=RiskLevel.MEDIUM,
                evidence=(
                    "Usage status is "
                    f"{usage_analysis.usage_status}; the permission may no longer be needed."
                ),
            )

        unused_high = unused & {PermissionLevel.ADMIN, PermissionLevel.DELETE}
        if unused_high:
            level = self._highest(unused_high)
            emit(
                "UNUSED_HIGH_PRIVILEGE",
                resource_type="permission_scope",
                access_level=level,
                risk=RiskLevel.HIGH,
                evidence=f"High-privilege permission {level.value} is granted but unused.",
            )

        if not profile.owner:
            emit(
                "OWNER_MISSING",
                resource_type="nhi",
                access_level=self._highest(granted),
                risk=RiskLevel.HIGH,
                evidence="No confirmed owner is available for this NHI.",
            )

        if granted and granted <= {PermissionLevel.READ}:
            mutation = used & {
                PermissionLevel.WRITE,
                PermissionLevel.DELETE,
                PermissionLevel.ADMIN,
            }
            if mutation:
                level = self._highest(mutation)
                emit(
                    "UNAUTHORIZED_MUTATION",
                    resource_type="resource_access",
                    access_level=level,
                    risk=RiskLevel.CRITICAL,
                    evidence=(
                        "Read-only permission is granted, but observed usage includes "
                        f"{level.value} mutation access."
                    ),
                )

        shared_projects = [project for project in signals.shared_projects if project]
        if len(set(shared_projects)) >= 2:
            emit(
                "TOKEN_SHARED_ACROSS_PROJECTS",
                resource_type="project",
                access_level=self._highest(granted),
                risk=RiskLevel.HIGH,
                evidence=(
                    "The NHI is explicitly shared across projects: "
                    f"{', '.join(dict.fromkeys(shared_projects))}."
                ),
            )
        elif blast_radius and len(set(blast_radius.affected_projects)) >= 2:
            # Blast radius alone is impact evidence, not proof of credential sharing.
            pass

        return events

    @staticmethod
    def _permissions(values: Iterable[PermissionLevel]) -> Set[PermissionLevel]:
        return {value for value in values if isinstance(value, PermissionLevel)}

    @staticmethod
    def _highest(
        permissions: Iterable[PermissionLevel],
        *,
        default: Optional[PermissionLevel] = None,
    ) -> Optional[PermissionLevel]:
        values = list(permissions)
        if not values:
            return default
        return max(values, key=lambda permission: PERMISSION_RANK[permission])


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
