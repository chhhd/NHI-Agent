"""Compare granted NHI permissions with observed usage."""

from __future__ import annotations

from typing import Iterable, List, Optional, Set

from agents.scope_translation_agent import ScopeTranslationAgent
from core.nhi_models import (
    AnalysisSignals,
    PERMISSION_RANK,
    PermissionLevel,
    PermissionProfile,
    UsageAnalysisResult,
    days_since,
)


class UsageAnalysisAgent:
    """Build a usage analysis from normalized permissions and local signals."""

    def __init__(self, *, scope_translator: Optional[ScopeTranslationAgent] = None) -> None:
        self.scope_translator = scope_translator or ScopeTranslationAgent()

    def analyze(
        self,
        permissions: PermissionProfile,
        signals: Optional[AnalysisSignals] = None,
    ) -> UsageAnalysisResult:
        """Compare a permission profile with ``AnalysisSignals.observed_actions``."""
        signals = signals or AnalysisSignals()
        granted = self._sorted_permissions(permissions.permissions)
        used = self._sorted_permissions(self._permissions_from_actions(signals.observed_actions))
        granted_set = set(granted)
        used_set = set(used)
        unused = self._sorted_permissions(granted_set - used_set)
        elapsed = days_since(signals.last_used_at)

        return UsageAnalysisResult(
            granted_permissions=granted,
            used_permissions=self._sorted_permissions(used_set),
            unused_permissions=unused,
            days_since_last_used=elapsed,
            usage_status=self._usage_status(elapsed),
            excessive_permission=bool(
                set(unused) & {PermissionLevel.DELETE, PermissionLevel.ADMIN}
            ),
            evidence=self._evidence(granted, used_set, unused, elapsed),
        )

    def _permissions_from_actions(self, actions: Iterable[object]) -> Set[PermissionLevel]:
        permissions: Set[PermissionLevel] = set()
        for action in actions or []:
            if isinstance(action, PermissionLevel):
                permissions.add(action)
                continue
            if not isinstance(action, str) or not action.strip():
                continue
            try:
                permissions.add(PermissionLevel(action.strip().upper()))
                continue
            except ValueError:
                pass
            mapping = self.scope_translator.translate_scope(action)
            if mapping.permission is not None:
                permissions.add(mapping.permission)
        return permissions

    @staticmethod
    def _sorted_permissions(
        permissions: Iterable[PermissionLevel],
    ) -> List[PermissionLevel]:
        return sorted(set(permissions), key=lambda permission: PERMISSION_RANK[permission])

    @staticmethod
    def _usage_status(days: Optional[int]) -> str:
        if days is None:
            return "unknown"
        if days <= 30:
            return "active"
        if days <= 90:
            return "inactive_warning"
        if days <= 180:
            return "stale"
        return "orphaned_candidate"

    @staticmethod
    def _evidence(
        granted: List[PermissionLevel],
        used: Set[PermissionLevel],
        unused: List[PermissionLevel],
        days: Optional[int],
    ) -> List[str]:
        granted_text = ", ".join(permission.value for permission in granted) or "none"
        used_text = ", ".join(permission.value for permission in sorted(used, key=lambda p: PERMISSION_RANK[p])) or "none"
        evidence = [f"Granted permissions: {granted_text}.", f"Observed used permissions: {used_text}."]
        if unused:
            unused_text = ", ".join(permission.value for permission in unused)
            evidence.append(f"Granted permissions not observed in use: {unused_text}.")
        if days is None:
            evidence.append("Last usage time is unknown.")
        else:
            evidence.append(f"Last usage was {days} day(s) ago.")
        if set(unused) & {PermissionLevel.DELETE, PermissionLevel.ADMIN}:
            evidence.append("High-privilege permission is granted but has no observed use.")
        return evidence
