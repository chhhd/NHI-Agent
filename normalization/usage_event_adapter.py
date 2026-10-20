"""JSON/Dictionary 감사 로그를 UsageEvent와 AnalysisSignals로 정규화한다."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.nhi_models import AnalysisSignals, parse_dt
from core.usage_models import UsageEvent
from security.redaction import sanitize_security_text, sanitize_security_value


@dataclass
class UsageEventAdaptation:
    events: List[UsageEvent] = field(default_factory=list)
    failures: List[Dict[str, Any]] = field(default_factory=list)
    duplicate_count: int = 0

    def summary(self) -> Dict[str, Any]:
        return {
            "accepted_event_count": len(self.events),
            "invalid_event_count": len(self.failures),
            "duplicate_event_count": self.duplicate_count,
            "failures": list(self.failures),
        }


class UsageEventAdapter:
    """공급자별 로그 표현을 최소 공통 모델로 바꾸고 NHI별로 집계한다."""

    def adapt(
        self,
        records: Iterable[Dict[str, Any]],
        *,
        provider: str = "generic",
        source: str = "audit_log",
    ) -> UsageEventAdaptation:
        result = UsageEventAdaptation()
        seen = set()
        for index, record in enumerate(records):
            try:
                event = UsageEvent.from_dict(
                    record,
                    default_provider=provider,
                    default_source=source,
                )
                event = self._sanitize(event)
            except (TypeError, ValueError) as exc:
                result.failures.append(
                    {"index": index, "error": sanitize_security_text(str(exc))}
                )
                continue
            if event.event_id in seen:
                result.duplicate_count += 1
                continue
            seen.add(event.event_id)
            result.events.append(event)
        return result

    def to_signals(
        self,
        events: Sequence[UsageEvent],
        *,
        principal_ids: Iterable[str],
        declared_permissions: Optional[Iterable[str]] = None,
        data_complete: bool = False,
    ) -> AnalysisSignals:
        principals = {
            str(principal).strip()
            for principal in principal_ids
            if str(principal).strip()
        }
        matched = [event for event in events if event.principal_id in principals]
        matched.sort(key=lambda event: parse_dt(event.occurred_at) or parse_dt("1970-01-01T00:00:00Z"))

        actions: List[str] = []
        projects: List[str] = []
        sources: List[str] = []
        for event in matched:
            if event.action not in actions:
                actions.append(event.action)
            if event.project and event.project not in projects:
                projects.append(event.project)
            source = f"{event.provider}:{event.source}"
            if source not in sources:
                sources.append(source)

        latest = matched[-1] if matched else None
        return AnalysisSignals(
            declared_permissions=[
                str(permission)
                for permission in (declared_permissions or [])
                if str(permission).strip()
            ],
            observed_actions=actions,
            shared_projects=projects,
            last_used_at=latest.occurred_at if latest else None,
            extra={
                "usage_data_complete": data_complete,
                "usage_sources": sources,
                "usage_event_count": len(matched),
                "usage_source_event_id": latest.event_id if latest else None,
                "usage_occurred_at": latest.occurred_at if latest else None,
            },
        )

    def merge_into_signals(
        self,
        base: Optional[AnalysisSignals],
        derived: AnalysisSignals,
    ) -> AnalysisSignals:
        """명시 신호를 보존하면서 이벤트에서 관측한 목록·최근 시각을 합친다."""
        merged = AnalysisSignals.from_dict(base.to_dict() if base else None)
        merged.observed_actions = _ordered_union(
            merged.observed_actions, derived.observed_actions
        )
        merged.shared_projects = _ordered_union(
            merged.shared_projects, derived.shared_projects
        )
        if not merged.declared_permissions:
            merged.declared_permissions = list(derived.declared_permissions)

        base_last = parse_dt(merged.last_used_at)
        derived_last = parse_dt(derived.last_used_at)
        if derived_last is not None and (
            base_last is None or derived_last > base_last
        ):
            merged.last_used_at = derived.last_used_at

        existing_sources = merged.extra.get("usage_sources")
        merged.extra["usage_sources"] = _ordered_union(
            existing_sources if isinstance(existing_sources, list) else [],
            derived.extra.get("usage_sources") or [],
        )
        for key in (
            "usage_data_complete",
            "usage_event_count",
            "usage_source_event_id",
            "usage_occurred_at",
        ):
            merged.extra[key] = derived.extra.get(key)
        return merged

    @staticmethod
    def _sanitize(event: UsageEvent) -> UsageEvent:
        attributes = sanitize_security_value(event.attributes)
        return UsageEvent(
            event_id=sanitize_security_text(event.event_id),
            provider=sanitize_security_text(event.provider),
            principal_id=event.principal_id,
            action=sanitize_security_text(event.action),
            occurred_at=event.occurred_at,
            source=sanitize_security_text(event.source),
            project=sanitize_security_text(event.project) if event.project else None,
            resource=sanitize_security_text(event.resource) if event.resource else None,
            success=event.success,
            attributes=attributes if isinstance(attributes, dict) else {},
        )


def _ordered_union(first: Iterable[str], second: Iterable[str]) -> List[str]:
    result: List[str] = []
    for value in [*first, *second]:
        if isinstance(value, str) and value.strip() and value not in result:
            result.append(value)
    return result


__all__ = ["UsageEventAdaptation", "UsageEventAdapter"]
