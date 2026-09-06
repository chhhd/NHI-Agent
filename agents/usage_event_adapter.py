"""Convert provider-independent usage events into analysis signals."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Union

from core.nhi_models import AnalysisSignals, parse_dt
from core.observation_models import UsageEvent


def usage_events_from_dicts(records: Iterable[Dict[str, object]]) -> List[UsageEvent]:
    """Build usage events from JSON-compatible records."""
    return [UsageEvent.from_dict(record) for record in records if isinstance(record, dict)]


def load_usage_events(path: Union[str, Path]) -> List[UsageEvent]:
    """Load a list of mock usage events from a JSON file."""
    with Path(path).open(encoding="utf-8") as stream:
        payload = json.load(stream)
    records = payload.get("events", payload) if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        raise ValueError("Usage event JSON must contain a list or an 'events' list.")
    return usage_events_from_dicts(records)


def signals_for_nhi(events: Iterable[UsageEvent], nhi_id: str) -> AnalysisSignals:
    """Convert matching ``UsageEvent`` values to ``AnalysisSignals``."""
    matching = [event for event in events if event.nhi_id == nhi_id]
    matching.sort(key=_event_datetime)
    timestamps = [event.timestamp for event in matching if parse_dt(event.timestamp)]
    return AnalysisSignals(
        observed_actions=[event.action for event in matching if event.action],
        last_used_at=timestamps[-1] if timestamps else None,
    )


def signals_by_nhi(events: Iterable[UsageEvent]) -> Dict[str, AnalysisSignals]:
    """Convert usage events for all NHIs into independently-owned signals."""
    grouped: Dict[str, List[UsageEvent]] = {}
    for event in events:
        grouped.setdefault(event.nhi_id, []).append(event)
    return {nhi_id: signals_for_nhi(items, nhi_id) for nhi_id, items in grouped.items()}


def _event_datetime(event: UsageEvent) -> datetime:
    """Sort invalid timestamps before valid timestamps without raising."""
    return parse_dt(event.timestamp) or datetime.min.replace(tzinfo=timezone.utc)
