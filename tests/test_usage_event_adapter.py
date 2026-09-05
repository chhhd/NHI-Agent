"""공급자 Audit Log → UsageEvent → AnalysisSignals 정규화 테스트."""

from __future__ import annotations

import json

from core.nhi_models import AnalysisSignals
from normalization.usage_event_adapter import UsageEventAdapter


def test_adapter_filters_nhi_deduplicates_and_preserves_latest_usage():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    records = [
        {
            "id": "evt-1",
            "actor_id": "agent-7",
            "operation": "contents:read",
            "timestamp": "2026-09-01T00:00:00Z",
            "repository": "acme/a",
            "attributes": {"authorization": f"Bearer {secret}"},
        },
        {
            "id": "evt-2",
            "actor_id": "agent-7",
            "operation": "contents:write",
            "timestamp": "2026-09-02T00:00:00Z",
            "repository": "acme/b",
        },
        {
            "id": "evt-2",
            "actor_id": "agent-7",
            "operation": "contents:write",
            "timestamp": "2026-09-02T00:00:00Z",
        },
        {
            "id": "evt-other",
            "actor_id": "another-agent",
            "operation": "admin",
            "timestamp": "2026-09-03T00:00:00Z",
        },
        {"id": "invalid", "operation": "read"},
    ]
    adapter = UsageEventAdapter()

    adaptation = adapter.adapt(
        records, provider="github", source="organization_audit_log"
    )
    signals = adapter.to_signals(
        adaptation.events,
        principal_ids=["agent-7"],
        data_complete=False,
    )

    assert len(adaptation.events) == 3
    assert adaptation.duplicate_count == 1
    assert len(adaptation.failures) == 1
    assert signals.observed_actions == ["contents:read", "contents:write"]
    assert signals.shared_projects == ["acme/a", "acme/b"]
    assert signals.last_used_at == "2026-09-02T00:00:00+00:00"
    assert signals.extra["usage_event_count"] == 2
    assert signals.extra["usage_data_complete"] is False
    assert secret not in json.dumps(
        [event.to_dict() for event in adaptation.events], ensure_ascii=False
    )


def test_adapter_merges_explicit_and_observed_signals_without_losing_newest_time():
    adapter = UsageEventAdapter()
    adaptation = adapter.adapt(
        [
            {
                "event_id": "evt-1",
                "principal_id": "agent-7",
                "action": "WRITE",
                "occurred_at": "2026-09-02T00:00:00Z",
            }
        ]
    )
    derived = adapter.to_signals(
        adaptation.events,
        principal_ids=["agent-7"],
        data_complete=True,
    )
    merged = adapter.merge_into_signals(
        AnalysisSignals(
            observed_actions=["READ"],
            last_used_at="2026-09-03T00:00:00Z",
            extra={"usage_sources": ["manual_signal"]},
        ),
        derived,
    )

    assert merged.observed_actions == ["READ", "WRITE"]
    assert merged.last_used_at == "2026-09-03T00:00:00Z"
    assert merged.extra["usage_sources"] == ["manual_signal", "generic:audit_log"]
    assert merged.extra["usage_data_complete"] is True
