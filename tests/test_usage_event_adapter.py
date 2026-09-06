"""agents/usage_event_adapter.py 와 normalization/usage_event_adapter.py 둘 다 검증한다.

경로는 이름이 같아 병합 시 파일이 충돌했을 뿐 서로 다른 모듈이다 — 전자는
`PermissionUsageAgent`(권한 사용률 비교) 입력을, 후자는 provider Audit Log를
`AnalysisSignals` 로 정규화하는 별도 기능을 검증한다.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.usage_analysis_agent import PermissionUsageAgent
from agents.usage_event_adapter import load_usage_events, signals_for_nhi
from core.nhi_models import AnalysisSignals, PermissionLevel, PermissionProfile
from normalization.usage_event_adapter import UsageEventAdapter


DATA_PATH = Path(__file__).parents[1] / "data" / "dummy_audit_logs.json"


def test_dummy_audit_logs_load_as_provider_independent_usage_events():
    events = load_usage_events(DATA_PATH)

    assert len(events) == 6
    assert events[0].nhi_id == "nhi-recent"
    assert events[0].resource_id == "repo-1"
    assert events[0].provider == "mock"


def test_usage_events_convert_to_signals_and_usage_analysis():
    events = load_usage_events(DATA_PATH)
    signals = signals_for_nhi(events, "nhi-recent")
    result = PermissionUsageAgent().analyze(
        PermissionProfile(permissions=[PermissionLevel.READ, PermissionLevel.WRITE]),
        signals,
    )

    assert signals == AnalysisSignals(
        observed_actions=["read", "write"],
        last_used_at="2026-08-29T10:00:00+00:00",
    )
    assert result.used_permissions == [PermissionLevel.READ, PermissionLevel.WRITE]
    assert result.unused_permissions == []


def test_unexpected_write_event_remains_visible_to_usage_analysis():
    events = load_usage_events(DATA_PATH)
    signals = signals_for_nhi(events, "nhi-unexpected-write")
    result = PermissionUsageAgent().analyze(
        PermissionProfile(permissions=[PermissionLevel.READ]), signals
    )

    assert signals.observed_actions == ["write"]
    assert result.used_permissions == [PermissionLevel.WRITE]
    assert result.unused_permissions == [PermissionLevel.READ]


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
