from pathlib import Path

from agents.usage_analysis_agent import UsageAnalysisAgent
from agents.usage_event_adapter import load_usage_events, signals_for_nhi
from core.nhi_models import AnalysisSignals, PermissionLevel, PermissionProfile


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
    result = UsageAnalysisAgent().analyze(
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
    result = UsageAnalysisAgent().analyze(
        PermissionProfile(permissions=[PermissionLevel.READ]), signals
    )

    assert signals.observed_actions == ["write"]
    assert result.used_permissions == [PermissionLevel.WRITE]
    assert result.unused_permissions == [PermissionLevel.READ]
