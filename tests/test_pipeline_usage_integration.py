from datetime import datetime, timedelta, timezone

from agents.pipeline import NHIAnalysisPipeline
from core.nhi_models import AnalysisSignals, PermissionLevel
from tests.test_nhi_agents import make_finding


def test_pipeline_stores_usage_events_and_scenarios_before_existing_assessments():
    finding = make_finding(
        raw_scopes=["admin"],
        credential_active=True,
        file_path="config/production/service.env",
    )
    signals = AnalysisSignals(
        owner="platform-team",
        last_used_at=(datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
        observed_actions=["read"],
    )

    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)

    assert analysis.usage_analysis.days_since_last_used == 120
    assert analysis.usage_analysis.usage_status == "stale"
    assert analysis.events
    assert analysis.scenario_matches
    assert {event.event_type for event in analysis.events} >= {
        "HIGH_RISK_SCOPE_GRANTED",
        "STALE_PERMISSION",
    }
    assert "SCN_001" in {match.scenario_id for match in analysis.scenario_matches}
    scenario = next(
        match for match in analysis.scenario_matches if match.scenario_id == "SCN_001"
    )
    disable_recommendations = [
        recommendation
        for recommendation in analysis.recommendations
        if recommendation.action.value == "DISABLE_INACTIVE_NHI"
    ]
    assert len(disable_recommendations) == 1
    assert scenario.scenario_name in disable_recommendations[0].rationale
    assert scenario.matched_reason in disable_recommendations[0].rationale
    assert analysis.risk is not None
    assert analysis.policy is not None
    assert analysis.recommendations
    assert analysis.permissions.highest is PermissionLevel.ADMIN


def test_github_inventory_entry_point_uses_the_same_new_analysis_stages(high_risk_nhi):
    analysis = NHIAnalysisPipeline().analyze_github_nhi(high_risk_nhi)

    assert analysis.usage_analysis is not None
    assert isinstance(analysis.events, list)
    assert isinstance(analysis.scenario_matches, list)
    assert analysis.risk is not None
    assert analysis.policy is not None
    assert analysis.recommendations
