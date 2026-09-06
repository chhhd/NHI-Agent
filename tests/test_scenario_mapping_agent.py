from agents.scenario_mapping_agent import ScenarioMappingAgent
from core.nhi_models import PermissionLevel, RiskLevel, SecurityEvent


def _event(event_id, event_type):
    return SecurityEvent(
        event_id=event_id,
        nhi_id="nhi-test",
        event_type=event_type,
        resource_type="permission_scope",
        access_level=PermissionLevel.ADMIN,
    )


def test_scn_001_matches_when_all_required_events_exist():
    matches = ScenarioMappingAgent().map(
        [_event("e-high", "HIGH_RISK_SCOPE_GRANTED"), _event("e-stale", "STALE_PERMISSION")]
    )

    match = next(match for match in matches if match.scenario_id == "SCN_001")
    assert match.matched_events == ["e-high", "e-stale"]
    assert match.severity is RiskLevel.HIGH
    assert match.risk_addition == 20


def test_scn_002_matches_when_owner_and_scope_events_exist():
    matches = ScenarioMappingAgent().analyze(
        [_event("e-owner", "OWNER_MISSING"), _event("e-high", "HIGH_RISK_SCOPE_GRANTED")]
    )

    match = next(match for match in matches if match.scenario_id == "SCN_002")
    assert set(match.matched_events) == {"e-owner", "e-high"}
    assert match.recommended_action.value == "ASSIGN_OWNER"


def test_missing_required_event_does_not_match_scenario():
    matches = ScenarioMappingAgent().map([_event("e-high", "HIGH_RISK_SCOPE_GRANTED")])

    assert not any(match.scenario_id == "SCN_001" for match in matches)


def test_empty_events_produce_no_scenarios():
    assert ScenarioMappingAgent().map([]) == []


def test_multiple_satisfied_scenarios_are_each_returned_once():
    events = [
        _event("e-high", "HIGH_RISK_SCOPE_GRANTED"),
        _event("e-stale", "STALE_PERMISSION"),
        _event("e-owner", "OWNER_MISSING"),
        _event("e-unused", "UNUSED_HIGH_PRIVILEGE"),
    ]

    matches = ScenarioMappingAgent().map(events)
    scenario_ids = [match.scenario_id for match in matches]
    assert {"SCN_001", "SCN_002", "SCN_003"} <= set(scenario_ids)
    assert len(scenario_ids) == len(set(scenario_ids))
