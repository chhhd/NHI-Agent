import json
from pathlib import Path

from core.nhi_models import RecommendedAction, RiskLevel


CATALOG_PATH = Path(__file__).parents[1] / "data" / "scenario_catalog.json"
EXPECTED_EVENTS = {
    "SCN_001": {"HIGH_RISK_SCOPE_GRANTED", "STALE_PERMISSION"},
    "SCN_002": {"OWNER_MISSING", "HIGH_RISK_SCOPE_GRANTED"},
    "SCN_003": {"UNUSED_HIGH_PRIVILEGE"},
    "SCN_004": {"UNAUTHORIZED_MUTATION"},
    "SCN_005": {"TOKEN_SHARED_ACROSS_PROJECTS"},
}


def test_scenario_catalog_has_expected_provider_independent_mappings():
    with CATALOG_PATH.open(encoding="utf-8") as stream:
        catalog = json.load(stream)

    scenarios = catalog["scenarios"]
    assert {item["scenario_id"] for item in scenarios} == set(EXPECTED_EVENTS)

    required_fields = {
        "scenario_id",
        "name",
        "required_events",
        "severity",
        "risk_addition",
        "recommended_action",
        "description",
    }
    for scenario in scenarios:
        assert required_fields <= scenario.keys()
        assert set(scenario["required_events"]) == EXPECTED_EVENTS[scenario["scenario_id"]]
        assert scenario["severity"] in {level.value for level in RiskLevel}
        assert scenario["recommended_action"] in {
            action.value for action in RecommendedAction
        }
        assert isinstance(scenario["risk_addition"], int)
        assert scenario["risk_addition"] >= 0
        assert scenario["description"]
