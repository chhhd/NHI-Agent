"""Map extracted security events to catalog-defined risk scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from core.nhi_models import RecommendedAction, RiskLevel, ScenarioMatch, SecurityEvent


class ScenarioMappingAgent:
    """Match a list of security events against the scenario catalog."""

    def __init__(self, catalog_path: Optional[Path] = None) -> None:
        self.catalog_path = catalog_path or (
            Path(__file__).resolve().parents[1] / "data" / "scenario_catalog.json"
        )

    def load_catalog(self) -> List[Dict[str, object]]:
        """Load scenario definitions from the repository catalog."""
        with self.catalog_path.open(encoding="utf-8") as stream:
            catalog = json.load(stream)
        scenarios = catalog.get("scenarios") if isinstance(catalog, dict) else None
        if not isinstance(scenarios, list):
            raise ValueError("Scenario catalog must contain a 'scenarios' list.")
        return [scenario for scenario in scenarios if isinstance(scenario, dict)]

    def map(self, events: Iterable[SecurityEvent]) -> List[ScenarioMatch]:
        """Return one match per catalog scenario whose events are all present."""
        event_list = list(events or [])
        events_by_type: Dict[str, List[SecurityEvent]] = {}
        for event in event_list:
            events_by_type.setdefault(event.event_type, []).append(event)

        matches: List[ScenarioMatch] = []
        seen_scenarios = set()
        for scenario in self.load_catalog():
            scenario_id = str(scenario.get("scenario_id") or "")
            if not scenario_id or scenario_id in seen_scenarios:
                continue
            required = [str(value) for value in scenario.get("required_events", [])]
            if not required or not all(event_type in events_by_type for event_type in required):
                continue

            matched_events = [
                event.event_id
                for event_type in required
                for event in events_by_type[event_type]
            ]
            severity = RiskLevel(str(scenario["severity"]))
            recommended_action = RecommendedAction(str(scenario["recommended_action"]))
            name = str(scenario.get("name") or scenario_id)
            matches.append(
                ScenarioMatch(
                    scenario_id=scenario_id,
                    scenario_name=name,
                    severity=severity,
                    matched_events=matched_events,
                    matched_reason=(
                        f"Scenario '{name}' matched because required events are present: "
                        f"{', '.join(required)}."
                    ),
                    risk_addition=int(scenario["risk_addition"]),
                    recommended_action=recommended_action,
                )
            )
            seen_scenarios.add(scenario_id)
        return matches

    def analyze(self, events: Iterable[SecurityEvent]) -> List[ScenarioMatch]:
        """Alias using the repository's conventional Agent method name."""
        return self.map(events)
