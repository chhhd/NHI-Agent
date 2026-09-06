"""Orchestration for converting Slack API results into an NHI analysis."""

from __future__ import annotations

from typing import Optional

from agents.inventory_adapter import build_slack_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from connectors.base_connector import AuthenticationError
from connectors.slack_connector import SlackConnector
from core.nhi_models import AnalysisSignals, NHIAnalysis


def analyze_slack_nhi_from_connector(
    connector: SlackConnector,
    *,
    pipeline: Optional[NHIAnalysisPipeline] = None,
) -> NHIAnalysis:
    """Fetch the Slack credential's live identity/scopes and run the existing pipeline.

    `SlackConnector.validate_credential()` calls `/auth.test` once and already
    returns identity, the real OAuth scopes (`x-oauth-scopes` response
    header), and accessible channels — unlike the GitHub PAT path, no second
    call is needed to assemble the inventory input.
    """
    status = connector.validate_credential()
    if status.active is not True:
        raise AuthenticationError(
            f"Slack credential is not active: {status.error or 'unknown'}",
            status_code=401,
        )

    nhi = build_slack_nhi_input(status, status.accessible_resources)
    signals = AnalysisSignals(extra={"slack_account": status.account})
    return (pipeline or NHIAnalysisPipeline()).analyze_slack_nhi(nhi, signals=signals)
