"""Orchestration for converting Slack API results into an NHI analysis."""

from __future__ import annotations

from typing import Optional, Tuple

from agents.inventory_adapter import build_slack_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from connectors.base_connector import AuthenticationError
from connectors.slack_connector import SlackConnector
from core.nhi_models import AnalysisSignals, NHIAnalysis
from core.slack_inventory_models import SlackNHIInput


def analyze_slack_nhi_from_connector(
    connector: SlackConnector,
    *,
    pipeline: Optional[NHIAnalysisPipeline] = None,
) -> Tuple[NHIAnalysis, SlackNHIInput]:
    """Fetch the Slack credential's live identity/scopes and run the existing pipeline.

    `SlackConnector.validate_credential()` calls `/auth.test` once and already
    returns identity, the real OAuth scopes (`x-oauth-scopes` response
    header), and accessible channels — unlike the GitHub PAT path, no second
    call is needed to assemble the inventory input.

    `agents/aws_inventory_service.py::analyze_aws_nhi_from_connector()` 와
    동일하게 `NHIAnalysis` 하나만이 아니라 조립에 쓰인 `SlackNHIInput` 도 함께
    반환한다 — 호출부(`api/app.py`)가 `channels`/`channels_error` 처럼 공통
    `NHIAnalysis`/`NHIProfile` 에는 실리지 않는 Slack 고유 필드를
    `provider_detail` 로 저장하려면 원본 입력이 필요하기 때문이다.
    """
    status = connector.validate_credential()
    if status.active is not True:
        raise AuthenticationError(
            f"Slack credential is not active: {status.error or 'unknown'}",
            status_code=401,
        )

    nhi = build_slack_nhi_input(status, status.accessible_resources)
    signals = AnalysisSignals(extra={"slack_account": status.account})
    analysis = (pipeline or NHIAnalysisPipeline()).analyze_slack_nhi(nhi, signals=signals)
    return analysis, nhi
