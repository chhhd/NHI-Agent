"""Orchestration for converting GitHub API results into an NHI analysis."""

from __future__ import annotations

import logging
from typing import List, Optional

from agents.inventory_adapter import build_github_app_nhi_input, build_github_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from connectors.base_connector import ConnectorError
from connectors.github_app_connector import GitHubAppConnector
from connectors.github_connector import GitHubConnector
from core.nhi_models import AnalysisSignals, NHIAnalysis

logger = logging.getLogger(__name__)


def analyze_github_nhi_from_connector(
    connector: GitHubConnector,
    *,
    pipeline: Optional[NHIAnalysisPipeline] = None,
) -> NHIAnalysis:
    """Fetch the authenticated GitHub inventory and run the existing pipeline."""
    user = connector.get_authenticated_user()
    repositories = connector.list_accessible_repositories()
    nhi = build_github_nhi_input(user, repositories)
    signals = AnalysisSignals(extra={"github_user": user})
    return (pipeline or NHIAnalysisPipeline()).analyze_github_nhi(
        nhi, signals=signals
    )


def analyze_github_app_nhi_from_connector(
    connector: GitHubAppConnector,
    *,
    pipeline: Optional[NHIAnalysisPipeline] = None,
) -> List[NHIAnalysis]:
    """Fetch every GitHub App installation's inventory and run the existing pipeline.

    한 App 은 여러 조직/계정에 설치될 수 있으므로 PAT 경로(항상 단일 신원)와
    달리 Installation 당 하나씩 `NHIAnalysis` 를 만들어 리스트로 반환한다.

    흐름: `list_installations()` → Installation 별 `list_installation_repositories()`
    → `build_github_app_nhi_input()` → 기존 `NHIAnalysisPipeline.analyze_github_nhi()`
    (PAT 경로와 완전히 동일한 파이프라인 — Risk/Policy/Event/Scenario 로직은 그대로다).

    `list_installation_repositories()` 호출의 성공/실패 자체가 이 Installation
    이 실제로 살아있는지에 대한 라이브 검증이다 — 성공하면 `credential_verified=True`,
    실패(정지·권한 취소 등)하면 `credential_verified=False` 로 `build_github_app_nhi_input()`
    에 전달해 `credential_active` 판정에 반영한다(`agents/inventory_adapter.py` 참고).
    한 Installation 의 검증 실패가 다른 Installation 분석까지 막지 않도록 이 호출만
    개별적으로 감싼다.
    """
    active_pipeline = pipeline or NHIAnalysisPipeline()
    analyses: List[NHIAnalysis] = []

    for installation in connector.list_installations():
        installation_id = installation.get("installation_id")
        try:
            repositories = connector.list_installation_repositories(installation_id)
            credential_verified: Optional[bool] = True
        except ConnectorError as exc:
            logger.warning(
                "installation %s 저장소 조회 실패 — 검증 실패로 기록: %s",
                installation_id,
                exc,
            )
            repositories = []
            credential_verified = False
        nhi = build_github_app_nhi_input(
            installation, repositories, credential_verified=credential_verified
        )
        signals = AnalysisSignals(
            extra={
                "github_login": installation.get("account_login"),
                "github_installation": installation,
            }
        )
        analyses.append(active_pipeline.analyze_github_nhi(nhi, signals=signals))

    return analyses
