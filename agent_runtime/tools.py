"""Agent Tool — 기존 기능을 Agent 가 호출할 수 있는 공통 인터페이스로 감싼다.

Orchestrator 는 도구 내부 구현을 모른다. `name` / `action_type` / `execute()` 만 안다.
새 도구는 Registry 에 등록하면 되고 실행기는 수정하지 않는다.

네 도구 모두 **실제 구현**이다. Mock 이 아니다.
  * COLLECT_GITHUB_DATA → GitHub 조직 App installation 인벤토리 수집
  * ANALYZE_NHI     → `agents/pipeline.py` 의 통합 분석
  * SCAN_SECRETS    → `scanner/` + `connectors/github_connector.py` 실제 저장소 스캔
  * EVALUATE_POLICY → `policy/` 규칙으로 판정된 결과 + 정책 카탈로그·임계값

다만 SCAN_SECRETS 는 외부 API 호출이 필요하므로, 토큰이 없거나 연동에 실패하면
"실행하지 않았다" 는 사실을 결과에 명시한다. 검사하지 않은 것을 "Secret 없음" 으로
보고하지 않는 것이 이 계층의 원칙이다.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from agent_runtime.models import AgentActionType, NHIAgentState
from agents.pipeline import NHIAnalysisPipeline
from connectors.base_connector import ConnectorError
from connectors.github_connector import GitHubConnector
from core.config import get_settings
from core.models import ScanTrigger, SecretFinding
from policy.rules import FORCED_CRITICAL_RULES, POLICIES
from scanner.scan_service import SecretScanService

logger = logging.getLogger(__name__)


def _policy_summary(analysis) -> Dict[str, Any]:
    return {
        "fingerprint": analysis.fingerprint,
        "nhi_id": analysis.profile.nhi_id,
        "provider": analysis.profile.provider,
        "nhi_type": analysis.profile.nhi_type.value,
        "risk_level": analysis.risk.level.value,
        "risk_score": analysis.risk.score,
        "forced_rules": [item["rule_id"] for item in analysis.risk.forced_rules],
        "violations": [
            violation.to_dict() for violation in analysis.policy.violations
        ],
        "human_review_required": analysis.policy.human_review_required,
        "recommended_action": analysis.recommended_action.value,
    }


class AgentTool(ABC):
    """모든 Agent Tool 의 공통 인터페이스."""

    name: str
    action_type: AgentActionType

    @abstractmethod
    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        """작업을 실행하고 결과를 dict 로 반환한다 (계획에 그대로 기록된다)."""


# ---------------------------------------------------------------------------
# 1) GitHub 조직 데이터 수집
# ---------------------------------------------------------------------------
class CollectGitHubDataTool(AgentTool):
    """조직의 GitHub App installation을 읽기 전용으로 수집한다."""

    name = "collect_github_data"
    action_type = AgentActionType.COLLECT_GITHUB_DATA

    def __init__(
        self,
        *,
        connector_factory: Callable[[], GitHubConnector] = GitHubConnector.for_inventory,
    ) -> None:
        self.connector_factory = connector_factory

    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        request = state.request
        organization = getattr(request, "organization", None)
        if not organization:
            raise ValueError("GitHub 조직 수집 요청에 organization이 필요합니다.")

        with self.connector_factory() as github:
            result = github.discover_organization_apps(
                organization, limit=getattr(request, "inventory_limit", 100)
            )
        state.collected_inventory = list(result.items)
        payload = result.to_dict()
        state.github_collection_result = payload
        return {key: value for key, value in payload.items() if key != "inventory"}


# ---------------------------------------------------------------------------
# 2) NHI 통합 분석
# ---------------------------------------------------------------------------
class AnalyzeNHITool(AgentTool):
    """인벤토리로 받은 NHI 를 통합 분석한다."""

    name = "analyze_nhi"
    action_type = AgentActionType.ANALYZE_NHI

    def __init__(self, *, pipeline: Optional[NHIAnalysisPipeline] = None) -> None:
        self.pipeline = pipeline or NHIAnalysisPipeline()

    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        if state.github_collection_result is not None:
            analyses = []
            signals_by_nhi_id = getattr(state.request, "signals_by_nhi_id", {})
            for item in state.collected_inventory:
                item_signals = signals_by_nhi_id.get(
                    item.nhi_id, getattr(state.request, "signals", None)
                )
                analyses.append(
                    self.pipeline.analyze_github_nhi(item, signals=item_signals)
                )
            state.inventory_analyses = analyses
            if not analyses:
                return {
                    "analyzed_count": 0,
                    "primary_nhi_id": None,
                    "risk_distribution": {},
                }

            state.analysis = max(
                analyses,
                key=lambda analysis: (
                    analysis.risk.score,
                    analysis.profile.nhi_id,
                ),
            )
            risk_distribution: Dict[str, int] = {}
            for analysis in analyses:
                level = analysis.risk.level.value
                risk_distribution[level] = risk_distribution.get(level, 0) + 1
            return {
                "analyzed_count": len(analyses),
                "primary_nhi_id": state.analysis.profile.nhi_id,
                "risk_distribution": risk_distribution,
            }

        analysis = self.pipeline.analyze_github_nhi(
            state.request.nhi, signals=state.request.signals
        )
        # 이후 단계(재계획·정책 정리)가 참조하므로 상태에 보관한다.
        state.analysis = analysis
        return analysis.to_dict()


# ---------------------------------------------------------------------------
# 3) 저장소 Secret 스캔
# ---------------------------------------------------------------------------
class SecretScanTool(AgentTool):
    """NHI 가 접근할 수 있는 저장소를 실제로 스캔한다."""

    name = "secret_scanner"
    action_type = AgentActionType.SCAN_SECRETS

    def __init__(
        self,
        *,
        pipeline: Optional[NHIAnalysisPipeline] = None,
        scan_service: Optional[SecretScanService] = None,
        connector_factory: Callable[[], GitHubConnector] = GitHubConnector,
    ) -> None:
        self.pipeline = pipeline or NHIAnalysisPipeline()
        self.scan_service = scan_service or SecretScanService()
        self.connector_factory = connector_factory

    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        request = state.request
        # 한 실행의 산출물만 상태에 남긴다. Tool 재호출이나 context manager 종료
        # 예외가 이전/부분 결과를 새 응답과 섞지 않게 한다.
        state.discovered_analyses.clear()
        inventory = state.collected_inventory
        if not inventory:
            direct_nhi = getattr(request, "nhi", None)
            inventory = [direct_nhi] if direct_nhi is not None else []
        repositories: List[str] = []
        for nhi in inventory:
            for repo in nhi.repositories:
                if repo.name not in repositories:
                    repositories.append(repo.name)

        if not repositories:
            incomplete = any(
                not nhi.repository_inventory_complete for nhi in inventory
            )
            reason = (
                "GitHub 조직 installation API가 개별 저장소 이름을 제공하지 않아 "
                "Secret 스캔 대상을 확정할 수 없습니다."
                if incomplete
                else "접근 가능한 저장소 목록이 없어 스캔 대상이 없습니다."
            )
            return self._not_executed(
                state, reason
            )

        planned = repositories[: request.scan_repository_limit]
        skipped = repositories[request.scan_repository_limit :]

        if not get_settings().github.token:
            return self._not_executed(
                state,
                "GITHUB_TOKEN 이 설정되지 않아 실제 저장소 스캔을 수행하지 않았습니다.",
                repositories_planned=planned,
                repositories_skipped=skipped,
            )

        scanned: List[Dict[str, Any]] = []
        failed: List[Dict[str, str]] = []
        findings: List[SecretFinding] = []
        scanned_files = 0

        try:
            with self.connector_factory() as github:
                for full_name in planned:
                    try:
                        files = github.list_files(full_name)
                        targets = github.build_scan_targets(
                            full_name, [item["path"] for item in files]
                        )
                        result = self.scan_service.scan_targets(
                            targets, repository=full_name, trigger=ScanTrigger.MANUAL
                        )
                    except ConnectorError as exc:
                        logger.warning("스캔 실패 repo=%s: %s", full_name, exc)
                        failed.append({"repository": full_name, "error": exc.message})
                        continue

                    scanned_files += result.scanned_files
                    findings.extend(result.findings)
                    scanned.append(
                        {
                            "repository": full_name,
                            "scanned_files": result.scanned_files,
                            "finding_count": len(result.findings),
                            **self._risk_summary(state, full_name, result.findings),
                        }
                    )
        except ConnectorError as exc:
            state.discovered_analyses.clear()
            return self._not_executed(
                state,
                f"GitHub 연동에 실패해 스캔을 수행하지 못했습니다: {exc.message}",
                repositories_planned=planned,
                repositories_skipped=skipped,
            )

        result_payload: Dict[str, Any] = {
            "scan_executed": True,
            "scan_complete": not failed and not skipped and len(scanned) == len(planned),
            "repositories_scanned": scanned,
            "repositories_skipped": skipped,
            "repositories_failed": failed,
            "repository_count_planned": len(planned),
            "repository_count_scanned": len(scanned),
            "repository_count_failed": len(failed),
            "repository_count_skipped": len(skipped),
            "scanned_files": scanned_files,
            "finding_count": len(findings),
            "discovered_analysis_count": len(state.discovered_analyses),
            "max_discovered_risk_score": max(
                (analysis.risk.score for analysis in state.discovered_analyses),
                default=0,
            ),
            "discovered_human_review_required": any(
                analysis.policy.human_review_required
                for analysis in state.discovered_analyses
            ),
            "findings": [finding.to_dict() for finding in findings],
            "note": (
                "탐지된 값은 마스킹된 상태이며 원문은 반환하지 않습니다. "
                "토큰 유효성 재검증은 이 단계에서 수행하지 않습니다."
            ),
        }
        state.secret_scan_result = result_payload
        return result_payload

    # ------------------------------------------------------------------
    def _risk_summary(
        self,
        state: NHIAgentState,
        repository: str,
        findings: List[SecretFinding],
    ) -> Dict[str, Any]:
        """탐지 결과를 같은 분석 엔진으로 채점해 요약한다 (스캔 → 분석 연결)."""
        if not findings:
            return {"nhi_analysis": None}
        report = self.pipeline.analyze_findings(
            findings, repository=repository, build_graph=False
        )
        state.discovered_analyses.extend(report.analyses)
        return {"nhi_analysis": report.summary()}

    @staticmethod
    def _not_executed(
        state: NHIAgentState, reason: str, **extra: Any
    ) -> Dict[str, Any]:
        """실행하지 않았음을 명시한다. 미검사를 '이상 없음' 으로 보고하지 않는다."""
        payload: Dict[str, Any] = {
            "scan_executed": False,
            "scan_complete": False,
            "finding_count": None,
            "discovered_analysis_count": 0,
            "repository_count_scanned": 0,
            "reason": reason,
            **extra,
        }
        state.secret_scan_result = payload
        return payload


# ---------------------------------------------------------------------------
# 4) 정책 판정 정리
# ---------------------------------------------------------------------------
class PolicyEvaluationTool(AgentTool):
    """적용된 정책과 판정 근거를 감사 가능한 형태로 정리한다.

    정책 판정 자체는 분석 파이프라인 안에서 이미 실행된다(점수 계산이 위반 건수를
    사용하기 때문에 순서를 바꿀 수 없다). 이 단계는 그 결과에 정책 카탈로그와
    임계값을 붙여 "무엇을 기준으로 판정했는가" 를 드러낸다.
    """

    name = "policy_evaluation"
    action_type = AgentActionType.EVALUATE_POLICY

    def __init__(self, *, pipeline: Optional[NHIAnalysisPipeline] = None) -> None:
        self.pipeline = pipeline or NHIAnalysisPipeline()

    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        if state.analysis is None:
            payload: Dict[str, Any] = {
                "policy_evaluated": False,
                "reason": "NHI 분석 결과가 없어 정책을 평가할 수 없습니다.",
            }
            state.policy_evaluation_result = payload
            return payload

        policy = state.analysis.policy
        config = self.pipeline.config
        discovered = [_policy_summary(analysis) for analysis in state.discovered_analyses]
        inventory = [_policy_summary(analysis) for analysis in state.inventory_analyses]

        aggregate_analyses = []
        seen = set()
        for analysis in [
            state.analysis,
            *state.inventory_analyses,
            *state.discovered_analyses,
        ]:
            if analysis is None:
                continue
            identity = (
                analysis.profile.nhi_id,
                analysis.fingerprint,
                analysis.repository,
            )
            if identity in seen:
                continue
            seen.add(identity)
            aggregate_analyses.append(analysis)
        aggregate_violations = sum(
            len(analysis.policy.violations) for analysis in aggregate_analyses
        )

        payload = {
            "policy_evaluated": True,
            "outcome": policy.outcome.value,
            "violation_count": len(policy.violations),
            "violations": [violation.to_dict() for violation in policy.violations],
            "auto_remediable": policy.auto_remediable,
            "human_review_required": policy.human_review_required,
            "exception_applied": policy.exception_applied,
            "evidence": policy.evidence,
            "inventory_policies": inventory,
            "inventory_summary": {
                "total": len(inventory),
                "critical_high": sum(
                    1
                    for item in inventory
                    if item["risk_level"] in {"CRITICAL", "HIGH"}
                ),
                "human_review_required": sum(
                    1 for item in inventory if item["human_review_required"]
                ),
            },
            "discovered_secret_policies": discovered,
            "discovered_summary": {
                "total": len(discovered),
                "critical_high": sum(
                    1
                    for item in discovered
                    if item["risk_level"] in {"CRITICAL", "HIGH"}
                ),
                "human_review_required": sum(
                    1 for item in discovered if item["human_review_required"]
                ),
            },
            # 기존 최상위 필드는 최초 분석 대상의 정책을 뜻한다. 2차 스캔에서
            # 발견된 NHI까지 포함한 전체 판단은 aggregate_* 필드로 명시한다.
            "aggregate_analysis_count": len(aggregate_analyses),
            "aggregate_max_risk_score": max(
                (analysis.risk.score for analysis in aggregate_analyses), default=0
            ),
            "aggregate_violation_count": aggregate_violations,
            "aggregate_human_review_required": any(
                analysis.policy.human_review_required for analysis in aggregate_analyses
            ),
            "aggregate_auto_remediable": bool(aggregate_analyses) and all(
                analysis.policy.auto_remediable for analysis in aggregate_analyses
            ),
            "evaluated_policies": sorted(POLICIES),
            "forced_critical_rules": sorted(FORCED_CRITICAL_RULES),
            "thresholds": {
                "max_token_age_days": config.max_token_age_days,
                "rotation_period_days": config.rotation_period_days,
                "inactive_days": config.inactive_days,
                "broad_repository_access_threshold": config.broad_repository_access_threshold,
                "human_review_min_score": config.human_review_min_score,
                "auto_remediation_max_score": config.auto_remediation_max_score,
            },
        }
        state.policy_evaluation_result = payload
        return payload


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def build_tool_registry(
    *,
    pipeline: Optional[NHIAnalysisPipeline] = None,
    scan_service: Optional[SecretScanService] = None,
    collection_connector_factory: Callable[
        [], GitHubConnector
    ] = GitHubConnector.for_inventory,
    connector_factory: Callable[[], GitHubConnector] = GitHubConnector,
) -> Dict[AgentActionType, AgentTool]:
    """작업 유형 → Tool 매핑을 만든다.

    분석 파이프라인을 도구들이 공유하므로 정책 설정(`PolicyConfig`)이 한 곳에서 결정된다.
    테스트나 다른 환경에서는 인자로 구현을 갈아끼운다.
    """
    shared = pipeline or NHIAnalysisPipeline()
    return {
        AgentActionType.COLLECT_GITHUB_DATA: CollectGitHubDataTool(
            connector_factory=collection_connector_factory
        ),
        AgentActionType.ANALYZE_NHI: AnalyzeNHITool(pipeline=shared),
        AgentActionType.SCAN_SECRETS: SecretScanTool(
            pipeline=shared,
            scan_service=scan_service,
            connector_factory=connector_factory,
        ),
        AgentActionType.EVALUATE_POLICY: PolicyEvaluationTool(pipeline=shared),
    }


#: 기본 Registry (API 서버가 사용)
AGENT_TOOL_REGISTRY: Dict[AgentActionType, AgentTool] = build_tool_registry()
