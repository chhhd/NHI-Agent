"""Agent Tool — 기존 기능을 Agent 가 호출할 수 있는 공통 인터페이스로 감싼다.

Orchestrator 는 도구 내부 구현을 모른다. `name` / `action_type` / `execute()` 만 안다.
새 도구는 Registry 에 등록하면 되고 실행기는 수정하지 않는다.

세 도구 모두 **실제 구현**이다. Mock 이 아니다.
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


class AgentTool(ABC):
    """모든 Agent Tool 의 공통 인터페이스."""

    name: str
    action_type: AgentActionType

    @abstractmethod
    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        """작업을 실행하고 결과를 dict 로 반환한다 (계획에 그대로 기록된다)."""


# ---------------------------------------------------------------------------
# 1) NHI 통합 분석
# ---------------------------------------------------------------------------
class AnalyzeNHITool(AgentTool):
    """인벤토리로 받은 NHI 를 통합 분석한다."""

    name = "analyze_nhi"
    action_type = AgentActionType.ANALYZE_NHI

    def __init__(self, *, pipeline: Optional[NHIAnalysisPipeline] = None) -> None:
        self.pipeline = pipeline or NHIAnalysisPipeline()

    def execute(self, state: NHIAgentState) -> Dict[str, Any]:
        analysis = self.pipeline.analyze_github_nhi(
            state.request.nhi, signals=state.request.signals
        )
        # 이후 단계(재계획·정책 정리)가 참조하므로 상태에 보관한다.
        state.analysis = analysis
        return analysis.to_dict()


# ---------------------------------------------------------------------------
# 2) 저장소 Secret 스캔
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
        repositories = [repo.name for repo in request.nhi.repositories]

        if not repositories:
            return self._not_executed(
                state, "접근 가능한 저장소 목록이 없어 스캔 대상이 없습니다."
            )

        planned = repositories[: request.scan_repository_limit]
        skipped = repositories[request.scan_repository_limit :]

        if not get_settings().github.token:
            return self._not_executed(
                state,
                "GITHUB_TOKEN 이 설정되지 않아 실제 저장소 스캔을 수행하지 않았습니다.",
                repositories_planned=planned,
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
                            **self._risk_summary(full_name, result.findings),
                        }
                    )
        except ConnectorError as exc:
            return self._not_executed(
                state,
                f"GitHub 연동에 실패해 스캔을 수행하지 못했습니다: {exc.message}",
                repositories_planned=planned,
            )

        result_payload: Dict[str, Any] = {
            "scan_executed": True,
            "repositories_scanned": scanned,
            "repositories_skipped": skipped,
            "repositories_failed": failed,
            "scanned_files": scanned_files,
            "finding_count": len(findings),
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
        self, repository: str, findings: List[SecretFinding]
    ) -> Dict[str, Any]:
        """탐지 결과를 같은 분석 엔진으로 채점해 요약한다 (스캔 → 분석 연결)."""
        if not findings:
            return {"nhi_analysis": None}
        report = self.pipeline.analyze_findings(
            findings, repository=repository, build_graph=False
        )
        return {"nhi_analysis": report.summary()}

    @staticmethod
    def _not_executed(
        state: NHIAgentState, reason: str, **extra: Any
    ) -> Dict[str, Any]:
        """실행하지 않았음을 명시한다. 미검사를 '이상 없음' 으로 보고하지 않는다."""
        payload: Dict[str, Any] = {
            "scan_executed": False,
            "finding_count": None,
            "reason": reason,
            **extra,
        }
        state.secret_scan_result = payload
        return payload


# ---------------------------------------------------------------------------
# 3) 정책 판정 정리
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

        payload = {
            "policy_evaluated": True,
            "outcome": policy.outcome.value,
            "violation_count": len(policy.violations),
            "violations": [violation.to_dict() for violation in policy.violations],
            "auto_remediable": policy.auto_remediable,
            "human_review_required": policy.human_review_required,
            "exception_applied": policy.exception_applied,
            "evidence": policy.evidence,
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
    connector_factory: Callable[[], GitHubConnector] = GitHubConnector,
) -> Dict[AgentActionType, AgentTool]:
    """작업 유형 → Tool 매핑을 만든다.

    분석 파이프라인을 도구들이 공유하므로 정책 설정(`PolicyConfig`)이 한 곳에서 결정된다.
    테스트나 다른 환경에서는 인자로 구현을 갈아끼운다.
    """
    shared = pipeline or NHIAnalysisPipeline()
    return {
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
