"""NHI 분석 Agent 패키지.

Credential 을 NHI 관점으로 해석하는 Agent 들의 모음이다.
개별 Agent 를 직접 쓸 수도 있고, `NHIAnalysisPipeline` 으로 한 번에 실행할 수도 있다.

입력은 두 경로다.
  * `analyze_finding` / `analyze_scan_result` — 저장소 스캔 결과
  * `analyze_github_nhi`                     — GitHub NHI 인벤토리 입력
"""

from agents.context_analysis_agent import ContextAnalysisAgent
from agents.discovery_agent import DiscoveryAgent
from agents.inventory_adapter import build_context, build_profile, build_signals
from agents.pipeline import NHIAnalysisPipeline, finding_from_dict
from agents.policy_evidence_agent import PolicyEvidenceAgent
from agents.recommendation_agent import RecommendationAgent
from agents.risk_scoring_agent import RiskScoringAgent
from agents.scope_translation_agent import ScopeTranslationAgent, expand_permissions
from agents.usage_analysis_agent import UsageAnalysisAgent

__all__ = [
    "ContextAnalysisAgent",
    "DiscoveryAgent",
    "NHIAnalysisPipeline",
    "PolicyEvidenceAgent",
    "RecommendationAgent",
    "RiskScoringAgent",
    "ScopeTranslationAgent",
    "UsageAnalysisAgent",
    "build_context",
    "build_profile",
    "build_signals",
    "expand_permissions",
    "finding_from_dict",
]
