"""Agent 실행 계층.

분석 파이프라인은 순서가 고정된 규칙 기반 엔진이고, 이 계층은 그 엔진과
Scanner·Policy 를 **도구로 보고 무엇을 실행할지 고르는** 실행 환경이다.

    Planner        최초 계획 (기본 분석 1단계)
    Tools          실행 가능한 도구 + Registry
    Replanner      분석 결과를 보고 추가 도구 선택
    Orchestrator   계획 실행 / 상태 관리 / 오류 기록

LLM 은 아직 쓰지 않는다. 위험 점수는 규칙 기반으로 유지해 재현성과 감사 가능성을
확보하고, LLM 은 나중에 `planner` 교체와 보고서 생성 단계에 붙인다.
"""

from agent_runtime.models import (
    ActionOrigin,
    AgentAction,
    AgentActionType,
    AgentStatus,
    GitHubInventoryAgentRequest,
    NHIAgentRequest,
    NHIAgentState,
)
from agent_runtime.orchestrator import run_nhi_agent
from agent_runtime.planner import create_agent_plan
from agent_runtime.replanner import (
    replan_after_analysis,
    replan_after_collection,
    replan_after_secret_scan,
)
from agent_runtime.tools import (
    AGENT_TOOL_REGISTRY,
    AgentTool,
    AnalyzeNHITool,
    CollectGitHubDataTool,
    PolicyEvaluationTool,
    SecretScanTool,
    build_tool_registry,
)

__all__ = [
    "AGENT_TOOL_REGISTRY",
    "ActionOrigin",
    "AgentAction",
    "AgentActionType",
    "AgentStatus",
    "AgentTool",
    "AnalyzeNHITool",
    "CollectGitHubDataTool",
    "GitHubInventoryAgentRequest",
    "NHIAgentRequest",
    "NHIAgentState",
    "PolicyEvaluationTool",
    "SecretScanTool",
    "build_tool_registry",
    "create_agent_plan",
    "replan_after_analysis",
    "replan_after_collection",
    "replan_after_secret_scan",
    "run_nhi_agent",
]
