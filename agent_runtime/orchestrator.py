"""Agent 실행기.

    State 생성 → 초기 계획 → 다음 작업 탐색 → Tool 선택 → 실행 → 결과 기록
              → (기본 분석 후) 재계획 → 완료 또는 실패

계획이 실행 중에 늘어나므로 `for` 가 아니라 `while` 로 매 반복마다 최신 계획에서
다음 미완료 작업을 다시 찾는다.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from agent_runtime.models import (
    AgentRequest,
    AgentActionType,
    AgentStatus,
    NHIAgentRequest,
    NHIAgentState,
)
from agent_runtime.planner import create_agent_plan
from agent_runtime.replanner import (
    replan_after_analysis,
    replan_after_collection,
    replan_after_secret_scan,
)
from agent_runtime.tools import AGENT_TOOL_REGISTRY, AgentTool
from connectors.base_connector import ConnectorError

logger = logging.getLogger(__name__)

#: 무한 루프 방지 — 계획이 잘못 늘어나도 실행이 끝나도록 상한을 둔다.
MAX_STEPS = 20


def run_nhi_agent(
    request: AgentRequest,
    *,
    registry: Optional[Dict[AgentActionType, AgentTool]] = None,
) -> NHIAgentState:
    """요청을 받아 계획을 세우고 도구를 실행한다."""
    tools = registry if registry is not None else AGENT_TOOL_REGISTRY
    state = NHIAgentState(request=request, status=AgentStatus.PENDING)

    try:
        state.plan = create_agent_plan(request)
        state.status = AgentStatus.RUNNING

        for _ in range(MAX_STEPS):
            action = state.next_pending_action()
            if action is None:
                state.status = AgentStatus.COMPLETED
                break

            state.current_step = action.step

            # COMPLETE 는 Tool 호출 없이 실행 종료를 의미한다.
            if action.action_type is AgentActionType.COMPLETE:
                action.completed = True
                state.status = AgentStatus.COMPLETED
                break

            tool = tools.get(action.action_type)
            if tool is None:
                raise ValueError(
                    f"등록되지 않은 Agent Tool 입니다: {action.action_type.value}"
                )

            try:
                action.result = tool.execute(state)
                action.completed = True
            except Exception as tool_error:  # 어느 도구가 왜 실패했는지 남긴다
                action.failed = True
                action.error_message = str(tool_error)
                raise

            # 기본 분석 직후 한 번만 재계획한다.
            if (
                action.action_type is AgentActionType.COLLECT_GITHUB_DATA
                and not state.replanned_after_collection
            ):
                replan_after_collection(state)
            elif (
                action.action_type is AgentActionType.ANALYZE_NHI
                and not state.replanned_after_analysis
            ):
                replan_after_analysis(state)
            elif (
                action.action_type is AgentActionType.SCAN_SECRETS
                and not state.replanned_after_secret_scan
            ):
                replan_after_secret_scan(state)
        else:
            state.status = AgentStatus.FAILED
            state.error_message = f"실행 단계 상한({MAX_STEPS})을 초과했습니다."

    except Exception as error:
        state.status = AgentStatus.FAILED
        state.error_message = str(error)
        if isinstance(error, ConnectorError):
            state.error_status_code = error.status_code or 502
        target = getattr(getattr(request, "nhi", None), "nhi_id", None)
        target = target or getattr(request, "organization", "unknown")
        logger.exception("Agent 실행 실패 (target=%s)", target)

    return state
