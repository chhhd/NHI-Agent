"""초기 계획 수립.

처음부터 모든 도구를 계획에 넣지 않는다. 추가 검사가 정말 필요한지는
기본 위험 분석 결과를 봐야 알 수 있고, 불필요한 스캔은 실행 시간·API 비용·
저장소 접근 범위를 늘리기 때문이다.

따라서 최초 계획은 기본 분석 한 단계뿐이며, 나머지는 `replanner` 가 결정한다.
LLM Planner 로 바꿀 때는 이 모듈만 교체하면 된다.
"""

from __future__ import annotations

from typing import List

from agent_runtime.models import (
    ActionOrigin,
    AgentAction,
    AgentActionType,
    NHIAgentRequest,
)


def create_agent_plan(request: NHIAgentRequest) -> List[AgentAction]:
    """최초 실행 계획 — 기본 NHI 위험 분석 1단계."""
    return [
        AgentAction(
            step=1,
            action_type=AgentActionType.ANALYZE_NHI,
            reason=(
                "추가 검사가 필요한지 판단하려면 먼저 기본 NHI 위험 분석 결과가 있어야 한다."
            ),
            created_by=ActionOrigin.INITIAL_PLAN,
        )
    ]
