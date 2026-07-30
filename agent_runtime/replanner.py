"""조건부 재계획 — 고정 파이프라인과 Agent 를 구분하는 지점.

기본 분석 결과를 관찰한 뒤 다음 작업을 정한다.
사용자가 허용했더라도 위험 등급이 낮으면 Secret 스캔을 실행하지 않는다.
설정 기반 실행("허용했으니 무조건 실행")과 다른 점이 여기다.
"""

from __future__ import annotations

import logging

from agent_runtime.models import AgentActionType, NHIAgentState
from core.nhi_models import RiskLevel

logger = logging.getLogger(__name__)

#: 이 등급 이상일 때만 추가 Secret 스캔을 계획한다.
SCAN_TRIGGER_LEVELS = {RiskLevel.HIGH, RiskLevel.CRITICAL}


def replan_after_analysis(state: NHIAgentState) -> None:
    """NHI 분석 결과를 보고 추가 작업을 계획에 붙인다."""
    if state.analysis is None:
        raise ValueError("NHI 분석 결과가 없어 재계획을 수행할 수 없습니다.")

    state.replan_count += 1
    risk = state.analysis.risk
    request = state.request

    if request.allow_secret_scan:
        if risk.level in SCAN_TRIGGER_LEVELS:
            state.add_action(
                AgentActionType.SCAN_SECRETS,
                reason=(
                    f"위험 등급이 {risk.level.value}(점수 {risk.score})이고 "
                    "사용자가 Secret 스캔을 허용했다. 접근 가능 저장소를 검사한다."
                ),
            )
        else:
            logger.info(
                "secret scan 생략: 위험 등급 %s — 추가 검사 근거 부족", risk.level.value
            )

    if request.allow_policy_evaluation:
        state.add_action(
            AgentActionType.EVALUATE_POLICY,
            reason="사용자가 정책 평가를 허용했다. 적용된 정책과 판정 근거를 정리한다.",
        )

    state.add_action(
        AgentActionType.COMPLETE,
        reason="현재 분석 결과와 허용 범위에서 필요한 작업이 모두 계획되었다.",
    )
