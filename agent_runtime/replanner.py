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
    if state.replanned_after_analysis:
        return
    if state.analysis is None:
        raise ValueError("NHI 분석 결과가 없어 재계획을 수행할 수 없습니다.")

    state.replanned_after_analysis = True
    state.replan_count += 1
    risk = state.analysis.risk
    request = state.request

    scan_planned = state.has_action(AgentActionType.SCAN_SECRETS)
    if request.allow_secret_scan:
        if risk.level in SCAN_TRIGGER_LEVELS:
            state.add_action(
                AgentActionType.SCAN_SECRETS,
                reason=(
                    f"위험 등급이 {risk.level.value}(점수 {risk.score})이고 "
                    "사용자가 Secret 스캔을 허용했다. 접근 가능 저장소를 검사한다."
                ),
            )
            scan_planned = state.has_action(AgentActionType.SCAN_SECRETS)
        else:
            logger.info(
                "secret scan 생략: 위험 등급 %s — 추가 검사 근거 부족", risk.level.value
            )

    # Secret scan이 계획되면 그 결과를 관찰한 2차 Replanner가 종료 단계를 붙인다.
    if scan_planned:
        return

    if not request.allow_secret_scan:
        completion_reason = (
            "추가 Secret 스캔이 사용자에게 허용되지 않아 기본 분석만으로 실행을 마친다."
        )
    else:
        completion_reason = (
            f"위험 등급 {risk.level.value}이 추가 Secret 스캔 임계값에 미달해 실행을 마친다."
        )
    _append_final_actions(state, completion_reason=completion_reason)


def replan_after_collection(state: NHIAgentState) -> None:
    """GitHub 조직 수집 결과를 관찰해 다중 분석 또는 종료를 계획한다."""
    if state.replanned_after_collection:
        return
    if state.github_collection_result is None:
        raise ValueError("GitHub 수집 결과가 없어 재계획을 수행할 수 없습니다.")

    state.replanned_after_collection = True
    state.replan_count += 1
    result = state.github_collection_result
    if result.get("collection_executed") is not True:
        raise ValueError("GitHub 인벤토리 수집이 실행되지 않았습니다.")

    count = len(state.collected_inventory)
    complete = result.get("inventory_complete") is True
    coverage = (
        f"GitHub App installation {count}건 수집"
        + ("(전체 페이지 완료)" if complete else "(부분 수집)")
    )
    state.replan_notes.append(coverage)

    if count == 0:
        conclusion = (
            "완전한 수집 범위에서 일치하는 installation이 없다."
            if complete
            else "수집이 불완전하므로 installation이 없다고 단정하지 않는다."
        )
        state.add_action(
            AgentActionType.COMPLETE,
            reason=f"{coverage}. {conclusion}",
        )
        return

    if not getattr(state.request, "analyze", True):
        state.add_action(
            AgentActionType.COMPLETE,
            reason=f"{coverage}. 요청이 수집 전용이므로 분석 없이 종료한다.",
        )
        return

    state.add_action(
        AgentActionType.ANALYZE_NHI,
        reason=f"{coverage}. 각 installation을 독립 NHI로 분석한다.",
    )


def replan_after_secret_scan(state: NHIAgentState) -> None:
    """Secret 스캔 결과를 관찰해 정책 정리와 종료 단계를 계획한다."""
    if state.secret_scan_result is None:
        raise ValueError("Secret 스캔 결과가 없어 2차 재계획을 수행할 수 없습니다.")
    if state.replanned_after_secret_scan:
        return

    state.replanned_after_secret_scan = True
    state.replan_count += 1
    scan = state.secret_scan_result
    executed = scan.get("scan_executed") is True
    finding_count = scan.get("finding_count")
    scanned_count = len(scan.get("repositories_scanned") or [])
    failed_count = len(scan.get("repositories_failed") or [])
    skipped_count = len(scan.get("repositories_skipped") or [])
    scan_complete = scan.get("scan_complete") is True

    if not executed:
        observation = (
            "Secret 스캔이 실행되지 않았으므로 '이상 없음'으로 판단하지 않는다: "
            + str(scan.get("reason") or "미실행 사유 미상")
        )
    elif scanned_count == 0:
        observation = (
            "성공적으로 스캔한 저장소가 없어 Secret 유무를 판단할 수 없다."
        )
    elif isinstance(finding_count, int) and finding_count > 0:
        max_risk = max(
            (analysis.risk.score for analysis in state.discovered_analyses), default=0
        )
        observation = (
            f"Secret {finding_count}건과 후속 NHI 분석 {len(state.discovered_analyses)}건을 "
            f"저장소 {scanned_count}곳에서 관측했다(최대 위험 점수 {max_risk})."
        )
    else:
        observation = (
            f"성공적으로 스캔한 저장소 {scanned_count}곳의 실행 범위에서는 "
            "Secret을 발견하지 못했다."
        )

    if failed_count:
        observation += f" 저장소 {failed_count}곳은 실패했다."
    if skipped_count:
        observation += f" 실행 제한으로 저장소 {skipped_count}곳을 건너뛰었다."
    if executed and not scan_complete:
        observation += " 결과가 부분적이므로 전체 저장소 인벤토리에 대한 결론이 아니다."
    state.replan_notes.append(observation)

    _append_final_actions(
        state,
        completion_reason=f"Secret 스캔 결과를 반영한 2차 재계획 완료. {observation}",
    )


def _append_final_actions(state: NHIAgentState, *, completion_reason: str) -> None:
    request = state.request
    if request.allow_policy_evaluation:
        state.add_action(
            AgentActionType.EVALUATE_POLICY,
            reason="사용자가 정책 평가를 허용했다. 적용된 정책과 판정 근거를 정리한다.",
        )

    state.add_action(
        AgentActionType.COMPLETE,
        reason=completion_reason,
    )
