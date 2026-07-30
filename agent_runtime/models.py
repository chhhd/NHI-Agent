"""Agent 실행 모델 — 요청 / 작업 / 상태.

분석 파이프라인은 순서가 고정된 함수 호출이지만, Agent 는 목표와 중간 결과에 따라
"다음에 무엇을 실행할지" 를 스스로 정한다. 그러려면 목표·계획·실행 결과·오류를
한 곳에 기록해야 한다. 그 기록이 `NHIAgentState` 다.

요청 모델만 Pydantic 이다 (API 입구에서 잘못된 입력을 422 로 걸러야 한다).
내부 상태는 프로젝트 다른 계층과 같은 dataclass + `to_dict()` 규약을 따른다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.inventory_models import GitHubNHIInput
from core.nhi_models import NHIAnalysis


class AgentActionType(str, Enum):
    """Agent 가 실행할 수 있는 작업.

    문자열을 직접 쓰지 않고 Enum 으로 제한해 실행 가능한 도구를 명확히 한다.
    """

    #: NHI 통합 위험 분석 (권한 정규화 → 문맥 → 점수 → 정책 → 권고)
    ANALYZE_NHI = "ANALYZE_NHI"
    #: 접근 가능 저장소의 Secret 스캔
    SCAN_SECRETS = "SCAN_SECRETS"
    #: 정책 판정 결과 정리 (정책 카탈로그·임계값 포함)
    EVALUATE_POLICY = "EVALUATE_POLICY"
    #: 더 실행할 작업이 없음
    COMPLETE = "COMPLETE"


class AgentStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ActionOrigin(str, Enum):
    """작업이 최초 계획에서 나왔는가, 실행 중 재계획으로 추가됐는가."""

    INITIAL_PLAN = "INITIAL_PLAN"
    REPLANNER = "REPLANNER"


@dataclass
class AgentAction:
    """계획에 포함된 작업 1건."""

    step: int
    action_type: AgentActionType
    reason: str
    created_by: ActionOrigin = ActionOrigin.INITIAL_PLAN
    completed: bool = False
    failed: bool = False
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "action_type": self.action_type.value,
            "reason": self.reason,
            "created_by": self.created_by.value,
            "completed": self.completed,
            "failed": self.failed,
            "error_message": self.error_message,
            "result": self.result,
        }


class NHIAgentRequest(BaseModel):
    """Agent 실행 요청."""

    nhi: GitHubNHIInput
    goal: str = Field(
        default="NHI 의 보안 위험을 분석하고 개선 조치를 제안한다.",
        description="현재 규칙 기반 Planner 는 참고만 한다. LLM Planner 를 붙이면 핵심 입력이 된다.",
    )
    #: 저장소 Secret 스캔 허용 여부 (외부 API 호출·비용이 발생한다)
    allow_secret_scan: bool = False
    #: 정책 판정 결과 정리 단계 실행 여부
    allow_policy_evaluation: bool = False
    #: 한 번의 실행에서 스캔할 최대 저장소 수
    scan_repository_limit: int = Field(default=3, ge=1, le=20)
    #: 코드·인벤토리에 없는 외부 사실 (agent_status, observed_actions, exception_id ...)
    signals: Optional[Dict[str, Any]] = None


@dataclass
class NHIAgentState:
    """Agent 의 실행 과정과 결과 전체."""

    request: NHIAgentRequest
    status: AgentStatus = AgentStatus.PENDING
    plan: List[AgentAction] = field(default_factory=list)
    current_step: int = 0
    replan_count: int = 0
    #: NHI 통합 분석 결과 (ANALYZE_NHI 실행 후 채워진다)
    analysis: Optional[NHIAnalysis] = None
    secret_scan_result: Optional[Dict[str, Any]] = None
    policy_evaluation_result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    def has_action(self, action_type: AgentActionType) -> bool:
        """같은 작업이 이미 계획에 있는지 — 재계획 시 중복 추가 방지용."""
        return any(action.action_type is action_type for action in self.plan)

    def add_action(
        self,
        action_type: AgentActionType,
        reason: str,
        *,
        created_by: ActionOrigin = ActionOrigin.REPLANNER,
    ) -> Optional[AgentAction]:
        """계획 마지막에 작업을 추가한다. 이미 있으면 아무것도 하지 않는다."""
        if self.has_action(action_type):
            return None
        action = AgentAction(
            step=len(self.plan) + 1,
            action_type=action_type,
            reason=reason,
            created_by=created_by,
        )
        self.plan.append(action)
        return action

    def next_pending_action(self) -> Optional[AgentAction]:
        for action in self.plan:
            if not action.completed and not action.failed:
                return action
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.request.goal,
            "status": self.status.value,
            "current_step": self.current_step,
            "replan_count": self.replan_count,
            "plan": [action.to_dict() for action in self.plan],
            "nhi_analysis": self.analysis.to_dict() if self.analysis else None,
            "secret_scan": self.secret_scan_result,
            "policy_evaluation": self.policy_evaluation_result,
            "error_message": self.error_message,
            "request": self.request.model_dump(mode="json"),
        }
