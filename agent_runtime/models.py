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
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from core.inventory_models import GitHubNHIInput
from core.nhi_models import NHIAnalysis
from security.redaction import sanitize_security_value


class AgentActionType(str, Enum):
    """Agent 가 실행할 수 있는 작업.

    문자열을 직접 쓰지 않고 Enum 으로 제한해 실행 가능한 도구를 명확히 한다.
    """

    #: NHI 통합 위험 분석 (권한 정규화 → 문맥 → 점수 → 정책 → 권고)
    ANALYZE_NHI = "ANALYZE_NHI"
    #: GitHub 조직의 App installation 인벤토리 읽기 전용 수집
    COLLECT_GITHUB_DATA = "COLLECT_GITHUB_DATA"
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


class GitHubInventoryAgentRequest(BaseModel):
    """조직 GitHub App 인벤토리 수집 Agent 요청.

    기존 단건 ``NHIAgentRequest`` 계약을 변경하지 않고 별도 모드로 둔다.
    GitHub token은 본문으로 받지 않고 서버의 ``GITHUB_INVENTORY_TOKEN``만 사용한다.
    """

    organization: str = Field(
        ...,
        min_length=1,
        max_length=39,
        pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$",
    )
    goal: str = "GitHub 조직의 NHI를 수집하고 권한·범위·정책 위험을 분석한다."
    model_config = {"extra": "forbid"}

    # 동기 요청에서 전건 분석·정책 평가까지 수행하므로 응답/CPU 상한을 보수적으로 둔다.
    inventory_limit: int = Field(default=100, ge=1, le=500)
    analyze: bool = True
    allow_secret_scan: bool = False
    allow_policy_evaluation: bool = True
    scan_repository_limit: int = Field(default=3, ge=1, le=20)
    signals: Optional[Dict[str, Any]] = None
    signals_by_nhi_id: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


AgentRequest = Union[NHIAgentRequest, GitHubInventoryAgentRequest]


@dataclass
class NHIAgentState:
    """Agent 의 실행 과정과 결과 전체."""

    request: AgentRequest
    status: AgentStatus = AgentStatus.PENDING
    plan: List[AgentAction] = field(default_factory=list)
    current_step: int = 0
    replan_count: int = 0
    replanned_after_collection: bool = False
    replanned_after_analysis: bool = False
    replanned_after_secret_scan: bool = False
    replan_notes: List[str] = field(default_factory=list)
    #: NHI 통합 분석 결과 (ANALYZE_NHI 실행 후 채워진다)
    analysis: Optional[NHIAnalysis] = None
    github_collection_result: Optional[Dict[str, Any]] = None
    collected_inventory: List[GitHubNHIInput] = field(default_factory=list)
    inventory_analyses: List[NHIAnalysis] = field(default_factory=list)
    secret_scan_result: Optional[Dict[str, Any]] = None
    #: Secret scan에서 새로 발견한 NHI 분석. 원문 Secret 없이 마스킹된 분석만 보관한다.
    discovered_analyses: List[NHIAnalysis] = field(default_factory=list)
    policy_evaluation_result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    error_status_code: Optional[int] = None

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
        """작업을 종료 단계 앞에 추가한다. 이미 있으면 아무것도 하지 않는다.

        Replanner가 ``COMPLETE``를 붙인 뒤 후속 검사를 발견할 수도 있다. 이때 단순히
        맨 뒤에 append하면 실행기가 COMPLETE에서 멈춰 후속 작업은 영원히 실행되지
        않으므로, 아직 실행되지 않은 COMPLETE 바로 앞에 삽입한다.
        """
        if self.has_action(action_type):
            return None
        action = AgentAction(
            step=0,
            action_type=action_type,
            reason=reason,
            created_by=created_by,
        )
        pending_complete_index = next(
            (
                index
                for index, planned in enumerate(self.plan)
                if planned.action_type is AgentActionType.COMPLETE
                and not planned.completed
                and not planned.failed
            ),
            len(self.plan),
        )
        self.plan.insert(pending_complete_index, action)
        for step, planned in enumerate(self.plan, start=1):
            planned.step = step
        return action

    def next_pending_action(self) -> Optional[AgentAction]:
        for action in self.plan:
            if not action.completed and not action.failed:
                return action
        return None

    def to_dict(self) -> Dict[str, Any]:
        request_payload = self.request.model_dump(mode="json")
        for key in ("signals", "signals_by_nhi_id"):
            if key in request_payload:
                request_payload[key] = sanitize_security_value(request_payload[key])

        plan = []
        for action in self.plan:
            serialized = action.to_dict()
            result = serialized.get("result")
            if isinstance(result, dict):
                # 상세 목록은 top-level github_collection/inventory_analyses에 한 번만 둔다.
                if action.action_type is AgentActionType.COLLECT_GITHUB_DATA:
                    serialized["result"] = {
                        key: value for key, value in result.items() if key != "inventory"
                    }
                elif (
                    action.action_type is AgentActionType.ANALYZE_NHI
                    and self.github_collection_result is not None
                ):
                    serialized["result"] = {
                        key: value for key, value in result.items() if key != "analyses"
                    }
            plan.append(serialized)

        return {
            "goal": self.request.goal,
            "status": self.status.value,
            "current_step": self.current_step,
            "replan_count": self.replan_count,
            "replan_notes": list(self.replan_notes),
            "plan": plan,
            "nhi_analysis": self.analysis.to_dict() if self.analysis else None,
            "github_collection": self.github_collection_result,
            "inventory_analyses": [
                analysis.to_dict() for analysis in self.inventory_analyses
            ],
            "secret_scan": self.secret_scan_result,
            "discovered_secret_analyses": [
                analysis.to_dict() for analysis in self.discovered_analyses
            ],
            "policy_evaluation": self.policy_evaluation_result,
            "error_message": self.error_message,
            "error_status_code": self.error_status_code,
            "request": request_payload,
        }
