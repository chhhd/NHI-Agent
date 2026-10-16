"""실시간 접근 통제 — ALLOW/REVIEW/DENY 판정을 실제 요청 집행 권고로 변환한다.

판정(`AgentAccessEvaluator`)과 집행(이 모듈)을 분리한다. 판정은 "무엇이
근거인가"만 말하고, 이 모듈은 "그래서 이 요청을 통과시킬지"만 순수 함수로
계산한다 — Gateway/Proxy는 이 값을 그대로 적용하면 된다.

`enforce` 모드(기본값, 고정값)의 정책:
  * ALLOW  → ALLOW (통과)
  * REVIEW → BLOCK  (사람이 확인하기 전까지 기본 차단)
  * DENY   → BLOCK  (무조건 차단)

`AccessControlMode`(`monitor`/`human_in_the_loop`)는 이 기본 정책을 **완화하는
용도로만** 쓴다 — DENY는 모드와 무관하게 항상 BLOCK이다(아래 docstring,
`enforcement_action_for()` 참고). 모드는 REVIEW(확정하지 못한, blocking=False
finding만 모인 상태)에만 영향을 준다. DPoP 검증 실패는 이 모듈에 도달하기도
전에 `/runtime/protected`가 무조건 차단하므로 모드의 영향을 받지 않는다.

평가기 자체가 응답하지 않을 때(타임아웃/장애)도 기본값은 BLOCK이다
(`ENFORCEMENT_ON_EVALUATOR_FAILURE`). 이 프로세스 **내부**에서 평가 로직이
예외를 던진 경우는 `build_fail_closed_decision()`으로 "정상 판정이 아니라
장애로 인한 차단"임을 구분한 `AgentAccessDecision`을 만들어 응답 스키마를
그대로 유지한다 — `api/app.py`가 이 함수를 쓴다. 이 decision의 outcome은
항상 DENY이므로, 아래에서 보듯 모드와 무관하게 BLOCK이다. Gateway가 네트워크
타임아웃으로 이 API 호출 자체를 못 받았을 때는 이 서버가 알 방법이 없으므로,
그 경우의 fail-closed 처리는 Gateway 쪽 타임아웃/예외 핸들러가
`ENFORCEMENT_ON_EVALUATOR_FAILURE`를 직접 참조해 구현해야 한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from backend.services.agent_access_evaluator import (
    AGENT_ACCESS_RULE_CATALOG,
    AgentAccessEvaluator,
)
from core.agent_access_models import (
    AgentAccessDecision,
    AgentAccessOutcome,
    AgentApiObservation,
    AgentThreatFinding,
)
from core.nhi_models import RiskLevel


class EnforcementAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class AccessControlMode(str, Enum):
    """실시간 접근 통제 운영 모드 (`core.config.AccessControlSettings.mode`).

    `ENFORCE`(기본값)는 기존 동작과 완전히 동일하다. `MONITOR`/
    `HUMAN_IN_THE_LOOP`는 REVIEW(확정하지 못한 요청)에만 영향을 주고, DENY는
    세 모드 모두 동일하게 BLOCK이다 — `enforcement_action_for()`가 이 불변식을
    지킨다. 알 수 없는 문자열이 설정되면 `from_str()`이 가장 안전한 값
    (`ENFORCE`)으로 fail-closed 한다.
    """

    ENFORCE = "enforce"
    MONITOR = "monitor"
    HUMAN_IN_THE_LOOP = "human_in_the_loop"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "AccessControlMode":
        try:
            return cls((value or "").strip().lower())
        except ValueError:
            return cls.ENFORCE


class EnforcementDirective(str, Enum):
    """`action`(ALLOW/BLOCK)에 "왜"라는 맥락을 더하는 표시 전용 값.

    Gateway가 실제로 지켜야 하는 값은 여전히 `EnforcementRecommendation.action`
    하나뿐이다 — `directive`는 동일한 BLOCK이라도 "정책상 영구 차단"
    (`BLOCK`)과 "사람 승인 대기"(`REQUIRE_APPROVAL`)를 구분해 보여주는 용도다.
    """

    PASS = "PASS"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALERT_ONLY = "ALERT_ONLY"


class CredentialConfirmationState(str, Enum):
    """Credential 폐기 여부가 실제로 확인됐는지 — 평가 outcome과는 별개 축.

    `recommended_enforcement.action`은 "이 요청을 막을지"만 말하므로,
    Credential 상태를 확인하지 못했다는 사실이 DENY/REVIEW 사유 목록에
    섞여 묻히지 않도록 이 필드로 항상 별도 표시한다.
    """

    REVOKED_CONFIRMED = "revoked_confirmed"
    NOT_REVOKED_CONFIRMED = "not_revoked_confirmed"
    UNKNOWN = "unknown"


#: 평가기 자체가 응답하지 않을 때(Gateway의 타임아웃/연결 실패)의 기본
#: 집행값. Gateway는 `/agent-access/evaluate` 호출이 실패하면 이 값을
#: 그대로 적용해야 한다(이 프로세스 밖의 실패라 서버가 감지할 수 없다).
ENFORCEMENT_ON_EVALUATOR_FAILURE = EnforcementAction.BLOCK

#: 평가 로직이 내부적으로 예외를 던졌을 때(이 프로세스 안의 실패) 남기는
#: 전용 규칙 ID. `AgentAccessEvaluator`의 규칙 카탈로그와 분리해 "정상
#: 판정 결과"와 "판정 자체가 실패함"을 명확히 구분한다.
EVALUATOR_FAILURE_RULE_ID = "EVALUATOR_UNAVAILABLE"


@dataclass
class EnforcementRecommendation:
    """`/agent-access/evaluate` 응답에 덧붙는 집행 권고 — 순수 계산 결과."""

    action: EnforcementAction
    reason: str
    credential_state: CredentialConfirmationState
    mode: AccessControlMode = AccessControlMode.ENFORCE
    directive: EnforcementDirective = EnforcementDirective.PASS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "credential_state": self.credential_state.value,
            "mode": self.mode.value,
            "directive": self.directive.value,
        }


def enforcement_action_for(
    outcome: AgentAccessOutcome, *, mode: AccessControlMode = AccessControlMode.ENFORCE
) -> EnforcementAction:
    """판정 outcome(+모드) → 집행 액션.

    ALLOW는 항상 ALLOW, **DENY는 모드와 무관하게 항상 BLOCK**이다 — DPoP 실패,
    비활성 Lifecycle, 폐기 확인된 Credential, 평가 실패(fail-closed)는 전부
    DENY로 들어오므로 이 한 줄이 "monitor 모드가 필수 보안 차단을 우회하지
    못한다"는 보장의 핵심이다. 모드는 REVIEW에만 영향을 준다 —
    `MONITOR`(섀도 모드)에서만 REVIEW를 통과시키고, `ENFORCE`/
    `HUMAN_IN_THE_LOOP`는 REVIEW도 BLOCK이다(`directive`로만 둘을 구분한다).
    """
    if outcome is AgentAccessOutcome.ALLOW:
        return EnforcementAction.ALLOW
    if outcome is AgentAccessOutcome.DENY:
        return EnforcementAction.BLOCK
    # REVIEW
    if mode is AccessControlMode.MONITOR:
        return EnforcementAction.ALLOW
    return EnforcementAction.BLOCK


def directive_for(
    outcome: AgentAccessOutcome,
    action: EnforcementAction,
    *,
    mode: AccessControlMode = AccessControlMode.ENFORCE,
) -> EnforcementDirective:
    if action is EnforcementAction.ALLOW:
        if outcome is AgentAccessOutcome.REVIEW:
            # MONITOR 모드에서만 REVIEW가 ALLOW로 내려온다 — 왜 통과시켰는지 표시.
            return EnforcementDirective.ALERT_ONLY
        return EnforcementDirective.PASS
    if mode is AccessControlMode.HUMAN_IN_THE_LOOP and outcome is AgentAccessOutcome.REVIEW:
        return EnforcementDirective.REQUIRE_APPROVAL
    return EnforcementDirective.BLOCK


def credential_confirmation_state(
    credential_known_revoked: Optional[bool],
) -> CredentialConfirmationState:
    if credential_known_revoked is True:
        return CredentialConfirmationState.REVOKED_CONFIRMED
    if credential_known_revoked is False:
        return CredentialConfirmationState.NOT_REVOKED_CONFIRMED
    return CredentialConfirmationState.UNKNOWN


def recommend_enforcement(
    decision: AgentAccessDecision,
    *,
    credential_known_revoked: Optional[bool] = None,
    mode: AccessControlMode = AccessControlMode.ENFORCE,
) -> EnforcementRecommendation:
    """판정 결과(+Credential 확인 상태, +운영 모드)로 집행 권고를 만든다. 순수 함수.

    `credential_known_revoked`는 호출부(API 레이어)가 저장소에서 조회한
    `NHIAccessContext.credential_known_revoked`를 그대로 넘긴다 — 이 함수는
    그 값을 다시 조회하지 않는다. `mode`를 생략하면 `ENFORCE`(기존 동작과
    완전히 동일)로 처리된다.
    """
    action = enforcement_action_for(decision.outcome, mode=mode)
    directive = directive_for(decision.outcome, action, mode=mode)
    return EnforcementRecommendation(
        action=action,
        reason=_reason_for(decision, action, mode=mode),
        credential_state=credential_confirmation_state(credential_known_revoked),
        mode=mode,
        directive=directive,
    )


def _reason_for(
    decision: AgentAccessDecision,
    action: EnforcementAction,
    *,
    mode: AccessControlMode = AccessControlMode.ENFORCE,
) -> str:
    if decision.outcome is AgentAccessOutcome.ALLOW:
        return "판정 결과 ALLOW — 위반·검토 사유 없음"
    if decision.outcome is AgentAccessOutcome.DENY:
        rule_ids = ", ".join(f.rule_id for f in decision.findings if f.blocking)
        return (
            f"판정 결과 DENY — 차단 규칙: {rule_ids or '명시된 차단 규칙 없음'} "
            "(모드와 무관하게 항상 차단)"
        )
    # REVIEW
    rule_ids = ", ".join(f.rule_id for f in decision.findings)
    if action is EnforcementAction.ALLOW:
        return (
            f"판정 결과 REVIEW — {mode.value} 모드라 통과시키되 사유를 남김: "
            f"{rule_ids or '명시된 검토 사유 없음'}"
        )
    if mode is AccessControlMode.HUMAN_IN_THE_LOOP:
        return (
            "판정 결과 REVIEW — human_in_the_loop 모드, 승인 전까지 보류(차단), 사유: "
            f"{rule_ids or '명시된 검토 사유 없음'}"
        )
    return (
        "판정 결과 REVIEW — 검토 전까지 기본 차단 정책 적용, 사유: "
        f"{rule_ids or '명시된 검토 사유 없음'}"
    )


def build_fail_closed_decision(observation: AgentApiObservation) -> AgentAccessDecision:
    """평가 로직 내부 예외 발생 시 쓰는 fail-closed `AgentAccessDecision`.

    정상 판정 경로와 동일한 응답 스키마를 유지하면서, outcome을 강제로
    `DENY`로 두고 `EVALUATOR_FAILURE_RULE_ID` finding으로 "정상 판정이
    아니라 장애로 인한 차단"임을 구분한다. `observation`은 평가기가 쓰는
    것과 동일하게 저장 전 redaction을 거친다.
    """
    safe_observation = AgentAccessEvaluator._sanitize_observation(observation)
    catalog_entry = AGENT_ACCESS_RULE_CATALOG[EVALUATOR_FAILURE_RULE_ID]
    finding = AgentThreatFinding(
        rule_id=EVALUATOR_FAILURE_RULE_ID,
        category=str(catalog_entry["category"]),
        severity=catalog_entry["severity"],
        title=str(catalog_entry["title"]),
        detail="평가 로직 내부 오류로 판정을 완료하지 못해 기본 차단(fail-closed)으로 처리함",
        evidence=[],
        blocking=True,
    )
    return AgentAccessDecision(
        decision_id=str(uuid4()),
        event_id=safe_observation.event_id,
        agent_id=safe_observation.claimed_agent_id,
        outcome=AgentAccessOutcome.DENY,
        overall_severity=RiskLevel.CRITICAL,
        matched_grant_id=None,
        findings=[finding],
        observation=safe_observation,
    )


__all__ = [
    "AccessControlMode",
    "CredentialConfirmationState",
    "EnforcementAction",
    "EnforcementDirective",
    "EnforcementRecommendation",
    "ENFORCEMENT_ON_EVALUATOR_FAILURE",
    "EVALUATOR_FAILURE_RULE_ID",
    "build_fail_closed_decision",
    "credential_confirmation_state",
    "directive_for",
    "enforcement_action_for",
    "recommend_enforcement",
]
