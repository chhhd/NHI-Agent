"""backend/services/access_enforcement.py — ALLOW/REVIEW/DENY → 집행 권고 변환.

순수 함수만 다룬다(storage/네트워크 없음). ALLOW만 통과, REVIEW/DENY는 전부
차단, 평가기 내부 실패도 기본 차단이라는 정책과, Credential 상태 미확인이
별도 근거로 표시되는지를 확인한다.
"""

from __future__ import annotations

import pytest

from backend.services.access_enforcement import (
    ENFORCEMENT_ON_EVALUATOR_FAILURE,
    EVALUATOR_FAILURE_RULE_ID,
    AccessControlMode,
    CredentialConfirmationState,
    EnforcementAction,
    EnforcementDirective,
    build_fail_closed_decision,
    credential_confirmation_state,
    directive_for,
    enforcement_action_for,
    recommend_enforcement,
)
from backend.services.agent_access_evaluator import AGENT_ACCESS_RULE_CATALOG
from core.agent_access_models import (
    AgentAccessDecision,
    AgentAccessOutcome,
    AgentApiObservation,
    AgentThreatFinding,
)
from core.nhi_models import PermissionLevel, RiskLevel


def _observation(**overrides) -> AgentApiObservation:
    values = {
        "event_id": "evt-1",
        "claimed_agent_id": "finance-agent",
        "provider": "github",
        "nhi_id": "github-bot-1",
        "action": "GET /acme/support/contents",
    }
    values.update(overrides)
    return AgentApiObservation(**values)


def _decision(outcome: AgentAccessOutcome, *, findings=None) -> AgentAccessDecision:
    return AgentAccessDecision(
        decision_id="dec-1",
        event_id="evt-1",
        agent_id="finance-agent",
        outcome=outcome,
        overall_severity=RiskLevel.CRITICAL if outcome is AgentAccessOutcome.DENY else None,
        matched_grant_id=None,
        findings=findings or [],
        observation=_observation(),
    )


# ---------------------------------------------------------------------------
# enforcement_action_for — 고정 정책: ALLOW만 ALLOW, 나머지는 전부 BLOCK
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "outcome,expected",
    [
        (AgentAccessOutcome.ALLOW, EnforcementAction.ALLOW),
        (AgentAccessOutcome.REVIEW, EnforcementAction.BLOCK),
        (AgentAccessOutcome.DENY, EnforcementAction.BLOCK),
    ],
)
def test_enforcement_action_for_outcome(outcome, expected):
    assert enforcement_action_for(outcome) is expected


def test_all_outcomes_are_covered_by_enforcement_mapping():
    """AgentAccessOutcome에 새 값이 추가되면 이 테스트가 깨져 정책 갱신을 강제한다."""
    for outcome in AgentAccessOutcome:
        action = enforcement_action_for(outcome)
        assert action in (EnforcementAction.ALLOW, EnforcementAction.BLOCK)
        if outcome is not AgentAccessOutcome.ALLOW:
            assert action is EnforcementAction.BLOCK


# ---------------------------------------------------------------------------
# credential_confirmation_state — Credential 미확인을 별도 축으로 표시
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        (True, CredentialConfirmationState.REVOKED_CONFIRMED),
        (False, CredentialConfirmationState.NOT_REVOKED_CONFIRMED),
        (None, CredentialConfirmationState.UNKNOWN),
    ],
)
def test_credential_confirmation_state(value, expected):
    assert credential_confirmation_state(value) is expected


# ---------------------------------------------------------------------------
# recommend_enforcement — 판정 + Credential 신호 → 전체 권고
# ---------------------------------------------------------------------------
def test_allow_decision_recommends_allow_and_unknown_credential_by_default():
    decision = _decision(AgentAccessOutcome.ALLOW)

    recommendation = recommend_enforcement(decision)

    assert recommendation.action is EnforcementAction.ALLOW
    assert recommendation.credential_state is CredentialConfirmationState.UNKNOWN
    assert "ALLOW" in recommendation.reason


def test_review_decision_recommends_block_with_reason_citing_findings():
    finding = AgentThreatFinding(
        rule_id="NHI_LIFECYCLE_PENDING_ACTIVATION",
        category="coverage",
        severity=RiskLevel.MEDIUM,
        title="미활성화 NHI 사용",
        detail="등록만 되고 아직 ACTIVE 전",
        blocking=False,
    )
    decision = _decision(AgentAccessOutcome.REVIEW, findings=[finding])

    recommendation = recommend_enforcement(decision)

    assert recommendation.action is EnforcementAction.BLOCK
    assert "REVIEW" in recommendation.reason
    assert "NHI_LIFECYCLE_PENDING_ACTIVATION" in recommendation.reason


def test_deny_decision_recommends_block_with_blocking_rule_ids_only():
    blocking = AgentThreatFinding(
        rule_id="NHI_LIFECYCLE_NOT_ACTIVE",
        category="lifecycle",
        severity=RiskLevel.CRITICAL,
        title="비활성/파기된 NHI 사용",
        detail="DEACTIVATED",
        blocking=True,
    )
    non_blocking = AgentThreatFinding(
        rule_id="NHI_LIFECYCLE_UNKNOWN",
        category="coverage",
        severity=RiskLevel.MEDIUM,
        title="상태 미확인",
        detail="있을 리 없지만 섞여 들어온 경우를 가정",
        blocking=False,
    )
    decision = _decision(AgentAccessOutcome.DENY, findings=[blocking, non_blocking])

    recommendation = recommend_enforcement(decision)

    assert recommendation.action is EnforcementAction.BLOCK
    assert "NHI_LIFECYCLE_NOT_ACTIVE" in recommendation.reason
    assert "NHI_LIFECYCLE_UNKNOWN" not in recommendation.reason  # non-blocking은 DENY 사유에서 제외


def test_credential_state_is_reported_separately_from_outcome():
    """Credential 미확인은 ALLOW 결과에도 섞이지 않고 항상 별도로 드러난다."""
    decision = _decision(AgentAccessOutcome.ALLOW)

    recommendation = recommend_enforcement(decision, credential_known_revoked=None)

    assert recommendation.action is EnforcementAction.ALLOW  # 통과 여부는 영향 없음
    assert recommendation.credential_state is CredentialConfirmationState.UNKNOWN


def test_confirmed_revoked_credential_is_reflected_even_on_allow_outcome():
    """(설계상 evaluate()가 이미 DENY로 만들지만) 권고 함수 자체는 outcome과
    credential_state를 독립적으로 계산한다는 것을 단위 테스트로 고정한다."""
    decision = _decision(AgentAccessOutcome.ALLOW)

    recommendation = recommend_enforcement(decision, credential_known_revoked=True)

    assert recommendation.credential_state is CredentialConfirmationState.REVOKED_CONFIRMED
    assert recommendation.action is EnforcementAction.ALLOW


# ---------------------------------------------------------------------------
# 평가기 내부 실패 — fail-closed
# ---------------------------------------------------------------------------
def test_enforcement_on_evaluator_failure_constant_is_block():
    assert ENFORCEMENT_ON_EVALUATOR_FAILURE is EnforcementAction.BLOCK


def test_build_fail_closed_decision_denies_with_dedicated_rule():
    decision = build_fail_closed_decision(_observation())

    assert decision.outcome is AgentAccessOutcome.DENY
    assert len(decision.findings) == 1
    finding = decision.findings[0]
    assert finding.rule_id == EVALUATOR_FAILURE_RULE_ID
    assert finding.blocking is True

    recommendation = recommend_enforcement(decision)
    assert recommendation.action is EnforcementAction.BLOCK


def test_fail_closed_rule_id_is_registered_in_catalog_for_discoverability():
    assert EVALUATOR_FAILURE_RULE_ID in AGENT_ACCESS_RULE_CATALOG


def test_build_fail_closed_decision_sanitizes_observation():
    """fail-closed 응답도 다른 판정 경로와 동일하게 민감정보를 제거한다."""
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    decision = build_fail_closed_decision(
        _observation(action=f"Authorization: Bearer {secret}")
    )

    import json

    serialized = json.dumps(decision.model_dump(mode="json"), ensure_ascii=False)
    assert secret not in serialized


# ---------------------------------------------------------------------------
# AccessControlMode — monitor/human_in_the_loop 는 REVIEW에만 영향을 준다.
# DENY(비활성 Lifecycle/폐기 확인된 Credential/평가 실패 포함)는 모드와
# 무관하게 항상 BLOCK이어야 한다 — 이게 "monitor 가 필수 보안 차단을
# 우회하지 못한다"는 요구사항의 핵심 불변식이다.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "mode",
    [AccessControlMode.ENFORCE, AccessControlMode.MONITOR, AccessControlMode.HUMAN_IN_THE_LOOP],
)
def test_deny_is_always_blocked_regardless_of_mode(mode):
    """DENY는 세 모드 모두 BLOCK — monitor/human_in_the_loop 도 예외 없다."""
    decision = _decision(AgentAccessOutcome.DENY)
    assert enforcement_action_for(decision.outcome, mode=mode) is EnforcementAction.BLOCK


@pytest.mark.parametrize(
    "mode",
    [AccessControlMode.ENFORCE, AccessControlMode.MONITOR, AccessControlMode.HUMAN_IN_THE_LOOP],
)
def test_allow_is_always_allowed_regardless_of_mode(mode):
    decision = _decision(AgentAccessOutcome.ALLOW)
    assert enforcement_action_for(decision.outcome, mode=mode) is EnforcementAction.ALLOW


def test_review_is_blocked_under_enforce_mode():
    assert enforcement_action_for(AgentAccessOutcome.REVIEW) is EnforcementAction.BLOCK
    assert (
        enforcement_action_for(AgentAccessOutcome.REVIEW, mode=AccessControlMode.ENFORCE)
        is EnforcementAction.BLOCK
    )


def test_review_is_allowed_under_monitor_mode():
    """monitor 모드는 REVIEW(확정하지 못한 요청)만 통과시키는 섀도 모드다."""
    assert (
        enforcement_action_for(AgentAccessOutcome.REVIEW, mode=AccessControlMode.MONITOR)
        is EnforcementAction.ALLOW
    )


def test_review_is_blocked_under_human_in_the_loop_mode():
    """human_in_the_loop 는 승인 전까지 보호된 요청을 실행하지 않는다 — enforce 와 동일하게 차단."""
    assert (
        enforcement_action_for(
            AgentAccessOutcome.REVIEW, mode=AccessControlMode.HUMAN_IN_THE_LOOP
        )
        is EnforcementAction.BLOCK
    )


def test_access_control_mode_from_str_is_fail_closed_on_unknown_value():
    assert AccessControlMode.from_str("monitor") is AccessControlMode.MONITOR
    assert AccessControlMode.from_str("human_in_the_loop") is AccessControlMode.HUMAN_IN_THE_LOOP
    assert AccessControlMode.from_str("enforce") is AccessControlMode.ENFORCE
    assert AccessControlMode.from_str("") is AccessControlMode.ENFORCE
    assert AccessControlMode.from_str(None) is AccessControlMode.ENFORCE
    assert AccessControlMode.from_str("nonsense-typo") is AccessControlMode.ENFORCE


def test_directive_marks_monitor_pass_through_as_alert_only():
    directive = directive_for(
        AgentAccessOutcome.REVIEW, EnforcementAction.ALLOW, mode=AccessControlMode.MONITOR
    )
    assert directive is EnforcementDirective.ALERT_ONLY


def test_directive_marks_human_in_the_loop_block_as_require_approval():
    directive = directive_for(
        AgentAccessOutcome.REVIEW,
        EnforcementAction.BLOCK,
        mode=AccessControlMode.HUMAN_IN_THE_LOOP,
    )
    assert directive is EnforcementDirective.REQUIRE_APPROVAL


def test_directive_marks_deny_block_as_block_regardless_of_mode():
    for mode in (
        AccessControlMode.ENFORCE,
        AccessControlMode.MONITOR,
        AccessControlMode.HUMAN_IN_THE_LOOP,
    ):
        directive = directive_for(AgentAccessOutcome.DENY, EnforcementAction.BLOCK, mode=mode)
        assert directive is EnforcementDirective.BLOCK


def test_recommend_enforcement_with_monitor_mode_allows_review_but_keeps_deny_blocked():
    review_decision = _decision(
        AgentAccessOutcome.REVIEW,
        findings=[
            AgentThreatFinding(
                rule_id="NHI_LIFECYCLE_PENDING_ACTIVATION",
                category="coverage",
                severity=RiskLevel.MEDIUM,
                title="미활성화 NHI 사용",
                detail="등록만 되고 아직 ACTIVE 전",
                blocking=False,
            )
        ],
    )
    recommendation = recommend_enforcement(review_decision, mode=AccessControlMode.MONITOR)
    assert recommendation.action is EnforcementAction.ALLOW
    assert recommendation.mode is AccessControlMode.MONITOR
    assert recommendation.directive is EnforcementDirective.ALERT_ONLY

    deny_decision = _decision(
        AgentAccessOutcome.DENY,
        findings=[
            AgentThreatFinding(
                rule_id="NHI_LIFECYCLE_NOT_ACTIVE",
                category="lifecycle",
                severity=RiskLevel.CRITICAL,
                title="비활성/파기된 NHI 사용",
                detail="DEACTIVATED",
                blocking=True,
            )
        ],
    )
    deny_recommendation = recommend_enforcement(deny_decision, mode=AccessControlMode.MONITOR)
    assert deny_recommendation.action is EnforcementAction.BLOCK


def test_recommend_enforcement_defaults_to_enforce_mode_for_backward_compatibility():
    """mode를 생략한 기존 호출부는 전부 enforce — 기존 동작과 완전히 동일해야 한다."""
    decision = _decision(AgentAccessOutcome.REVIEW)
    recommendation = recommend_enforcement(decision)
    assert recommendation.mode is AccessControlMode.ENFORCE
    assert recommendation.action is EnforcementAction.BLOCK
