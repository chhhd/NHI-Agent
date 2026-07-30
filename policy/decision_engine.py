"""정책 결정 엔진 — 위반 목록 + 위험 점수 → 조치 결정.

판단하는 것
  * 자동 조치가 가능한가 (AUTO_REMEDIATION)
  * 사람 검토가 필요한가 (HUMAN_REVIEW)
  * 승인된 예외로 허용되는가 (EXCEPTION_APPROVED)
  * 아무 위반이 없어 관찰만 하면 되는가 (MONITOR)

예외 정책은 **강제 Critical 을 덮지 못한다.** 예외 승인은 조직이 감수하기로 한
잔여 위험에만 적용되며, 공개 노출·폐기 후 사용 같은 사고성 조건은 항상 검토 대상이다.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.nhi_models import (
    NHIType,
    PolicyEvaluation,
    PolicyOutcome,
    PolicyViolation,
    RiskAssessment,
    RiskLevel,
    parse_dt,
)
from policy.rules import EvaluationContext, is_production

logger = logging.getLogger(__name__)


class DecisionEngine:
    """정책 위반과 위험도를 종합해 최종 조치 방향을 정한다."""

    def decide(
        self,
        ctx: EvaluationContext,
        risk: RiskAssessment,
        violations: List[PolicyViolation],
    ) -> PolicyEvaluation:
        evidence: List[str] = []
        exception = self._active_exception(ctx, evidence)

        human_review = self._needs_human_review(ctx, risk, violations, evidence)
        auto = self._can_auto_remediate(ctx, risk, violations, evidence)

        if exception and not risk.forced_critical and risk.level is not RiskLevel.CRITICAL:
            outcome = PolicyOutcome.EXCEPTION_APPROVED
            human_review = False
            auto = False
            evidence.append("승인된 예외 정책 범위 내 — 조치 보류")
        elif human_review:
            outcome = PolicyOutcome.HUMAN_REVIEW
        elif auto and violations:
            outcome = PolicyOutcome.AUTO_REMEDIATION
        else:
            outcome = PolicyOutcome.MONITOR
            if not violations:
                evidence.append("정책 위반 없음 — 관찰 유지")

        return PolicyEvaluation(
            outcome=outcome,
            violations=violations,
            auto_remediable=auto and outcome is PolicyOutcome.AUTO_REMEDIATION,
            human_review_required=outcome is PolicyOutcome.HUMAN_REVIEW,
            exception_applied=exception,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _active_exception(
        ctx: EvaluationContext, evidence: List[str]
    ) -> Optional[Dict[str, Any]]:
        """유효한 예외 승인이 있는지 확인한다."""
        signals = ctx.signals
        if not signals.exception_id:
            return None

        expires = parse_dt(signals.exception_expires_at)
        if expires is not None and expires < datetime.now(timezone.utc):
            evidence.append(f"예외 {signals.exception_id} 만료됨 ({signals.exception_expires_at})")
            return None

        evidence.append(f"예외 승인 확인: {signals.exception_id}")
        return {
            "exception_id": signals.exception_id,
            "reason": signals.exception_reason,
            "expires_at": signals.exception_expires_at,
            "exempted_policies": list(signals.exempted_policies),
        }

    def _needs_human_review(
        self,
        ctx: EvaluationContext,
        risk: RiskAssessment,
        violations: List[PolicyViolation],
        evidence: List[str],
    ) -> bool:
        needed = False

        if risk.forced_critical:
            evidence.append(
                "강제 Critical 규칙 적용: "
                + ", ".join(r["rule_id"] for r in risk.forced_rules)
            )
            needed = True

        if risk.score >= ctx.config.human_review_min_score:
            evidence.append(f"위험 점수 {risk.score} ≥ 검토 기준 {ctx.config.human_review_min_score}")
            needed = True

        blocked = [v for v in violations if not v.remediable]
        if blocked:
            evidence.append(
                "자동 조치로 해소 불가한 위반: " + ", ".join(v.policy_id for v in blocked)
            )
            needed = True

        if ctx.profile.nhi_type is NHIType.UNKNOWN_NHI or not ctx.profile.identified:
            evidence.append("NHI 를 특정하지 못함 — 자동 조치 시 서비스 영향 예측 불가")
            needed = True

        if is_production(ctx) and risk.level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            evidence.append("운영 환경 고위험 자산 — 조치 전 승인 필요")
            needed = True

        return needed

    def _can_auto_remediate(
        self,
        ctx: EvaluationContext,
        risk: RiskAssessment,
        violations: List[PolicyViolation],
        evidence: List[str],
    ) -> bool:
        if risk.forced_critical:
            return False
        if risk.score > ctx.config.auto_remediation_max_score:
            return False
        if any(not v.remediable for v in violations):
            return False
        if not ctx.profile.identified:
            return False
        if is_production(ctx):
            evidence.append("운영 환경 — 자동 조치 대신 검토 경로로 보냄")
            return False

        evidence.append(f"자동 조치 가능 (위험 점수 {risk.score} ≤ {ctx.config.auto_remediation_max_score})")
        return True
