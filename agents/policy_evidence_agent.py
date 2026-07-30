"""Policy Evidence Agent — 정책 판정과 그 "근거"를 남긴다.

두 단계로 나뉜다.
  1. `collect_violations()` — 위험 점수 이전에 정책 위반을 판정한다
     (Owner·정책 관리 상태 배점에 위반 개수가 반영되므로 순서가 중요하다).
  2. `decide()` — 위반 + 위험 점수로 자동 조치 / 사람 검토 / 예외 여부를 정한다.

모든 판단에는 사용한 입력의 출처를 함께 기록해, 나중에 "왜 이렇게 판정했는가"를
재구성할 수 있게 한다.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.nhi_models import PolicyEvaluation, PolicyViolation, RiskAssessment
from policy.decision_engine import DecisionEngine
from policy.rules import EvaluationContext, evaluate_policies

logger = logging.getLogger(__name__)


class PolicyEvidenceAgent:
    """정책 평가 + 근거(Evidence) 수집."""

    def __init__(self, engine: Optional[DecisionEngine] = None) -> None:
        self.engine = engine or DecisionEngine()

    # ------------------------------------------------------------------
    def collect_violations(self, ctx: EvaluationContext) -> List[PolicyViolation]:
        violations = evaluate_policies(ctx)
        logger.debug(
            "policy violations nhi=%s count=%d", ctx.profile.nhi_id, len(violations)
        )
        return violations

    def decide(
        self,
        ctx: EvaluationContext,
        risk: RiskAssessment,
        violations: List[PolicyViolation],
    ) -> PolicyEvaluation:
        evaluation = self.engine.decide(ctx, risk, violations)
        evaluation.evidence = self._provenance(ctx) + evaluation.evidence
        return evaluation

    # ------------------------------------------------------------------
    @staticmethod
    def _provenance(ctx: EvaluationContext) -> List[str]:
        """판단에 사용한 입력의 출처 — 신뢰도 검토용."""
        evidence: List[str] = []
        finding = ctx.finding

        if ctx.from_code_scan:
            evidence.append(
                f"탐지: {finding.file_path}:{finding.line_number} "
                f"({finding.secret_type}, detector={finding.detector.value})"
            )
        else:
            evidence.append(
                f"입력: GitHub NHI 인벤토리 ({ctx.profile.nhi_type.value}, "
                f"접근 저장소 {len(ctx.accessible_repositories)}개) — 코드 스캔 결과 아님"
            )

        if finding.credential_active is None:
            evidence.append("자격 증명 외부 검증 미수행 — 상태 기반 판단은 추정값")
        else:
            evidence.append(
                f"자격 증명 외부 검증 완료 (active={finding.credential_active}, "
                f"revoked={finding.credential_revoked})"
            )
        if ctx.permissions.assumed:
            evidence.append("Scope 미확인 — 권한은 Secret 유형 기준 가정값")
        else:
            evidence.append(f"원본 scope {len(ctx.permissions.raw_scopes)}건을 공통 권한으로 변환")

        evidence.append(
            f"NHI 식별 신뢰도 {ctx.profile.confidence}, 문맥 분석 신뢰도 {ctx.context.confidence}"
        )
        if ctx.from_code_scan and ctx.signals.repository_public is None:
            evidence.append("Repository 공개 여부 미제공 — 노출 위치 점수는 보수적 기본값")
        if not ctx.from_code_scan and not ctx.accessible_repositories:
            evidence.append("접근 가능 저장소 목록 미제공 — 노출 면적 점수는 보수적 기본값")
        return evidence
