"""Risk Scoring Agent — 규칙 기반 위험 점수 산출.

계산 로직 자체는 `policy/scoring.py` 에 있고, 이 Agent 는
  * 입력 번들(EvaluationContext) 구성
  * 점수 산출 호출
  * 결과 요약(설명 가능한 형태) 제공
을 담당한다. 점수 규칙을 OPA/Cerbos 로 옮기더라도 이 인터페이스는 유지된다.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.nhi_models import PolicyViolation, RiskAssessment
from policy.rules import EvaluationContext
from policy.scoring import AREA_MAX, RiskScorer, risk_level_for

logger = logging.getLogger(__name__)


class RiskScoringAgent:
    """EvaluationContext → RiskAssessment."""

    def __init__(self, scorer: Optional[RiskScorer] = None) -> None:
        self.scorer = scorer or RiskScorer()

    def score(
        self,
        ctx: EvaluationContext,
        violations: Optional[List[PolicyViolation]] = None,
    ) -> RiskAssessment:
        assessment = self.scorer.score(ctx, violations or [])
        logger.debug(
            "risk scored nhi=%s score=%d level=%s forced=%s",
            ctx.profile.nhi_id,
            assessment.score,
            assessment.level.value,
            assessment.forced_critical,
        )
        return assessment

    # ------------------------------------------------------------------
    @staticmethod
    def explain(assessment: RiskAssessment) -> Dict[str, Any]:
        """점수 구성을 사람이 검토할 수 있는 형태로 펼친다."""
        return {
            "score": assessment.score,
            "level": assessment.level.value,
            "base_score": assessment.base_score,
            "forced_critical": assessment.forced_critical,
            "breakdown": [
                {
                    "area": factor.label,
                    "score": f"{factor.score}/{factor.max_score}",
                    "reasons": factor.reasons,
                }
                for factor in assessment.factors
            ],
            "total_possible": sum(AREA_MAX.values()),
        }

    @staticmethod
    def level_for(score: int) -> str:
        return risk_level_for(score).value
