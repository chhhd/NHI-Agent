"""정책 엔진 패키지.

`rules` 가 판정, `scoring` 이 점수화, `decision_engine` 이 조치 결정을 담당한다.
정책을 외부화해야 하면 이 세 모듈만 OPA/Cerbos 어댑터로 교체하면 된다.
"""

from policy.decision_engine import DecisionEngine
from policy.rules import (
    FORCED_CRITICAL_RULES,
    POLICIES,
    EvaluationContext,
    PolicyConfig,
    evaluate_forced_critical,
    evaluate_policies,
)
from policy.scoring import AREA_MAX, RiskScorer, risk_level_for

__all__ = [
    "AREA_MAX",
    "DecisionEngine",
    "EvaluationContext",
    "FORCED_CRITICAL_RULES",
    "POLICIES",
    "PolicyConfig",
    "RiskScorer",
    "evaluate_forced_critical",
    "evaluate_policies",
    "risk_level_for",
]
