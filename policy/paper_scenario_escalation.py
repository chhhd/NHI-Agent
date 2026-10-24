"""논문 기반 시나리오 평가 결과로 강제 CRITICAL 승격을 허용하는 (현재 비활성) 확장 슬롯.

A+B 하이브리드 설계의 "B" 부분이다 — 지금은 의도적으로 비어 있다.

``evaluate_forced_critical()`` 레벨의 활성화 조건 (둘 다 필요):
    1) ``policy.rules.PolicyConfig.enable_paper_scenario_escalation = True``
    2) 이 모듈의 ``PAPER_SCENARIO_ESCALATION_RULES`` 에 팀이 승인한 규칙이 등록됨

둘 중 하나라도 충족되지 않으면 `policy.rules.evaluate_forced_critical()` 은 이
규칙들을 전혀 평가하지 않는다 — 기존 8개 강제 Critical 규칙과 100점 Risk Score
계산은 이 모듈이 비어 있는 한 절대 영향을 받지 않는다.

⚠️ **위 두 조건을 만족해도 이것만으로는 아직 아무 일도 일어나지 않는다.**
``policy.scoring.RiskScorer.score()`` — 100점 Risk Score와 최종 등급을 만드는
실제 지점 — 는 ``evaluate_forced_critical(ctx)`` 를 **인자 1개로만** 호출한다
(``paper_result`` 를 넘기지 않는다. ``policy/scoring.py`` 의 해당 호출부 참고).
``agents/pipeline.py`` 의 계산 순서도 위험 점수(``risk_scoring.score(...)``)를
먼저 계산한 뒤에야 논문 기반 평가(``paper_scenario_evaluations``)를 만든다 —
즉 위험 점수를 계산하는 시점에는 논문 평가 결과 자체가 아직 존재하지도 않는다.

따라서 이 슬롯을 실제로 "활성화"하려면 위 두 조건 외에 **최소 세 군데를 추가로
변경**해야 한다 (이번 작업 범위에는 포함되지 않음 — 의도적으로 건드리지 않았다):
    a) ``agents/risk_scoring_agent.py``/``policy/scoring.py: RiskScorer.score()`` 가
       ``paper_result`` 를 받아 ``evaluate_forced_critical(ctx, paper_result)`` 로
       넘기도록 시그니처 확장
    b) ``agents/pipeline.py: _assess()`` 의 계산 순서를 "논문 평가 → Risk Scoring"
       순으로 재배치(현재는 반대 순서)
    c) 위 두 호출부를 실제로 연결

이 사실을 모른 채 "규칙 등록 + 플래그만 켜면 활성화된다"고 오해하지 않도록 이
문서에 명시한다.

규칙 함수 시그니처는 기존 ``FORCED_CRITICAL_RULES``(policy/rules.py)와 동일한
관례를 따른다: ``(EvaluationContext, ScenarioEvaluationResult) -> Optional[str]``.
반환값이 사람이 읽는 근거 문장이면 승격, ``None`` 이면 미승격이다.

예시(아직 추가하지 않음 — 팀 승인 전까지 참고용 주석으로만 남긴다)::

    def _example_rule(ctx, paper_result):
        if paper_result.raw_score is not None and paper_result.raw_score >= 400:
            return f"논문 모델 위험도 {paper_result.raw_score}점 (팀 승인 시나리오 X)"
        return None

    PAPER_SCENARIO_ESCALATION_RULES["EXAMPLE_PAPER_SCENARIO"] = _example_rule
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, Optional

if TYPE_CHECKING:  # 순환 import 방지
    from core.scenario_evaluation_models import ScenarioEvaluationResult
    from policy.rules import EvaluationContext

#: 규칙 ID -> 판정 함수. 팀이 고위험 시나리오를 승인하기 전까지 비워 둔다.
#: 임의로 채우지 않는다.
PAPER_SCENARIO_ESCALATION_RULES: Dict[
    str, Callable[["EvaluationContext", "ScenarioEvaluationResult"], Optional[str]]
] = {}

__all__ = ["PAPER_SCENARIO_ESCALATION_RULES"]
