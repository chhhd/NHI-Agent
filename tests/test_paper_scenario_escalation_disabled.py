"""선택적 CRITICAL 승격 확장 슬롯(A+B 하이브리드의 "B")이 기본 OFF인지 고정하는 테스트.

이 테스트가 깨진다면 둘 중 하나가 바뀐 것이다:
    1) `PolicyConfig.enable_paper_scenario_escalation` 기본값이 False가 아니게 됨
    2) `PAPER_SCENARIO_ESCALATION_RULES` 에 누군가 팀 승인 없이 규칙을 추가함

둘 다 이번 1차 구현에서 금지된 변경이다.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.models import CodeContext, DetectorType, SecretFinding, Severity
from core.nhi_models import (
    AnalysisSignals,
    BlastRadiusReport,
    ContextInsight,
    Environment,
    NHIProfile,
    NHIType,
    PermissionProfile,
)
from core.scenario_evaluation_models import EvaluationStatus, ScenarioEvaluationResult
from policy.paper_scenario_escalation import PAPER_SCENARIO_ESCALATION_RULES
from policy.rules import EvaluationContext, PolicyConfig, evaluate_forced_critical
from policy.scoring import RiskScorer


def _finding() -> SecretFinding:
    return SecretFinding(
        secret_type="generic_api_key",
        provider="unknown",
        masked_value="****",
        fingerprint="fp-escalation-test",
        file_path="app.py",
        line_number=1,
        detector=DetectorType.REGEX,
        severity=Severity.MEDIUM,
        context=CodeContext(before=[], line="", after=[]),
    )


def _ctx(config: PolicyConfig) -> EvaluationContext:
    return EvaluationContext(
        finding=_finding(),
        profile=NHIProfile(nhi_id="nhi-1", nhi_name="nhi-1", nhi_type=NHIType.UNKNOWN_NHI),
        context=ContextInsight(environment=Environment.PRODUCTION),
        permissions=PermissionProfile(),
        signals=AnalysisSignals(),
        blast_radius=BlastRadiusReport(),
        config=config,
    )


def test_rule_table_is_empty_by_default():
    assert PAPER_SCENARIO_ESCALATION_RULES == {}


def test_config_flag_defaults_to_false():
    assert PolicyConfig().enable_paper_scenario_escalation is False


def test_flag_off_ignores_paper_result_even_if_it_looks_critical():
    config = PolicyConfig(enable_paper_scenario_escalation=False)
    ctx = _ctx(config)
    paper_result = ScenarioEvaluationResult(
        nhi_id="nhi-1", status=EvaluationStatus.EVALUATED, raw_score=999
    )

    baseline = evaluate_forced_critical(ctx)
    with_paper = evaluate_forced_critical(ctx, paper_result=paper_result)

    assert baseline == []
    assert with_paper == []
    assert baseline == with_paper


def test_flag_on_but_empty_rule_table_still_promotes_nothing():
    """현재 상태(규칙 0개)에서는 플래그를 켜도 아무 일도 생기지 않아야 한다."""
    config = PolicyConfig(enable_paper_scenario_escalation=True)
    ctx = _ctx(config)
    paper_result = ScenarioEvaluationResult(
        nhi_id="nhi-1", status=EvaluationStatus.EVALUATED, raw_score=999
    )

    hits = evaluate_forced_critical(ctx, paper_result=paper_result)

    assert hits == []


def test_risk_scorer_never_escalates_even_with_a_rule_registered_and_flag_on():
    """리뷰 MEDIUM 항목의 회귀 테스트 — "선택적 승격 슬롯이 RiskScorer까지
    실제로 연결되어 있지 않다"는 사실을 고정한다.

    `evaluate_forced_critical()`을 직접 호출하는 위 테스트들과 달리, 여기서는
    `RiskScorer.score()`를 통해서 들어간다. `RiskScorer.score()`는
    `evaluate_forced_critical(ctx)`를 인자 1개로만 호출하므로(`policy/scoring.py`),
    팀이 규칙을 등록하고 플래그를 켜도(아래에서 실제로 둘 다 해봄) RiskScorer가
    계산하는 100점 Risk Score/등급에는 전혀 영향이 없어야 한다. 이 테스트가
    실패한다면 `policy/scoring.py` 또는 `agents/pipeline.py`의 계산 순서가
    바뀌어 이 슬롯이 실제로 연결됐다는 뜻이다 — 그 변경은 이번 작업 범위 밖이다.
    """

    def _always_escalate(ctx, paper_result):
        return "테스트 전용 규칙 — 항상 승격"

    config = PolicyConfig(enable_paper_scenario_escalation=True)
    ctx = _ctx(config)
    baseline_score = RiskScorer().score(ctx)

    PAPER_SCENARIO_ESCALATION_RULES["TEST_ONLY_ALWAYS_ESCALATE"] = _always_escalate
    try:
        scored = RiskScorer().score(ctx)
    finally:
        del PAPER_SCENARIO_ESCALATION_RULES["TEST_ONLY_ALWAYS_ESCALATE"]

    assert scored.score == baseline_score.score
    assert scored.level == baseline_score.level
    assert scored.forced_critical == baseline_score.forced_critical
    assert scored.forced_rules == baseline_score.forced_rules
    assert PAPER_SCENARIO_ESCALATION_RULES == {}  # 테스트가 정리까지 확인
