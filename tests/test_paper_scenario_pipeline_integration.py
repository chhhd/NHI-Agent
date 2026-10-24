"""파이프라인 연동 + 기존 Risk Score/대시보드(JSON) 호환성 테스트.

핵심 불변식:
    * `usage_events` 를 넘기든 안 넘기든 risk.score/risk.level/강제 Critical 결과는
      완전히 동일하다 (논문 시나리오 점수가 100점 Risk Score에 가산되지 않는다).
    * `usage_events` 를 넘기지 않으면(Slack/AWS 등 연결 안 된 provider) 평가 자체를
      시도하지 않아 `paper_scenario_evaluations` 가 빈 리스트다 ("평가 성공"으로
      표시하지 않는다).
    * `NHIAnalysis.to_dict()` 의 기존 키는 그대로 유지되고, 새 키 1개만 끝에 추가된다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agents.pipeline import NHIAnalysisPipeline
from core.scenario_evaluation_models import EvaluationStatus, UserRiskResult
from core.usage_models import UsageEvent
from policy.paper_scenario_engine import PaperScenarioEvaluator, StageCycleDetector


def _usage_event(nhi_id: str, index: int) -> UsageEvent:
    return UsageEvent(
        event_id=f"evt-{index}",
        provider="github",
        principal_id=nhi_id,
        action="repo.read",
        occurred_at=(datetime.now(timezone.utc) - timedelta(days=index)).isoformat(),
        source="organization_audit_log",
    )


def test_usage_events_absent_means_no_evaluation_attempted(high_risk_nhi):
    """usage_events=None(기본값) — 이벤트 데이터 자체가 제공되지 않아 평가를
    시도하지 않는다."""
    pipeline = NHIAnalysisPipeline()
    analysis = pipeline.analyze_github_nhi(high_risk_nhi)

    assert analysis.paper_scenario_evaluations == []


def test_usage_events_empty_list_attempts_evaluation_and_returns_insufficient_data(high_risk_nhi):
    """usage_events=[](리뷰 MEDIUM 수정) — None과 달리 "조회는 했으나 이벤트가
    0건"이므로 평가를 실제로 시도하고, 그 결과(INSUFFICIENT_DATA + 사유)가
    `paper_scenario_evaluations`에 남아야 한다. None처럼 조용히 빈 리스트로
    사라지면 안 된다."""
    pipeline = NHIAnalysisPipeline()

    analysis = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=[])

    assert len(analysis.paper_scenario_evaluations) == 1
    evaluation = analysis.paper_scenario_evaluations[0]
    assert evaluation.status is EvaluationStatus.INSUFFICIENT_DATA
    assert evaluation.raw_score is None
    assert any("이벤트가 없음" in reason for reason in evaluation.reasons)


def test_usage_events_present_produces_unconfigured_weight_by_default(high_risk_nhi):
    """ER 매핑표가 비어 있는 기본 엔진 상태에서는, GitHub 이벤트가 실제로 연결돼도
    점수는 나오지 않고 UNCONFIGURED_WEIGHT 로 귀결되어야 한다(임의 산출 금지)."""
    pipeline = NHIAnalysisPipeline()
    nhi_id = f"github:{high_risk_nhi.nhi_id}"
    events = [_usage_event(nhi_id, i) for i in range(3)]

    analysis = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=events)

    assert len(analysis.paper_scenario_evaluations) == 1
    evaluation = analysis.paper_scenario_evaluations[0]
    assert evaluation.status.value == "unconfigured_weight"
    assert evaluation.raw_score is None


def test_paper_scenario_result_never_changes_risk_score_or_level(high_risk_nhi):
    """같은 NHI 를 usage_events 유무만 다르게 돌려도 risk.score/risk.level은 동일해야
    한다 — 논문 시나리오 결과가 100점 Risk Score 계산 경로에 전혀 들어가지 않는다는
    직접 증거."""
    pipeline = NHIAnalysisPipeline()
    nhi_id = f"github:{high_risk_nhi.nhi_id}"
    events = [_usage_event(nhi_id, i) for i in range(3)]

    without_events = pipeline.analyze_github_nhi(high_risk_nhi)
    with_events = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=events)

    assert without_events.risk.score == with_events.risk.score
    assert without_events.risk.level == with_events.risk.level
    assert without_events.risk.forced_critical == with_events.risk.forced_critical
    assert without_events.risk.forced_rules == with_events.risk.forced_rules
    without_policy = {k: v for k, v in without_events.policy.to_dict().items() if k != "evaluated_at"}
    with_policy = {k: v for k, v in with_events.policy.to_dict().items() if k != "evaluated_at"}
    assert without_policy == with_policy


_FULL_CYCLE_MAPPING = {
    "github:repo.copy_sensitive": ("S1", 10),
    "github:secret.decrypt": ("S2", 10),
    "github:webhard.upload": ("S3", 10),
}


def _full_cycle_events(nhi_id: str) -> list:
    return [
        UsageEvent(
            event_id="full-s1", provider="github", principal_id=nhi_id,
            action="repo.copy_sensitive",
            occurred_at=(datetime.now(timezone.utc) - timedelta(days=6)).isoformat(),
            source="organization_audit_log", project="acme/sensitive-repo",
        ),
        UsageEvent(
            event_id="full-s2", provider="github", principal_id=nhi_id,
            action="secret.decrypt",
            occurred_at=(datetime.now(timezone.utc) - timedelta(days=4)).isoformat(),
            source="organization_audit_log", project="acme/sensitive-repo",
        ),
        UsageEvent(
            event_id="full-s3", provider="github", principal_id=nhi_id,
            action="webhard.upload",
            occurred_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            source="organization_audit_log", project="acme/sensitive-repo",
        ),
    ]


def _always_scored_user_risk_resolver(nhi_id, events):
    return UserRiskResult(status=EvaluationStatus.EVALUATED, basis="test-fixture", ur_score=50)


def test_real_raw_score_through_full_pipeline_still_does_not_change_risk_score_or_level(
    high_risk_nhi,
):
    """리뷰 MEDIUM 수정 — 이전 테스트는 기본(빈 매핑) 엔진만 써서 raw_score가
    항상 None인 상태에서만 '영향 없음'을 증명했다. 여기서는 매핑표/cycle_detector/
    user_risk_resolver를 전부 채워 **실제로 숫자가 나오는** paper_scenario_evaluations를
    만든 뒤에도 risk.score/risk.level이 여전히 변하지 않음을 직접 증명한다."""
    nhi_id = f"github:{high_risk_nhi.nhi_id}"
    scored_evaluator = PaperScenarioEvaluator(
        stage_mapping=_FULL_CYCLE_MAPPING,
        cycle_detector=StageCycleDetector(window=timedelta(days=30)),
        user_risk_resolver=_always_scored_user_risk_resolver,
    )
    baseline_pipeline = NHIAnalysisPipeline()
    scored_pipeline = NHIAnalysisPipeline(paper_scenario_evaluator=scored_evaluator)

    baseline = baseline_pipeline.analyze_github_nhi(high_risk_nhi)
    scored = scored_pipeline.analyze_github_nhi(
        high_risk_nhi, usage_events=_full_cycle_events(nhi_id)
    )

    # 전제 확인 — 이 테스트가 실제로 raw_score를 산출하는 상태에서 돌고 있는지
    assert len(scored.paper_scenario_evaluations) == 1
    evaluation = scored.paper_scenario_evaluations[0]
    assert evaluation.status is EvaluationStatus.EVALUATED
    assert evaluation.raw_score is not None
    assert evaluation.raw_score > 0

    # 핵심 불변식 — raw_score가 실제로 나왔어도 risk.score/level은 그대로다
    assert baseline.risk.score == scored.risk.score
    assert baseline.risk.level == scored.risk.level
    assert baseline.risk.forced_critical == scored.risk.forced_critical
    assert baseline.risk.forced_rules == scored.risk.forced_rules


def test_low_risk_nhi_unaffected_too(low_risk_nhi):
    pipeline = NHIAnalysisPipeline()
    nhi_id = f"github:{low_risk_nhi.nhi_id}"
    events = [_usage_event(nhi_id, i) for i in range(2)]

    without_events = pipeline.analyze_github_nhi(low_risk_nhi)
    with_events = pipeline.analyze_github_nhi(low_risk_nhi, usage_events=events)

    assert without_events.risk.score == with_events.risk.score
    assert without_events.risk.level == with_events.risk.level


# --------------------------------------------------------------------------- API/대시보드 JSON 호환성
_EXISTING_TOP_LEVEL_KEYS = {
    "nhi_name", "nhi_type", "owner", "environment", "permissions", "risk_score",
    "risk_level", "risk_reasons", "recommended_action", "source", "fingerprint",
    "repository", "file_path", "line_number", "masked_value", "discovery",
    "context_analysis", "permission_detail", "usage_analysis", "security_events",
    "scenario_matches", "risk_detail", "policy", "recommendations", "blast_radius",
    "analyzed_at",
}


def test_to_dict_keeps_every_existing_key_and_only_appends_one_new_key(high_risk_nhi):
    pipeline = NHIAnalysisPipeline()
    nhi_id = f"github:{high_risk_nhi.nhi_id}"
    events = [_usage_event(nhi_id, i) for i in range(2)]

    payload = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=events).to_dict()

    assert _EXISTING_TOP_LEVEL_KEYS <= payload.keys()
    assert payload.keys() - _EXISTING_TOP_LEVEL_KEYS == {"paper_scenario_evaluations"}


def test_to_dict_without_usage_events_has_empty_list_not_missing_key(high_risk_nhi):
    pipeline = NHIAnalysisPipeline()
    payload = pipeline.analyze_github_nhi(high_risk_nhi).to_dict()

    assert payload["paper_scenario_evaluations"] == []


def test_to_dict_distinguishes_none_from_empty_list_api_serialization(high_risk_nhi):
    """None과 []가 API 직렬화 결과에서도 서로 다르게 나타나는지 확인한다.

    None: paper_scenario_evaluations == [] (시도 자체를 안 함, 근거 없음)
    []:   paper_scenario_evaluations == [하나의 INSUFFICIENT_DATA 결과] (시도함, 근거 있음)
    """
    pipeline = NHIAnalysisPipeline()

    payload_none = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=None).to_dict()
    payload_empty = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=[]).to_dict()

    assert payload_none["paper_scenario_evaluations"] == []

    assert len(payload_empty["paper_scenario_evaluations"]) == 1
    evaluation_payload = payload_empty["paper_scenario_evaluations"][0]
    assert evaluation_payload["status"] == "insufficient_data"
    assert evaluation_payload["raw_score"] is None
    assert evaluation_payload["reasons"]  # 빈 리스트가 아니라 사유가 반드시 있어야 함


def test_paper_scenario_evaluation_payload_has_no_severity_or_grade_key(high_risk_nhi):
    pipeline = NHIAnalysisPipeline()
    nhi_id = f"github:{high_risk_nhi.nhi_id}"
    events = [_usage_event(nhi_id, i) for i in range(2)]

    payload = pipeline.analyze_github_nhi(high_risk_nhi, usage_events=events).to_dict()
    evaluation_payload = payload["paper_scenario_evaluations"][0]

    assert "severity" not in evaluation_payload
    assert "grade" not in evaluation_payload
    assert evaluation_payload["raw_score"] is None
    assert evaluation_payload["status"] == "unconfigured_weight"
