"""PaperScenarioEvaluator 단위 테스트 — 논문(JDCS 2020.21.3.617) ER·EC·PW·FR·UR 모델.

핵심 불변식: ER 매핑표/UR 리졸버/FR cycle_detector 를 주입하지 않으면(기본값) 어떤
입력을 넣어도 raw_score 는 None 이고 상태는 UNCONFIGURED_WEIGHT/INSUFFICIENT_DATA
중 하나다 — 임의로 숫자를 추정하지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from core.scenario_evaluation_models import EvaluationStatus, UserRiskResult
from core.usage_models import UsageEvent
from policy.paper_scenario_engine import PaperScenarioEvaluator, StageCycleDetector


def _event(
    event_id: str,
    *,
    action: str = "repo.read",
    provider: str = "github",
    occurred_at: str,
    principal_id: str = "github:nhi-1",
    project: Optional[str] = None,
) -> UsageEvent:
    return UsageEvent(
        event_id=event_id,
        provider=provider,
        principal_id=principal_id,
        action=action,
        occurred_at=occurred_at,
        source="organization_audit_log",
        project=project,
    )


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


# --------------------------------------------------------------------------- 이벤트 부족
def test_no_events_returns_insufficient_data_not_a_guessed_score():
    evaluator = PaperScenarioEvaluator()
    result = evaluator.evaluate(nhi_id="github:nhi-1", events=[])

    assert result.status is EvaluationStatus.INSUFFICIENT_DATA
    assert result.raw_score is None
    assert result.stage_sum is None


# --------------------------------------------------------------------------- ER 매핑표 미확정 (기본값)
def test_default_evaluator_has_empty_stage_mapping_and_never_scores():
    """ER 매핑표를 임의로 채우지 않는다는 제약의 핵심 보증."""
    evaluator = PaperScenarioEvaluator()
    events = [_event("e1", occurred_at=_iso(1)), _event("e2", occurred_at=_iso(0))]

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    assert result.status is EvaluationStatus.UNCONFIGURED_WEIGHT
    assert result.raw_score is None
    for stage, score in result.stage_scores.items():
        assert score.status is EvaluationStatus.UNCONFIGURED_WEIGHT
        assert score.stage_score is None
    assert set(result.unmapped_event_ids) == {"e1", "e2"}
    assert any("ER 매핑표" in reason for reason in result.reasons)


# --------------------------------------------------------------------------- ER 매핑표가 (테스트용으로) 주어진 경우
_TEST_MAPPING = {
    "github:repo.copy_sensitive": ("S1", 10),
    "github:secret.decrypt": ("S2", 10),
    "github:webhard.upload": ("S3", 10),
}


def test_stage_score_is_er_times_ec_when_mapping_is_configured():
    """ER x EC 계산 자체가 올바른지 — 매핑표는 테스트가 명시적으로 주입한다
    (엔진 기본값이 아니다 — 실제 운영 매핑은 여전히 팀 승인 필요)."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    day = _iso(5)
    events = [_event(f"s1-{i}", action="repo.copy_sensitive", occurred_at=day) for i in range(12)]

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    s1 = result.stage_scores["S1"]
    assert s1.status is EvaluationStatus.EVALUATED
    assert s1.er_raw_score == 10
    assert s1.event_count == 12
    assert s1.ec_weight == 5  # 논문 표5: 10 < count <= 30 -> Medium(5)
    assert s1.stage_score == 50  # 10 * 5

    # S2/S3 이벤트가 없으므로 stage_sum/raw_score 는 여전히 None
    assert result.stage_sum is None
    assert result.raw_score is None
    assert result.status is not EvaluationStatus.EVALUATED


def test_full_three_stage_chain_computes_stage_sum_but_not_raw_score_without_fr_ur():
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [
        _event("s1", action="repo.copy_sensitive", occurred_at=_iso(6)),
        _event("s2", action="secret.decrypt", occurred_at=_iso(4)),
        _event("s3", action="webhard.upload", occurred_at=_iso(1)),
    ]

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    assert result.stage_sum == 90  # (10*3) + (10*3) + (10*3), EC=3 (1~10건 Low)
    # PW는 계산 가능하지만(S1/S3 둘 다 있음) FR/UR 이 없어 raw_score 는 여전히 None
    assert result.period_weight.status is EvaluationStatus.EVALUATED
    assert result.period_weight.period_days == 5
    assert result.period_weight.pw_weight == 1.0  # 1~7일 -> High(1.0)
    assert result.frequency_risk.status is EvaluationStatus.UNCONFIGURED_WEIGHT
    assert result.user_risk.status is EvaluationStatus.UNCONFIGURED_WEIGHT
    assert result.threat_addition is None
    assert result.raw_score is None
    assert result.status is EvaluationStatus.UNCONFIGURED_WEIGHT


# --------------------------------------------------------------------------- 전 구성요소 충족 시에만 raw_score 산출
def test_raw_score_only_computed_when_every_component_is_evaluated():
    """StageCycleDetector를 명시적 window로 주입한 실사용 시나리오."""
    def user_risk_resolver(nhi_id, events):
        return UserRiskResult(status=EvaluationStatus.EVALUATED, basis="test-fixture", ur_score=50)

    evaluator = PaperScenarioEvaluator(
        stage_mapping=_TEST_MAPPING,
        cycle_detector=StageCycleDetector(window=timedelta(days=30)),
        user_risk_resolver=user_risk_resolver,
    )
    events = [
        _event("s1", action="repo.copy_sensitive", occurred_at=_iso(6), project="acme/secret-repo"),
        _event("s2", action="secret.decrypt", occurred_at=_iso(4), project="acme/secret-repo"),
        _event("s3", action="webhard.upload", occurred_at=_iso(1), project="acme/secret-repo"),
    ]

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    assert result.status is EvaluationStatus.EVALUATED
    assert result.stage_sum == 90
    assert result.frequency_risk.completed_cycle_count == 1
    assert result.frequency_risk.fr_score == 30  # 1회 -> Low(30)
    assert result.threat_addition == 30  # TR = PW(1.0) * FR(30)
    assert result.user_risk.ur_score == 50
    assert result.raw_score == 90 + 30 + 50  # Ws_sum + TR + UR


# --------------------------------------------------------------------------- UR/FR 미주입은 항상 미확정
def test_user_risk_is_always_unconfigured_without_explicit_resolver():
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [_event("e1", action="repo.copy_sensitive", occurred_at=_iso(1))]
    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)
    assert result.user_risk.status is EvaluationStatus.UNCONFIGURED_WEIGHT
    assert result.user_risk.ur_score is None


def test_period_weight_insufficient_without_both_s1_and_s3():
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [_event("s1", action="repo.copy_sensitive", occurred_at=_iso(3))]
    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)
    assert result.period_weight.status is EvaluationStatus.INSUFFICIENT_DATA


def test_period_weight_beyond_365_days_is_unconfigured_not_lowest_bucket():
    """논문에 365일 초과 구간이 정의돼 있지 않다 — 팀 합의 전까지 0.3을 임의로
    부여하지 않고 미확정으로 반환해야 한다."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [
        _event("s1", action="repo.copy_sensitive", occurred_at=_iso(400)),
        _event("s3", action="webhard.upload", occurred_at=_iso(1)),
    ]
    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    assert result.period_weight.status is EvaluationStatus.UNCONFIGURED_WEIGHT
    assert result.period_weight.pw_weight is None
    assert result.period_weight.period_days is not None and result.period_weight.period_days > 365
    assert any("365일" in reason for reason in result.period_weight.reasons)
    # 전체 결과도 raw_score가 나오면 안 된다
    assert result.raw_score is None


def test_period_weight_exactly_365_days_is_still_evaluated():
    """경계값(365일)은 논문 정의 범위 안이므로 정상적으로 Low(0.3)가 나와야 한다."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [
        _event("s1", action="repo.copy_sensitive", occurred_at=_iso(365)),
        _event("s3", action="webhard.upload", occurred_at=_iso(0)),
    ]
    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    assert result.period_weight.status is EvaluationStatus.EVALUATED
    assert result.period_weight.pw_weight == 0.3


# --------------------------------------------------------------------------- 기존 모델과 완전히 분리됨
def test_scenario_evaluation_result_has_no_severity_grade_field():
    """논문 400/300/200/100 임계값을 NHI-Agent 척도로 확정하지 않았으므로
    등급 필드 자체를 노출하지 않는다 — 실수로 추가되지 않았는지 고정한다."""
    evaluator = PaperScenarioEvaluator()
    result = evaluator.evaluate(nhi_id="github:nhi-1", events=[_event("e1", occurred_at=_iso(0))])
    payload = result.to_dict()
    assert "severity" not in payload
    assert "grade" not in payload
    assert "risk_level" not in payload


# --------------------------------------------------------------------------- 리뷰 HIGH 수정: ER/EC 중복 event_id 제거
def test_duplicate_event_id_does_not_inflate_ec_across_bucket_boundary():
    """리뷰에서 확인된 HIGH 결함의 회귀 테스트.

    EC 구간 경계는 10/30/50이다(논문 표5). 서로 다른 event_id를 가진 이벤트
    10건은 EC=3(Low, 1~10건)이어야 하고, 그중 1건을 event_id만 복제해 11건처럼
    보이게 만들어도 — 중복 제거 후에는 여전히 10건이므로 — EC가 5(Medium,
    11~30건)로 넘어가면 안 된다.
    """
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    day = _iso(5)
    distinct_events = [
        _event(f"s1-{i}", action="repo.copy_sensitive", occurred_at=day) for i in range(10)
    ]
    # distinct_events[0]과 event_id가 같은 "중복" 이벤트를 추가로 끼워 넣는다.
    duplicate_of_first = _event("s1-0", action="repo.copy_sensitive", occurred_at=day)

    result_without_duplicate = evaluator.evaluate(nhi_id="github:nhi-1", events=distinct_events)
    result_with_duplicate = evaluator.evaluate(
        nhi_id="github:nhi-1", events=[*distinct_events, duplicate_of_first]
    )

    assert result_without_duplicate.stage_scores["S1"].event_count == 10
    assert result_without_duplicate.stage_scores["S1"].ec_weight == 3  # 1~10건 Low(3)

    # 중복을 끼워 넣어도 event_count/ec_weight가 그대로여야 한다 — 11건으로
    # 세어 EC 구간(11~30 -> Medium(5))을 넘기면 안 된다.
    assert result_with_duplicate.stage_scores["S1"].event_count == 10
    assert result_with_duplicate.stage_scores["S1"].ec_weight == 3
    assert result_with_duplicate.stage_scores["S1"].stage_score == (
        result_without_duplicate.stage_scores["S1"].stage_score
    )
    assert "s1-0" in result_with_duplicate.duplicate_event_ids
    assert any("중복 event_id" in reason for reason in result_with_duplicate.reasons)


def test_duplicate_event_id_crossing_30_boundary_is_also_prevented():
    """10/30/50 중 30 경계에서도 동일하게 검증한다."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    day = _iso(5)
    distinct_events = [
        _event(f"s1-{i}", action="repo.copy_sensitive", occurred_at=day) for i in range(30)
    ]
    duplicates = [
        _event(f"s1-{i}", action="repo.copy_sensitive", occurred_at=day) for i in range(5)
    ]  # 30건 중 5건의 event_id를 다시 반복 (총 35건처럼 보이지만 실제로는 30건)

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=[*distinct_events, *duplicates])

    assert result.stage_scores["S1"].event_count == 30
    assert result.stage_scores["S1"].ec_weight == 5  # 11~30건 Medium(5), 31건 이상이면 7이 됐어야 함
    assert len(result.duplicate_event_ids) == 5


def test_duplicate_event_id_with_different_content_keeps_the_first_seen_record():
    """같은 event_id인데 내용(occurred_at/project)이 다른 두 레코드가 들어오면,
    `events` 시퀀스에서 먼저 나온 레코드를 채택하고 이후 발생분은 버린다 —
    내용을 비교·병합하지 않는다."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    first_seen = _event(
        "dup-1", action="repo.copy_sensitive", occurred_at=_iso(10), project="acme/first-repo"
    )
    second_seen_same_id = _event(
        "dup-1", action="repo.copy_sensitive", occurred_at=_iso(1), project="acme/second-repo"
    )

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=[first_seen, second_seen_same_id])

    assert result.stage_scores["S1"].event_count == 1
    # 채택된 날짜는 먼저 나온 레코드(first_seen, 10일 전)의 날짜여야 한다.
    assert result.stage_scores["S1"].peak_day == first_seen.occurred_at[:10]
    assert "dup-1" in result.duplicate_event_ids


# --------------------------------------------------------------------------- 여러 NHI·여러 자산이 섞인 입력
def test_multiple_assets_in_one_evaluate_call_aggregate_er_ec_across_assets():
    """ER/EC/PW는 NHI 1건 전체를 기준으로 집계되며 자산별로 나뉘지 않는다 — 자산
    단위 분리는 FR(StageCycleDetector)에서만 일어난다. 이 차이를 명시적으로
    고정해 둔다(설계상 의도된 동작이며 결함이 아니다)."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [
        _event("s1-repo-a", action="repo.copy_sensitive", occurred_at=_iso(5), project="acme/repo-a"),
        _event("s1-repo-b", action="repo.copy_sensitive", occurred_at=_iso(5), project="acme/repo-b"),
    ]

    result = evaluator.evaluate(nhi_id="github:nhi-1", events=events)

    # 서로 다른 자산(repo-a/repo-b)의 이벤트라도 같은 날 S1으로 함께 집계된다.
    assert result.stage_scores["S1"].event_count == 2
    assert set(result.stage_scores["S1"].event_ids) == {"s1-repo-a", "s1-repo-b"}


def test_evaluate_with_events_from_multiple_nhi_ids_passed_by_caller_mistake():
    """evaluate()는 principal_id로 이벤트를 다시 걸러내지 않는다 — 호출자가
    이미 한 NHI로 필터링해서 넘긴다는 계약에 의존한다. 서로 다른 principal_id가
    섞여 들어와도 엔진은 구분 없이 전부 집계한다는 현재 동작을 문서화 목적으로
    고정한다(StageCycleDetector만 principal_id로 그룹을 다시 나눈다)."""
    evaluator = PaperScenarioEvaluator(stage_mapping=_TEST_MAPPING)
    events = [
        _event("s1-a", action="repo.copy_sensitive", occurred_at=_iso(5), principal_id="github:nhi-A"),
        _event("s1-b", action="repo.copy_sensitive", occurred_at=_iso(5), principal_id="github:nhi-B"),
    ]

    result = evaluator.evaluate(nhi_id="github:nhi-A", events=events)

    # ER/EC는 principal_id를 구분하지 않고 둘 다 센다(호출자 책임 영역).
    assert result.stage_scores["S1"].event_count == 2


# --------------------------------------------------------------------------- 매핑 키 충돌 가능성(문서화)
def test_stage_mapping_key_is_provider_colon_action_and_can_collide_in_theory():
    """`_classify()`의 매핑 키는 `f"{provider}:{action}"` 단순 결합이다. action
    문자열에 콜론이 포함되면 서로 다른 (provider, action) 조합이 같은 키로
    충돌할 수 있는 구조적 여지가 있다 — DEFAULT_STAGE_MAPPING이 비어 있는 지금은
    영향이 없지만, 매핑표를 채울 때 이 제약을 인지해야 한다. 이 테스트는 그
    현재 동작을 고정해 알려진 한계로 남긴다(고치는 작업이 아니다)."""
    collision_mapping = {"github:a:b": ("S1", 10)}
    evaluator = PaperScenarioEvaluator(stage_mapping=collision_mapping)

    # provider="github:a", action="b"  ->  key = "github:a:b"
    event_one = _event("e1", provider="github:a", action="b", occurred_at=_iso(1))
    # provider="github", action="a:b"  ->  key = "github:a:b" (충돌)
    event_two = _event("e2", provider="github", action="a:b", occurred_at=_iso(1))

    result_one = evaluator.evaluate(nhi_id="n1", events=[event_one])
    result_two = evaluator.evaluate(nhi_id="n1", events=[event_two])

    # 서로 다른 (provider, action) 조합이지만 둘 다 같은 매핑 키로 S1 매칭된다
    # — 알려진 한계. 매핑표를 실제로 채울 때 provider 값에 ':'가 들어가지
    # 않도록 팀이 보장하거나, 키 생성 방식을 바꿔야 한다.
    assert result_one.stage_scores["S1"].status is EvaluationStatus.EVALUATED
    assert result_two.stage_scores["S1"].status is EvaluationStatus.EVALUATED
