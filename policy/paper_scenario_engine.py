"""논문(JDCS 2020.21.3.617) ER·EC·PW·FR·UR 기반 시나리오 평가 엔진.

``policy/scoring.py`` (100점 Risk Score)와 ``policy/rules.py`` (정책 위반 +
강제 Critical 8종)는 이 모듈을 import 하지 않는다 — 두 체계는 완전히 독립이다.
이 엔진의 산출물(``ScenarioEvaluationResult``)은 어디에도 가산되지 않고,
``NHIAnalysis.paper_scenario_evaluations`` 에 설명용 부가 데이터로만 담긴다.

핵심 원칙 (팀 합의 사항):
    * ER 매핑표(행위 → 단계·점수)와 UR 산정 기준은 아직 팀이 확정하지 않았으므로
      이 모듈에는 빈 테이블/``None`` 리졸버만 둔다. 임의의 숫자를 채우지 않는다.
    * 입력 이벤트가 부족하거나 매핑표가 비어 있으면 점수를 추정하지 않고
      ``EvaluationStatus`` 로 사유를 반환한다.
    * EC(이벤트 횟수)/PW(발생 기간) 구간표는 논문 표5·표6에 "그대로 재사용 가능한
      값"으로 명시된 비율이라 여기서는 그 값을 그대로 쓴다. FR(발생 빈도)은
      논문이 "S1~S3 완결 세트 반복 횟수"를 요구하지만, 원시 로그에서 이 세트를
      어떻게 묶을지(시간 근접 윈도우 등) 논문에 알고리즘이 없어 NHI-Agent 고유의
      신규 결정이 필요하다 — 따라서 ``cycle_detector`` 를 주입하지 않으면 항상
      미확정(``UNCONFIGURED_WEIGHT``)이다.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from core.nhi_models import parse_dt
from core.scenario_evaluation_models import (
    CycleDetectionResult,
    EvaluationStatus,
    FrequencyRiskResult,
    PeriodWeightResult,
    ScenarioEvaluationResult,
    StageEventScore,
    UserRiskResult,
)
from core.usage_models import UsageEvent

#: 단계 식별자 (논문 §3.1 S1 정보수집 / S2 정보가공 / S3 정보유출)
_STAGES: Tuple[str, str, str] = ("S1", "S2", "S3")

#: provider:action → (stage, ER 원점수). 팀이 승인하기 전까지 비워 둔다.
#: 임의로 채우지 않는다 — 비어 있으면 모든 이벤트가 "미매핑"으로 처리된다.
#: 키 형식: ``f"{provider}:{action}".lower()``
DEFAULT_STAGE_MAPPING: Dict[str, Tuple[str, int]] = {}

#: 논문 표5 — 이벤트 횟수(EC) 가중치. "1일 합산 로그 건수" 구간 비율은
#: provider 와 무관한 상대값이라 그대로 재사용한다(팀 결정 사항 아님).
_EC_BUCKETS: Tuple[Tuple[int, int], ...] = (
    (10, 3),   # 1 < Count <= 10  -> Low(3)  (1건도 이 구간으로 취급)
    (30, 5),   # 10 < Count <= 30 -> Medium(5)
    (50, 7),   # 30 < Count <= 50 -> Medium-high(7)
)
_EC_HIGH = 10  # Count > 50 -> High(10)

#: 논문 표6 — 발생 기간 가중치(PW). 일 단위. 논문이 정의한 범위는 1~365일뿐이다.
_PW_BUCKETS: Tuple[Tuple[int, float], ...] = (
    (7, 1.0),    # 1~7일   -> High(1.0)
    (30, 0.7),   # 8~30일  -> Medium-high(0.7)
    (90, 0.5),   # 31~90일 -> Medium(0.5)
    (365, 0.3),  # 91~365일 -> Low(0.3)
)


def _ec_weight(daily_count: int) -> int:
    for threshold, weight in _EC_BUCKETS:
        if daily_count <= threshold:
            return weight
    return _EC_HIGH


def _pw_weight(period_days: int) -> Tuple[Optional[float], bool]:
    """반환값: (가중치 또는 None, 논문 정의 범위를 벗어났는가).

    365일을 초과하면 논문에 해당 구간이 정의되어 있지 않다. 이전 구현은 최저
    구간(0.3)을 임의로 적용했으나, 팀 합의 없이 숫자를 만들어내지 않기 위해
    ``None`` 을 반환한다 — 호출부는 이를 UNCONFIGURED_WEIGHT 로 처리한다.
    """
    for threshold, weight in _PW_BUCKETS:
        if period_days <= threshold:
            return weight, False
    return None, True


def _event_day(event: UsageEvent) -> Optional[str]:
    dt = parse_dt(event.occurred_at)
    return dt.date().isoformat() if dt is not None else None


def _event_ts(event: UsageEvent) -> Optional[datetime]:
    return parse_dt(event.occurred_at)


def _asset_key(event: UsageEvent) -> Optional[str]:
    """자산 식별자. project(저장소)를 우선하고 없으면 resource(team/org)를 쓴다.

    둘 다 없으면 ``None`` 을 반환한다 — 호출부는 이런 이벤트를 "같은 자산"으로
    임의로 묶지 않고 평가 대상에서 제외해야 한다.
    """
    if event.project:
        return f"project:{event.project}"
    if event.resource:
        return f"resource:{event.resource}"
    return None


class PaperScenarioEvaluator:
    """``List[UsageEvent]`` -> ``ScenarioEvaluationResult``.

    ``stage_mapping``/``user_risk_resolver``/``cycle_detector`` 를 주입하지 않으면
    (기본값) 모든 구성요소가 ``UNCONFIGURED_WEIGHT``/``INSUFFICIENT_DATA`` 로
    귀결되고 ``raw_score`` 는 항상 ``None`` 이다 — 이것이 1차 구현의 의도된 동작이다.
    """

    def __init__(
        self,
        *,
        stage_mapping: Optional[Dict[str, Tuple[str, int]]] = None,
        user_risk_resolver: Optional[
            Callable[[str, Sequence[UsageEvent]], Optional[UserRiskResult]]
        ] = None,
        cycle_detector: Optional[
            Callable[[Dict[str, List[UsageEvent]]], Optional[CycleDetectionResult]]
        ] = None,
    ) -> None:
        self.stage_mapping = (
            dict(stage_mapping) if stage_mapping is not None else dict(DEFAULT_STAGE_MAPPING)
        )
        self.user_risk_resolver = user_risk_resolver
        self.cycle_detector = cycle_detector

    # ------------------------------------------------------------------
    def evaluate(self, *, nhi_id: str, events: Sequence[UsageEvent]) -> ScenarioEvaluationResult:
        events = [event for event in events if isinstance(event, UsageEvent)]
        # ER/EC 계산 전에 중복 event_id를 제거한다 — StageCycleDetector(FR)와 동일한
        # "리스트에서 먼저 나타난 레코드를 채택" 기준을 공유한다(_dedupe_events_by_id).
        # 여기서 먼저 정리하므로 이후 cycle_detector로 넘어가는 by_stage도 이미
        # 중복이 없는 상태다.
        events, duplicate_event_ids = _dedupe_events_by_id(events)

        if not events:
            return ScenarioEvaluationResult(
                nhi_id=nhi_id,
                status=EvaluationStatus.INSUFFICIENT_DATA,
                reasons=["평가에 사용할 수 있는 타임스탬프 이벤트가 없음"],
            )

        by_stage, unmapped = self._classify(events)
        mapping_configured = bool(self.stage_mapping)

        stage_scores: Dict[str, StageEventScore] = {}
        for stage in _STAGES:
            stage_scores[stage] = self._score_stage(stage, by_stage.get(stage, []), mapping_configured)

        all_evaluated = all(
            score.status is EvaluationStatus.EVALUATED for score in stage_scores.values()
        )
        stage_sum = (
            sum(score.stage_score for score in stage_scores.values())  # type: ignore[misc]
            if all_evaluated
            else None
        )

        period_weight = self._period_weight(
            by_stage.get("S1", []), by_stage.get("S3", []), mapping_configured
        )
        frequency_risk = self._frequency_risk(by_stage, mapping_configured)
        threat_addition = (
            round(period_weight.pw_weight * frequency_risk.fr_score)
            if (
                period_weight.status is EvaluationStatus.EVALUATED
                and frequency_risk.status is EvaluationStatus.EVALUATED
                and period_weight.pw_weight is not None
                and frequency_risk.fr_score is not None
            )
            else None
        )

        user_risk = self._user_risk(nhi_id, events)

        components_evaluated = (
            all_evaluated
            and period_weight.status is EvaluationStatus.EVALUATED
            and frequency_risk.status is EvaluationStatus.EVALUATED
            and user_risk.status is EvaluationStatus.EVALUATED
            and stage_sum is not None
            and threat_addition is not None
            and user_risk.ur_score is not None
        )

        reasons: List[str] = []
        if duplicate_event_ids:
            reasons.append(
                f"중복 event_id {len(duplicate_event_ids)}건은 최초 1건만 사용함 "
                "(먼저 나타난 레코드 채택, 내용이 다르더라도 이후 발생분은 버림)"
            )
        if not mapping_configured:
            reasons.append("ER 매핑표(행위→단계·점수)가 비어 있음 — 팀 승인 대기")
        if self.cycle_detector is None:
            reasons.append("FR 세트(S1→S2→S3) 판정 알고리즘이 주입되지 않음 — 팀 결정 필요")
        if self.user_risk_resolver is None:
            reasons.append("UR 산정 기준(고위험군 분류)이 주입되지 않음 — NHI-Agent 고유 설계 필요")
        for stage, score in stage_scores.items():
            reasons.extend(f"[{stage}] {reason}" for reason in score.reasons if reason not in reasons)

        raw_score = (
            stage_sum + threat_addition + user_risk.ur_score  # type: ignore[operator]
            if components_evaluated
            else None
        )
        if raw_score is not None:
            status = EvaluationStatus.EVALUATED
        else:
            # 가중치/매핑표 미확정이 데이터 부족보다 우선하는 사유다 — "값은 있는데
            # 계산 기준이 없다" 쪽이 "애초에 관측치가 없다" 보다 더 구체적인 사유라서다.
            component_statuses = (
                [score.status for score in stage_scores.values()]
                + [period_weight.status, frequency_risk.status, user_risk.status]
            )
            status = (
                EvaluationStatus.UNCONFIGURED_WEIGHT
                if EvaluationStatus.UNCONFIGURED_WEIGHT in component_statuses
                else EvaluationStatus.INSUFFICIENT_DATA
            )

        return ScenarioEvaluationResult(
            nhi_id=nhi_id,
            status=status,
            stage_scores=stage_scores,
            unmapped_event_ids=[event.event_id for event in unmapped],
            duplicate_event_ids=duplicate_event_ids,
            stage_sum=stage_sum,
            period_weight=period_weight,
            frequency_risk=frequency_risk,
            threat_addition=threat_addition,
            user_risk=user_risk,
            raw_score=raw_score,
            reasons=reasons,
        )

    # ------------------------------------------------------------------
    def _classify(
        self, events: Sequence[UsageEvent]
    ) -> Tuple[Dict[str, List[UsageEvent]], List[UsageEvent]]:
        by_stage: Dict[str, List[UsageEvent]] = defaultdict(list)
        unmapped: List[UsageEvent] = []
        for event in events:
            key = f"{event.provider}:{event.action}".strip().lower()
            entry = self.stage_mapping.get(key)
            if entry is None:
                unmapped.append(event)
                continue
            stage, _ = entry
            if stage not in _STAGES:
                unmapped.append(event)
                continue
            by_stage[stage].append(event)
        return by_stage, unmapped

    def _score_stage(
        self, stage: str, matched: List[UsageEvent], mapping_configured: bool
    ) -> StageEventScore:
        if not mapping_configured:
            return StageEventScore(
                stage=stage,
                status=EvaluationStatus.UNCONFIGURED_WEIGHT,
                reasons=["ER 매핑표 미확정으로 단계 판정 자체가 불가능"],
            )
        if not matched:
            return StageEventScore(
                stage=stage,
                status=EvaluationStatus.INSUFFICIENT_DATA,
                reasons=[f"{stage} 단계에 매핑된 이벤트 없음"],
            )

        er_scores = [
            self.stage_mapping[f"{event.provider}:{event.action}".strip().lower()][1]
            for event in matched
        ]
        er_raw_score = max(er_scores)

        daily_counts: Dict[str, int] = defaultdict(int)
        for event in matched:
            day = _event_day(event)
            if day is not None:
                daily_counts[day] += 1
        if not daily_counts:
            return StageEventScore(
                stage=stage,
                status=EvaluationStatus.INSUFFICIENT_DATA,
                event_ids=[event.event_id for event in matched],
                reasons=[f"{stage} 단계 이벤트의 발생 시각을 파싱할 수 없음"],
            )
        peak_day, peak_count = max(daily_counts.items(), key=lambda item: item[1])
        ec_weight = _ec_weight(peak_count)
        stage_score = er_raw_score * ec_weight

        return StageEventScore(
            stage=stage,
            status=EvaluationStatus.EVALUATED,
            er_raw_score=er_raw_score,
            er_basis=f"{len(matched)}건 매핑, 최고 ER={er_raw_score}",
            event_count=peak_count,
            peak_day=peak_day,
            ec_weight=ec_weight,
            stage_score=stage_score,
            event_ids=[event.event_id for event in matched],
            reasons=[f"{stage}: {peak_day} 일 최대 {peak_count}건 (EC={ec_weight}) x ER={er_raw_score}"],
        )

    def _period_weight(
        self,
        s1_events: List[UsageEvent],
        s3_events: List[UsageEvent],
        mapping_configured: bool,
    ) -> PeriodWeightResult:
        if not mapping_configured:
            return PeriodWeightResult(
                status=EvaluationStatus.UNCONFIGURED_WEIGHT,
                reasons=["ER 매핑표 미확정으로 S1/S3 단계를 식별할 수 없음"],
            )
        if not s1_events or not s3_events:
            return PeriodWeightResult(
                status=EvaluationStatus.INSUFFICIENT_DATA,
                reasons=["S1 또는 S3 단계 이벤트가 없어 발생 기간을 계산할 수 없음"],
            )
        s1_times = [parse_dt(event.occurred_at) for event in s1_events]
        s3_times = [parse_dt(event.occurred_at) for event in s3_events]
        s1_times = [dt for dt in s1_times if dt is not None]
        s3_times = [dt for dt in s3_times if dt is not None]
        if not s1_times or not s3_times:
            return PeriodWeightResult(
                status=EvaluationStatus.INSUFFICIENT_DATA,
                reasons=["S1/S3 이벤트의 발생 시각을 파싱할 수 없음"],
            )

        first_s1 = min(s1_times)
        last_s3 = max(s3_times)
        period_days = max(0, (last_s3 - first_s1).days)
        pw_weight, out_of_range = _pw_weight(period_days)
        reasons = [f"S1 최초({first_s1.isoformat()}) ~ S3 최종({last_s3.isoformat()}) = {period_days}일"]

        if out_of_range:
            # 논문 정의 범위(365일) 밖이다 — 팀 합의 없이 가중치를 만들어내지 않는다.
            reasons.append(
                "논문 정의 범위(365일) 초과 — 해당 구간의 가중치가 논문에 없어 "
                "팀 합의 전까지 산정하지 않음"
            )
            return PeriodWeightResult(
                status=EvaluationStatus.UNCONFIGURED_WEIGHT,
                first_event_at=first_s1.isoformat(),
                last_event_at=last_s3.isoformat(),
                period_days=period_days,
                pw_weight=None,
                reasons=reasons,
            )

        return PeriodWeightResult(
            status=EvaluationStatus.EVALUATED,
            first_event_at=first_s1.isoformat(),
            last_event_at=last_s3.isoformat(),
            period_days=period_days,
            pw_weight=pw_weight,
            reasons=reasons,
        )

    def _frequency_risk(
        self, by_stage: Dict[str, List[UsageEvent]], mapping_configured: bool
    ) -> FrequencyRiskResult:
        if not mapping_configured:
            return FrequencyRiskResult(
                status=EvaluationStatus.UNCONFIGURED_WEIGHT,
                reasons=["ER 매핑표 미확정으로 단계 분류 자체가 불가능"],
            )
        if self.cycle_detector is None:
            return FrequencyRiskResult(
                status=EvaluationStatus.UNCONFIGURED_WEIGHT,
                reasons=[
                    "S1→S2→S3 완결 세트를 원시 로그에서 묶는 알고리즘이 "
                    "논문에 명시되어 있지 않음 — cycle_detector 미주입"
                ],
            )
        detection = self.cycle_detector(dict(by_stage))
        if detection is None:
            return FrequencyRiskResult(
                status=EvaluationStatus.INSUFFICIENT_DATA,
                reasons=["cycle_detector가 결과를 반환하지 않음"],
            )
        if detection.completed_cycle_count <= 0:
            return FrequencyRiskResult(
                status=EvaluationStatus.INSUFFICIENT_DATA,
                completed_cycle_count=0,
                reasons=list(detection.reasons) or ["완결된 S1→S2→S3 세트를 찾지 못함"],
            )
        fr_score = _fr_score(detection.completed_cycle_count)
        return FrequencyRiskResult(
            status=EvaluationStatus.EVALUATED,
            completed_cycle_count=detection.completed_cycle_count,
            fr_score=fr_score,
            reasons=[*detection.reasons, f"완결 세트 {detection.completed_cycle_count}회 → FR={fr_score}"],
        )

    def _user_risk(self, nhi_id: str, events: Sequence[UsageEvent]) -> UserRiskResult:
        if self.user_risk_resolver is None:
            return UserRiskResult(
                status=EvaluationStatus.UNCONFIGURED_WEIGHT,
                reasons=["UR 산정 기준(고위험군 분류)이 아직 설계되지 않음 — NHI-Agent에는 인사정보 소스가 없음"],
            )
        result = self.user_risk_resolver(nhi_id, events)
        if result is None:
            return UserRiskResult(
                status=EvaluationStatus.INSUFFICIENT_DATA,
                reasons=["UR 산정에 필요한 입력(소유자/Agent 상태 등)이 부족함"],
            )
        return result


class StageCycleDetector:
    """S1→S2→S3 완결 시나리오 탐지기 — 동일 NHI·동일 자산·시간순·이벤트 재사용 금지.

    ``window`` 는 필수 인자이며 기본값이 없다. 팀이 시간 윈도우를 아직 정하지
    않았으므로, 이 클래스를 직접 생성하지 않으면(= ``PaperScenarioEvaluator`` 에
    ``cycle_detector`` 를 주입하지 않으면) FR은 계속 ``UNCONFIGURED_WEIGHT`` 다.
    명시적으로 ``window`` 를 주고 생성한 경우에만 실제 탐지를 수행한다.

    판정 규칙:
        1) 동일 NHI(``principal_id``) + 동일 자산(``project`` 우선, 없으면
           ``resource``)인 이벤트끼리만 짝짓는다. 자산 식별자가 둘 다 없는
           이벤트는 "같은 자산"으로 간주하지 않고 평가 대상에서 제외한다
           (``skipped_missing_asset_event_ids``).
        2) S1 → S2 → S3 순서(타임스탬프 오름차순)를 강제한다. 더 늦게 발생한
           이벤트가 앞 단계로 쓰이지 못한다.
        3) S1 시각부터 ``window`` 이내에 있는 이벤트만 같은 세트 후보로 본다.
        4) 탐욕적 최조 매칭(greedy earliest-match): 가장 이른 미사용 S1부터
           순서대로, 조건을 만족하는 가장 이른 미사용 S2 → S3 를 찾는다.
           완결되면 세 이벤트를 모두 소비(consumed) 처리해 다른 세트가 같은
           이벤트를 다시 쓰지 못하게 한다.
        5) 같은 ``event_id`` 가 여러 단계/여러 번 들어오면 최초 1건만 쓰고
           이후 발생분은 무시한다(``duplicate_event_ids``).
        6) 타임스탬프를 파싱할 수 없는 이벤트는 순서를 판단할 수 없으므로
           평가 대상에서 제외한다.

    알려진 경계 조건(의도된 동작, 팀 확인 필요):
        * **동일 타임스탬프**: S1과 S2(또는 S2와 S3)가 정확히 같은 시각이면
          매칭되지 않는다 — "엄격히 이후"(``>``)만 인정하고 "이상"(``>=``)은
          인정하지 않는다. 초 단위 해상도 감사로그처럼 동일 타임스탬프가 흔한
          환경에서는 FR이 체계적으로 과소평가될 수 있다.
        * **window 경계값**: ``S1 시각 + window`` 와 정확히 같은 시각의 이벤트는
          포함된다(``ts > deadline`` 일 때만 제외하므로 경계값 자체는 포함).
    """

    def __init__(self, *, window: timedelta) -> None:
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window는 0보다 큰 timedelta여야 합니다 (팀이 명시적으로 정해야 함).")
        self.window = window

    def __call__(self, by_stage: Dict[str, List[UsageEvent]]) -> CycleDetectionResult:
        deduped, duplicate_ids = _dedupe_by_event_id(by_stage)

        skipped_missing_asset: List[str] = []
        skipped_unparseable_ts: List[str] = []
        groups: Dict[Tuple[str, str], Dict[str, List[Tuple[datetime, UsageEvent]]]] = defaultdict(
            lambda: {"S1": [], "S2": [], "S3": []}
        )
        for stage in _STAGES:
            for event in deduped.get(stage, []):
                asset = _asset_key(event)
                if asset is None:
                    skipped_missing_asset.append(event.event_id)
                    continue
                ts = _event_ts(event)
                if ts is None:
                    skipped_unparseable_ts.append(event.event_id)
                    continue
                groups[(event.principal_id, asset)][stage].append((ts, event))

        total_cycles = 0
        unresolved: set = set()
        for (principal_id, asset), stages in groups.items():
            s1_events = sorted(stages["S1"], key=lambda item: item[0])
            s2_events = sorted(stages["S2"], key=lambda item: item[0])
            s3_events = sorted(stages["S3"], key=lambda item: item[0])
            consumed: set = set()

            for t1, s1 in s1_events:
                if s1.event_id in consumed:
                    continue
                deadline = t1 + self.window
                match2 = _earliest_unused_after(s2_events, after=t1, deadline=deadline, consumed=consumed)
                if match2 is None:
                    unresolved.add(s1.event_id)
                    continue
                t2, s2 = match2
                match3 = _earliest_unused_after(s3_events, after=t2, deadline=deadline, consumed=consumed)
                if match3 is None:
                    unresolved.add(s1.event_id)
                    unresolved.add(s2.event_id)
                    continue
                _, s3 = match3
                consumed.update({s1.event_id, s2.event_id, s3.event_id})
                total_cycles += 1

        reasons: List[str] = []
        if duplicate_ids:
            reasons.append(f"중복 event_id {len(duplicate_ids)}건은 최초 1건만 사용함")
        if skipped_missing_asset:
            reasons.append(
                f"자산 식별자(project/resource) 없는 이벤트 {len(skipped_missing_asset)}건은 "
                "동일 자산으로 간주하지 않고 평가에서 제외함"
            )
        if skipped_unparseable_ts:
            reasons.append(
                f"발생 시각을 파싱할 수 없는 이벤트 {len(skipped_unparseable_ts)}건은 제외함"
            )
        reasons.append(
            f"완결 세트 {total_cycles}건 탐지 (자산·NHI별 집계, window={self.window})"
            if total_cycles
            else f"완결된 S1→S2→S3 세트를 찾지 못함 (window={self.window})"
        )

        return CycleDetectionResult(
            completed_cycle_count=total_cycles,
            reasons=reasons,
            unresolved_event_ids=sorted(unresolved),
            skipped_missing_asset_event_ids=skipped_missing_asset,
            duplicate_event_ids=duplicate_ids,
        )


def _dedupe_events_by_id(events: Sequence[UsageEvent]) -> Tuple[List[UsageEvent], List[str]]:
    """같은 ``event_id`` 가 여러 번 나타나면 **시퀀스에서 먼저 나오는 레코드를
    채택**하고 이후 발생분은 버린다 — 두 레코드의 다른 필드(occurred_at/action/
    project 등)가 서로 달라도 선택 기준은 오직 "먼저 나왔는가"뿐이다(내용 비교·
    병합을 하지 않는다).

    ``PaperScenarioEvaluator``(ER/EC)와 ``StageCycleDetector._dedupe_by_event_id``
    (FR)가 이 함수를 공유해 동일한 중복 제거 기준을 쓴다.
    """
    seen: set = set()
    deduped: List[UsageEvent] = []
    duplicates: List[str] = []
    for event in events:
        if event.event_id in seen:
            duplicates.append(event.event_id)
            continue
        seen.add(event.event_id)
        deduped.append(event)
    return deduped, duplicates


def _dedupe_by_event_id(
    by_stage: Dict[str, List[UsageEvent]],
) -> Tuple[Dict[str, List[UsageEvent]], List[str]]:
    """같은 event_id 가 단계 내/단계 간에 중복으로 들어오면 최초 1건만 남긴다.

    ``_dedupe_events_by_id`` 와 동일한 "먼저 나온 레코드 채택" 기준을 쓴다 —
    여기서는 S1→S2→S3 순서로 이벤트를 펼친 뒤 그 함수에 위임하고, 살아남은
    이벤트를 원래 단계로 되돌린다. ``PaperScenarioEvaluator.evaluate()`` 가
    먼저 전체 이벤트를 정리하므로, 엔진을 통해 호출되는 한 이 함수에 도달하는
    시점엔 이미 중복이 없다 — ``StageCycleDetector`` 를 엔진 없이 단독으로 쓰는
    경우를 위한 방어선이다.
    """
    flattened = [event for stage in _STAGES for event in by_stage.get(stage, [])]
    deduped_flat, duplicates = _dedupe_events_by_id(flattened)
    kept_ids = {event.event_id for event in deduped_flat}
    deduped: Dict[str, List[UsageEvent]] = {stage: [] for stage in _STAGES}
    for stage in _STAGES:
        for event in by_stage.get(stage, []):
            if event.event_id in kept_ids:
                deduped[stage].append(event)
                kept_ids.discard(event.event_id)  # 같은 단계에 또 있어도 1건만
    return deduped, duplicates


def _earliest_unused_after(
    candidates: List[Tuple[datetime, UsageEvent]],
    *,
    after: datetime,
    deadline: datetime,
    consumed: set,
) -> Optional[Tuple[datetime, UsageEvent]]:
    """``after`` 보다 뒤, ``deadline`` 이내, 아직 소비되지 않은 가장 이른 이벤트."""
    for ts, event in candidates:  # candidates는 이미 시간순 정렬됨
        if event.event_id in consumed:
            continue
        if ts <= after:
            continue
        if ts > deadline:
            break  # 정렬돼 있으므로 이후 후보도 전부 범위를 벗어난다
        return ts, event
    return None


def _fr_score(cycle_count: int) -> int:
    """논문 표7 — 발생 빈도(FR) 점수. 비율 자체는 provider 와 무관해 그대로 쓴다."""
    if cycle_count == 1:
        return 30
    if cycle_count <= 5:
        return 50
    if cycle_count <= 10:
        return 70
    return 100


__all__ = ["PaperScenarioEvaluator", "StageCycleDetector", "DEFAULT_STAGE_MAPPING"]
