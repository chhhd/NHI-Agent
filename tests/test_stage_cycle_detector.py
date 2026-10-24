"""StageCycleDetector 단위 테스트 — 동일 NHI·동일 자산·시간순·이벤트 재사용 금지.

제약 확인용 핵심 테스트:
    * window를 명시하지 않으면 생성 자체가 안 된다(기본값 없음).
    * 자산 식별자가 없는 이벤트는 서로 "같은 자산"으로 묶이지 않는다.
    * 서로 다른 NHI / 서로 다른 자산 / 순서 역전 / 중복 event_id / 시간 윈도우
      초과는 전부 완결 세트로 세지 않는다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest

from core.usage_models import UsageEvent
from policy.paper_scenario_engine import StageCycleDetector

_BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event(
    event_id: str,
    stage_offset_minutes: int,
    *,
    principal_id: str = "github:nhi-1",
    project: Optional[str] = "acme/repo",
    resource: Optional[str] = None,
) -> UsageEvent:
    return UsageEvent(
        event_id=event_id,
        provider="github",
        principal_id=principal_id,
        action="irrelevant-for-this-test",
        occurred_at=(_BASE + timedelta(minutes=stage_offset_minutes)).isoformat(),
        source="organization_audit_log",
        project=project,
        resource=resource,
    )


def _by_stage(s1: List[UsageEvent], s2: List[UsageEvent], s3: List[UsageEvent]) -> Dict[str, List[UsageEvent]]:
    return {"S1": s1, "S2": s2, "S3": s3}


# --------------------------------------------------------------------------- window는 필수
def test_window_is_mandatory_no_default():
    with pytest.raises(ValueError):
        StageCycleDetector(window=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        StageCycleDetector(window=timedelta(0))
    with pytest.raises(ValueError):
        StageCycleDetector(window=timedelta(days=-1))


# --------------------------------------------------------------------------- 정상 완결
def test_single_asset_single_nhi_completes_one_cycle():
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1", 0)], [_event("s2", 10)], [_event("s3", 20)]
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 1
    assert result.unresolved_event_ids == []
    assert result.skipped_missing_asset_event_ids == []


# --------------------------------------------------------------------------- 서로 다른 NHI
def test_events_from_different_nhi_are_never_combined():
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1", 0, principal_id="github:nhi-A")],
        [_event("s2", 10, principal_id="github:nhi-B")],  # 다른 NHI
        [_event("s3", 20, principal_id="github:nhi-A")],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0
    assert "s1" in result.unresolved_event_ids


# --------------------------------------------------------------------------- 서로 다른 자산
def test_events_from_different_assets_are_never_combined():
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1", 0, project="acme/repo-a")],
        [_event("s2", 10, project="acme/repo-b")],  # 다른 저장소
        [_event("s3", 20, project="acme/repo-a")],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0


# --------------------------------------------------------------------------- 자산 식별자 없음 → 평가 불가 사유
def test_events_without_asset_identifier_are_excluded_not_treated_as_same_asset():
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1", 0, project=None, resource=None)],
        [_event("s2", 10, project=None, resource=None)],
        [_event("s3", 20, project=None, resource=None)],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0
    assert set(result.skipped_missing_asset_event_ids) == {"s1", "s2", "s3"}
    assert any("자산 식별자" in reason for reason in result.reasons)


def test_resource_is_used_when_project_is_absent():
    """project가 없어도 resource가 있으면 자산 식별자로 쓸 수 있다."""
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1", 0, project=None, resource="acme-org")],
        [_event("s2", 10, project=None, resource="acme-org")],
        [_event("s3", 20, project=None, resource="acme-org")],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 1


# --------------------------------------------------------------------------- 순서 역전
def test_reversed_order_events_do_not_form_a_cycle():
    """S2가 S1보다 먼저 발생하면 완결 세트로 인정하지 않는다."""
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1", 20)],   # S1이 가장 늦게 발생
        [_event("s2", 10)],
        [_event("s3", 0)],    # S3가 가장 먼저 발생
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0
    assert "s1" in result.unresolved_event_ids


# --------------------------------------------------------------------------- 중복 event_id
def test_duplicate_event_id_is_counted_once():
    detector = StageCycleDetector(window=timedelta(days=7))
    duplicate_s1 = _event("s1", 0)
    by_stage = _by_stage(
        [duplicate_s1, _event("s1", 1)],  # 같은 event_id가 두 번 들어옴(서로 다른 시각)
        [_event("s2", 10)],
        [_event("s3", 20)],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 1
    assert "s1" in result.duplicate_event_ids


def test_each_event_is_consumed_at_most_once_across_multiple_cycles():
    """이벤트가 풍부해도 한 이벤트는 한 세트에서만 쓰인다."""
    detector = StageCycleDetector(window=timedelta(days=7))
    by_stage = _by_stage(
        [_event("s1-a", 0), _event("s1-b", 100)],
        [_event("s2-a", 10)],  # S2는 1건뿐 — 두 번째 S1은 완결될 수 없어야 한다
        [_event("s3-a", 20)],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 1
    assert "s1-b" in result.unresolved_event_ids


# --------------------------------------------------------------------------- 시간 윈도우 초과
def test_events_beyond_the_time_window_do_not_form_a_cycle():
    detector = StageCycleDetector(window=timedelta(hours=1))
    by_stage = _by_stage(
        [_event("s1", 0)],
        [_event("s2", 30)],
        [_event("s3", 120)],  # S1으로부터 2시간 — window(1시간) 초과
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0
    assert "s1" in result.unresolved_event_ids
    assert "s2" in result.unresolved_event_ids


def test_events_within_the_time_window_do_form_a_cycle():
    detector = StageCycleDetector(window=timedelta(hours=3))
    by_stage = _by_stage(
        [_event("s1", 0)],
        [_event("s2", 30)],
        [_event("s3", 120)],  # 2시간 — window(3시간) 이내
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 1


def test_event_exactly_at_the_window_deadline_is_still_accepted():
    """경계값(== deadline)은 포함이다 — `_earliest_unused_after`가 `ts > deadline`
    일 때만 제외하므로, 정확히 deadline과 같은 시각은 통과한다. 이 경계 처리
    방식을 명시적으로 고정해 둔다."""
    detector = StageCycleDetector(window=timedelta(hours=2))
    by_stage = _by_stage(
        [_event("s1", 0)],
        [_event("s2", 60)],
        [_event("s3", 120)],  # S1으로부터 정확히 2시간 = window와 동일(경계값)
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 1


def test_event_one_unit_past_the_window_deadline_is_rejected():
    detector = StageCycleDetector(window=timedelta(hours=2))
    by_stage = _by_stage(
        [_event("s1", 0)],
        [_event("s2", 60)],
        [_event("s3", 121)],  # 2시간 1분 — window(2시간)을 1분 초과
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0


# --------------------------------------------------------------------------- 동일 타임스탬프 처리(문서화된 엣지 케이스)
def test_events_with_identical_timestamp_do_not_form_a_cycle():
    """S1과 S2가 정확히 같은 시각이면 매칭되지 않는다 — `_earliest_unused_after`가
    `ts <= after: continue`로 "엄격히 이후"만 인정하기 때문이다. 초 단위 해상도
    감사로그처럼 동일 타임스탬프가 흔한 환경에서는 FR이 체계적으로
    과소평가될 수 있다는 알려진 한계다(StageCycleDetector docstring에 명시).
    이 테스트는 그 현재 동작을 고정해 의도치 않게 바뀌는 것을 막는다."""
    detector = StageCycleDetector(window=timedelta(hours=1))
    by_stage = _by_stage(
        [_event("s1", 0)],
        [_event("s2", 0)],   # S1과 정확히 같은 시각
        [_event("s3", 10)],
    )

    result = detector(by_stage)

    assert result.completed_cycle_count == 0
    assert "s1" in result.unresolved_event_ids
