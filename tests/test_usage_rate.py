"""backend/services/usage_rate.py — 서버 측 호출률 측정(자가 신고 불신).

기준선 호출이 부족하면(`MIN_BASELINE_CALLS` 미만) ratio를 계산하지 않는다
("모름"과 "정상"을 구분), 호출이 쌓이면 현재/기준선 비율을 올바르게 계산하는지,
`BASELINE_WINDOW_SECONDS`보다 오래된 호출은 버려지는지를 확인한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.services.usage_rate import (
    BASELINE_WINDOW_SECONDS,
    CURRENT_WINDOW_SECONDS,
    MIN_BASELINE_CALLS,
    UsageRateTracker,
)


class _FakeClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def test_ratio_is_none_when_baseline_has_too_few_calls():
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    tracker = UsageRateTracker(clock=clock)

    for _ in range(MIN_BASELINE_CALLS - 1):
        clock.advance(60)
        sample = tracker.observe("nhi-1")

    assert sample.ratio is None
    assert sample.baseline_per_min is None


def test_ratio_reflects_spike_against_established_baseline():
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    tracker = UsageRateTracker(clock=clock)

    # 기준선 구간에 느린 속도로 충분한 호출을 쌓는다 (현재 1분 창 밖으로 보낸다).
    for _ in range(MIN_BASELINE_CALLS + 5):
        tracker.observe("nhi-1")
        clock.advance(120)  # 기준선 구간 호출 간격을 current window 밖으로 유지

    # 이제 짧은 간격으로 몰아서 호출 — 현재 1분 창에 몰림.
    clock.advance(CURRENT_WINDOW_SECONDS - 5)
    sample = None
    for _ in range(20):
        sample = tracker.observe("nhi-1")

    assert sample is not None
    assert sample.ratio is not None
    assert sample.current_per_min >= 15  # 20건이 거의 한 창에 몰렸다
    assert sample.ratio > 1.0  # 기준선보다 확실히 높다


def test_calls_older_than_baseline_window_are_discarded():
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    tracker = UsageRateTracker(clock=clock)

    for _ in range(MIN_BASELINE_CALLS + 5):
        tracker.observe("nhi-1")
        clock.advance(60)

    # 기준선 구간 전체보다 더 멀리 이동 — 과거 호출은 모두 버려져야 한다.
    clock.advance(BASELINE_WINDOW_SECONDS + 3600)
    sample = tracker.observe("nhi-1")

    # 이번 호출 1건뿐이라 기준선을 신뢰할 수 없다.
    assert sample.ratio is None


def test_different_nhi_ids_are_tracked_independently():
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    tracker = UsageRateTracker(clock=clock)

    for _ in range(MIN_BASELINE_CALLS + 1):
        tracker.observe("nhi-busy")
        clock.advance(60)

    quiet_sample = tracker.observe("nhi-quiet")
    assert quiet_sample.ratio is None  # nhi-busy 의 호출 이력과 섞이지 않는다


def test_reset_clears_all_tracked_calls():
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    tracker = UsageRateTracker(clock=clock)
    for _ in range(MIN_BASELINE_CALLS + 1):
        tracker.observe("nhi-1")
        clock.advance(60)

    tracker.reset()
    sample = tracker.observe("nhi-1")

    assert sample.ratio is None  # 리셋 이후 이번 호출 1건뿐
