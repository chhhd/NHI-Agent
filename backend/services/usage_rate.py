"""서버가 직접 측정하는 NHI 호출률 (호출 급증 탐지의 근거).

호출자가 넘기는 `requests_per_min`/`baseline_per_min` 같은 자가 신고 값은 신뢰할 수
없다 — 이 프로젝트 전체의 "Gateway/요청자가 보낸 값으로 보안을 판단하지 않는다"
원칙과 같은 이유다. 요청이 들어올 때마다 서버가 시각을 기록해 최근 1분 호출률과
그 직전 구간의 평균을 비교한다.

- 기준선 구간: (now-30분, now-1분]. 이 구간 호출이 `MIN_BASELINE_CALLS` 미만이면
  기준선을 신뢰할 수 없으므로 급증 판정을 하지 않는다(모름 ≠ 정상).
- 메모리 구현이라 프로세스 재시작 시 초기화되고 다중 프로세스에서는 공유되지 않는다
  — 운영에서는 Redis 등 공유 저장소로 교체해야 한다(`security/dpop.py`의
  `InMemoryReplayCache`와 같은 종류의 한계).
- 이 모듈은 측정만 한다. 측정값을 어떻게 판정에 반영할지는
  `backend/services/agent_access_evaluator.py::evaluate(call_rate_ratio=...)`가
  맡는다 — 평가기 자체는 상태를 갖지 않는 순수 함수로 유지하기 위해서다.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, Optional

CURRENT_WINDOW_SECONDS = 60
BASELINE_WINDOW_SECONDS = 30 * 60
MIN_BASELINE_CALLS = 10


@dataclass(frozen=True)
class RateSample:
    current_per_min: float
    baseline_per_min: Optional[float]  # None: 기준선 호출이 부족해 신뢰 불가

    @property
    def ratio(self) -> Optional[float]:
        if self.baseline_per_min is None or self.baseline_per_min <= 0:
            return None
        return self.current_per_min / self.baseline_per_min


class UsageRateTracker:
    def __init__(self, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._calls: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def observe(self, nhi_id: str) -> RateSample:
        """이번 호출을 기록하고 현재 호출률과 기준선을 돌려준다(이번 호출 포함)."""
        now = self._clock().timestamp()
        with self._lock:
            calls = self._calls[nhi_id]
            calls.append(now)
            while calls and calls[0] < now - BASELINE_WINDOW_SECONDS:
                calls.popleft()
            current = sum(1 for ts in calls if ts > now - CURRENT_WINDOW_SECONDS)
            baseline_calls = len(calls) - current
        if baseline_calls < MIN_BASELINE_CALLS:
            return RateSample(float(current), None)
        span_minutes = (BASELINE_WINDOW_SECONDS - CURRENT_WINDOW_SECONDS) / 60
        return RateSample(float(current), baseline_calls / span_minutes)

    def reset(self) -> None:
        with self._lock:
            self._calls.clear()


#: 요청마다 서비스 인스턴스가 새로 만들어지므로 프로세스 단위 공유 인스턴스를 쓴다.
DEFAULT_TRACKER = UsageRateTracker()

__all__ = [
    "DEFAULT_TRACKER",
    "MIN_BASELINE_CALLS",
    "RateSample",
    "UsageRateTracker",
]
