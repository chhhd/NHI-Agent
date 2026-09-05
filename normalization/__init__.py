"""수집 결과를 분석 입력용 공통 Observation 으로 변환한다."""

from normalization.observation_normalizer import (
    observation_from_finding,
    observation_from_inventory,
    observation_from_saas_inventory,
)
from normalization.usage_event_adapter import UsageEventAdaptation, UsageEventAdapter

__all__ = [
    "observation_from_finding",
    "observation_from_inventory",
    "observation_from_saas_inventory",
    "UsageEventAdaptation",
    "UsageEventAdapter",
]
