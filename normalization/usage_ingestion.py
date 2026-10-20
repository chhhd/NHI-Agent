"""감사 로그 → AnalysisSignals 병합. API 와 테스트가 공유하는 순수 함수(HTTP·저장소 의존 없음)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.nhi_models import AnalysisSignals
from normalization.usage_event_adapter import UsageEventAdapter
from security.redaction import sanitize_security_text


def signals_from_usage_events(
    *,
    nhi_id: str,
    provider: str,
    raw_signals: Optional[Dict[str, Any]],
    records: List[Dict[str, Any]],
    data_complete: bool,
    source: str,
    principal_aliases: Sequence[str] = (),
    declared_permissions: Sequence[str] = (),
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Audit Log를 NHI 분석 신호로 병합하고 수집 완전성 근거를 만든다."""
    adapter = UsageEventAdapter()
    adaptation = adapter.adapt(records, provider=provider, source=source)
    # 파싱 실패가 한 건이라도 있으면 요청자가 complete=true라고 했더라도 실제
    # 분석 범위는 불완전하다. 실패를 무시한 채 '미사용'을 확정하지 않는다.
    effective_complete = data_complete and not adaptation.failures
    derived = adapter.to_signals(
        adaptation.events,
        principal_ids=[nhi_id, *principal_aliases],
        declared_permissions=declared_permissions,
        data_complete=effective_complete,
    )
    merged = adapter.merge_into_signals(AnalysisSignals.from_dict(raw_signals), derived)
    summary = {
        **adaptation.summary(),
        "matched_event_count": derived.extra["usage_event_count"],
        "requested_data_complete": data_complete,
        "effective_data_complete": effective_complete,
        "principal_count": 1 + len(principal_aliases),
        "source": sanitize_security_text(source),
    }
    return merged.to_dict(), summary


__all__ = ["signals_from_usage_events"]
