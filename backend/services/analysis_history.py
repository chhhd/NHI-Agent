"""NHI 분석 스냅샷 이력 조회와 결정 변화 비교.

분석 결과를 다시 채점하지 않고 저장 당시의 산출물을 비교한다. 따라서 정책/점수
버전이 바뀐 경우에도 어떤 결과가 언제 달라졌는지 감사 가능한 형태로 보존된다.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from storage.base import Storage


class AnalysisHistoryService:
    """NHI별 분석 이력을 조회하고 두 스냅샷의 의미 있는 차이를 계산한다."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def list_history(self, nhi_id: str, *, limit: int = 100) -> Dict[str, Any]:
        analyses = self.storage.list_nhi_analyses(nhi_id, limit=limit)
        return {
            "nhi_id": nhi_id,
            "count": len(analyses),
            "analyses": [summarize_analysis(item) for item in analyses],
        }

    def compare(
        self,
        nhi_id: str,
        *,
        base_analysis_id: Optional[str] = None,
        target_analysis_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        analyses = self.storage.list_nhi_analyses(nhi_id, limit=500)
        if not analyses:
            raise KeyError(f"분석 이력이 없습니다: {nhi_id}")

        target_index = 0
        if target_analysis_id:
            target_index = self._index_of(analyses, target_analysis_id)
        target = analyses[target_index]

        if base_analysis_id:
            base = analyses[self._index_of(analyses, base_analysis_id)]
        else:
            previous_index = target_index + 1
            if previous_index >= len(analyses):
                raise ValueError("선택한 분석보다 이전 스냅샷이 없습니다.")
            base = analyses[previous_index]

        if base.get("analysis_id") == target.get("analysis_id"):
            raise ValueError("서로 다른 두 분석 스냅샷을 선택해야 합니다.")

        return compare_analysis_snapshots(nhi_id, base, target)

    @staticmethod
    def _index_of(analyses: List[Dict[str, Any]], analysis_id: str) -> int:
        for index, analysis in enumerate(analyses):
            if analysis.get("analysis_id") == analysis_id:
                return index
        raise KeyError(f"NHI에 속한 분석을 찾을 수 없습니다: {analysis_id}")


def summarize_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """목록 화면에 필요한 비민감 결정 정보만 반환한다."""
    usage = analysis.get("usage_analysis") or {}
    policy = analysis.get("policy") or {}
    return {
        "analysis_id": analysis.get("analysis_id"),
        "analyzed_at": analysis.get("analyzed_at"),
        "repository": analysis.get("repository"),
        "nhi_name": analysis.get("nhi_name")
        or (analysis.get("discovery") or {}).get("nhi_name"),
        "risk_score": analysis.get("risk_score"),
        "risk_level": analysis.get("risk_level"),
        "policy_outcome": policy.get("outcome"),
        "recommended_action": analysis.get("recommended_action"),
        "permissions": sorted(_permissions(analysis)),
        "activity_status": usage.get("activity_status", "unknown"),
        "usage_data_complete": usage.get("data_complete") is True,
        "event_count": len(analysis.get("security_events") or []),
        "scenario_count": len(analysis.get("scenario_matches") or []),
        "scoring_version": analysis.get("scoring_version"),
        "policy_version": analysis.get("policy_version"),
    }


def compare_analysis_snapshots(
    nhi_id: str,
    base: Dict[str, Any],
    target: Dict[str, Any],
) -> Dict[str, Any]:
    """base → target 변화량을 결정 근거별로 비교한다."""
    base_score = _number(base.get("risk_score"))
    target_score = _number(target.get("risk_score"))
    score_delta = (
        target_score - base_score
        if base_score is not None and target_score is not None
        else None
    )
    if score_delta is None:
        trend = "UNKNOWN"
    elif score_delta > 0:
        trend = "DEGRADED"
    elif score_delta < 0:
        trend = "IMPROVED"
    else:
        trend = "UNCHANGED"

    base_policy = _policy_ids(base)
    target_policy = _policy_ids(target)
    base_forced = _forced_rule_ids(base)
    target_forced = _forced_rule_ids(target)
    base_permissions = _permissions(base)
    target_permissions = _permissions(target)
    base_actions = _action_ids(base)
    target_actions = _action_ids(target)
    base_scenarios = _scenario_ids(base)
    target_scenarios = _scenario_ids(target)

    comparison = {
        "risk": {
            "before_score": base_score,
            "after_score": target_score,
            "score_delta": score_delta,
            "before_level": base.get("risk_level"),
            "after_level": target.get("risk_level"),
            "trend": trend,
        },
        "policy_violations": _set_delta(base_policy, target_policy),
        "forced_critical_rules": _set_delta(base_forced, target_forced),
        "permissions": _set_delta(base_permissions, target_permissions),
        "recommendations": _set_delta(base_actions, target_actions),
        "scenarios": _set_delta(base_scenarios, target_scenarios),
        "owner": {
            "before": base.get("owner"),
            "after": target.get("owner"),
            "changed": base.get("owner") != target.get("owner"),
        },
        "usage": {
            "before_activity_status": (base.get("usage_analysis") or {}).get(
                "activity_status", "unknown"
            ),
            "after_activity_status": (target.get("usage_analysis") or {}).get(
                "activity_status", "unknown"
            ),
            "before_data_complete": (base.get("usage_analysis") or {}).get(
                "data_complete"
            )
            is True,
            "after_data_complete": (target.get("usage_analysis") or {}).get(
                "data_complete"
            )
            is True,
        },
    }
    changed = (
        score_delta not in (None, 0)
        or any(
            item["added"] or item["removed"]
            for item in (
                comparison["policy_violations"],
                comparison["forced_critical_rules"],
                comparison["permissions"],
                comparison["recommendations"],
                comparison["scenarios"],
            )
        )
        or comparison["owner"]["changed"]
        or comparison["usage"]["before_activity_status"]
        != comparison["usage"]["after_activity_status"]
        or comparison["usage"]["before_data_complete"]
        != comparison["usage"]["after_data_complete"]
    )
    return {
        "nhi_id": nhi_id,
        "base": summarize_analysis(base),
        "target": summarize_analysis(target),
        "changed": changed,
        "comparison": comparison,
    }


def _set_delta(before: Set[str], after: Set[str]) -> Dict[str, List[str]]:
    return {
        "added": sorted(after - before),
        "removed": sorted(before - after),
        "unchanged": sorted(before & after),
    }


def _values(items: Iterable[Any], key: str) -> Set[str]:
    return {
        str(item[key])
        for item in items
        if isinstance(item, dict) and item.get(key)
    }


def _permissions(analysis: Dict[str, Any]) -> Set[str]:
    detail = analysis.get("permission_detail") or {}
    values = detail.get("permissions")
    if not isinstance(values, list):
        values = analysis.get("permissions") or []
    return {str(item) for item in values if item}


def _policy_ids(analysis: Dict[str, Any]) -> Set[str]:
    return _values((analysis.get("policy") or {}).get("violations") or [], "policy_id")


def _forced_rule_ids(analysis: Dict[str, Any]) -> Set[str]:
    return _values(
        (analysis.get("risk_detail") or {}).get("forced_rules") or [], "rule_id"
    )


def _scenario_ids(analysis: Dict[str, Any]) -> Set[str]:
    return _values(analysis.get("scenario_matches") or [], "scenario_id")


def _action_ids(analysis: Dict[str, Any]) -> Set[str]:
    actions = _values(analysis.get("recommendations") or [], "action")
    if not actions and analysis.get("recommended_action"):
        actions.add(str(analysis["recommended_action"]))
    return actions


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


__all__ = [
    "AnalysisHistoryService",
    "compare_analysis_snapshots",
    "summarize_analysis",
]
