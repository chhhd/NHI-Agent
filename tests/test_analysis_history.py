"""NHI 분석 스냅샷 이력과 변화 비교 테스트."""

from __future__ import annotations

import pytest

from backend.services.analysis_history import AnalysisHistoryService
from storage.sqlite_store import SQLiteStorage


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def _snapshot(
    *,
    analyzed_at: str,
    score: int,
    level: str,
    permissions,
    policy_ids,
    forced_ids=(),
    actions=("MONITOR",),
):
    return {
        "nhi_name": "deployment-agent",
        "owner": "platform-team",
        "repository": "acme/backend",
        "fingerprint": "fingerprint-1",
        "risk_score": score,
        "risk_level": level,
        "recommended_action": actions[0],
        "analyzed_at": analyzed_at,
        "discovery": {"nhi_id": "nhi-1", "nhi_name": "deployment-agent"},
        "permission_detail": {"permissions": list(permissions)},
        "usage_analysis": {
            "activity_status": "active",
            "data_complete": True,
        },
        "security_events": [],
        "scenario_matches": [
            {"scenario_id": rule_id} for rule_id in forced_ids
        ],
        "risk_detail": {
            "forced_rules": [{"rule_id": rule_id} for rule_id in forced_ids]
        },
        "policy": {
            "outcome": "HUMAN_REVIEW" if policy_ids else "MONITOR",
            "violations": [{"policy_id": policy_id} for policy_id in policy_ids],
        },
        "recommendations": [{"action": action} for action in actions],
    }


def _save(store, snapshot):
    return store.save_analysis(
        snapshot,
        repository="acme/backend",
        fingerprint="fingerprint-1",
    )


def test_history_comparison_reports_risk_policy_permission_and_action_delta(store):
    store.upsert_nhi("nhi-1", {"nhi_id": "nhi-1", "provider": "github"})
    store.bind_credential_to_nhi(
        "fingerprint-1", "nhi-1", confidence=0.95, evidence=["test"]
    )
    base_id = _save(
        store,
        _snapshot(
            analyzed_at="2026-09-01T00:00:00Z",
            score=82,
            level="CRITICAL",
            permissions=("READ", "WRITE", "ADMIN"),
            policy_ids=("ADMIN_SCOPE_RESTRICTED", "OWNER_REQUIRED"),
            forced_ids=("OWNERLESS_SENSITIVE_DATA_ACCESS",),
            actions=("SCOPE_REDUCTION", "ASSIGN_OWNER"),
        ),
    )
    target_id = _save(
        store,
        _snapshot(
            analyzed_at="2026-09-05T00:00:00Z",
            score=38,
            level="MEDIUM",
            permissions=("READ",),
            policy_ids=(),
            actions=("MONITOR",),
        ),
    )

    service = AnalysisHistoryService(store)
    history = service.list_history("nhi-1")
    result = service.compare("nhi-1")

    assert history["count"] == 2
    assert [item["analysis_id"] for item in history["analyses"]] == [
        target_id,
        base_id,
    ]
    assert result["comparison"]["risk"]["score_delta"] == -44
    assert result["comparison"]["risk"]["trend"] == "IMPROVED"
    assert result["comparison"]["permissions"]["removed"] == ["ADMIN", "WRITE"]
    assert result["comparison"]["policy_violations"]["removed"] == [
        "ADMIN_SCOPE_RESTRICTED",
        "OWNER_REQUIRED",
    ]
    assert result["comparison"]["forced_critical_rules"]["removed"] == [
        "OWNERLESS_SENSITIVE_DATA_ACCESS"
    ]
    assert result["comparison"]["recommendations"]["added"] == ["MONITOR"]
    assert result["changed"] is True


def test_compare_requires_an_older_snapshot(store):
    store.upsert_nhi("nhi-1", {"nhi_id": "nhi-1", "provider": "github"})
    store.bind_credential_to_nhi(
        "fingerprint-1", "nhi-1", confidence=0.95, evidence=["test"]
    )
    _save(
        store,
        _snapshot(
            analyzed_at="2026-09-05T00:00:00Z",
            score=38,
            level="MEDIUM",
            permissions=("READ",),
            policy_ids=(),
        ),
    )

    with pytest.raises(ValueError, match="이전 스냅샷"):
        AnalysisHistoryService(store).compare("nhi-1")
