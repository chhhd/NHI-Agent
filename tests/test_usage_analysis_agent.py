from datetime import datetime, timedelta, timezone

from agents.usage_analysis_agent import UsageAnalysisAgent
from core.nhi_models import AnalysisSignals, PermissionLevel, PermissionProfile


def _permissions(*levels):
    return PermissionProfile(permissions=list(levels))


def _signals(days_ago=None, actions=None):
    last_used_at = None
    if days_ago is not None:
        last_used_at = (
            datetime.now(timezone.utc) - timedelta(days=days_ago)
        ).isoformat()
    return AnalysisSignals(last_used_at=last_used_at, observed_actions=actions or [])


def test_all_granted_permissions_used_has_no_unused_permissions():
    result = UsageAnalysisAgent().analyze(
        _permissions(PermissionLevel.READ, PermissionLevel.WRITE),
        _signals(actions=["READ", "WRITE"]),
    )

    assert result.used_permissions == [PermissionLevel.READ, PermissionLevel.WRITE]
    assert result.unused_permissions == []


def test_unused_admin_permission_is_excessive():
    result = UsageAnalysisAgent().analyze(
        _permissions(PermissionLevel.READ, PermissionLevel.ADMIN),
        _signals(actions=["READ"]),
    )

    assert result.unused_permissions == [PermissionLevel.ADMIN]
    assert result.excessive_permission is True


def test_120_days_without_use_is_stale():
    result = UsageAnalysisAgent().analyze(
        _permissions(PermissionLevel.READ), _signals(days_ago=120)
    )

    assert result.days_since_last_used == 120
    assert result.usage_status == "stale"


def test_200_days_without_use_is_orphaned_candidate():
    result = UsageAnalysisAgent().analyze(
        _permissions(PermissionLevel.READ), _signals(days_ago=200)
    )

    assert result.days_since_last_used == 200
    assert result.usage_status == "orphaned_candidate"


def test_missing_last_used_at_is_unknown():
    result = UsageAnalysisAgent().analyze(
        _permissions(PermissionLevel.READ), _signals(actions=["READ"])
    )

    assert result.days_since_last_used is None
    assert result.usage_status == "unknown"
