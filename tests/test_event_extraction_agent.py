from agents.event_extraction_agent import EventExtractionAgent
from core.nhi_models import (
    AnalysisSignals,
    NHIProfile,
    PermissionLevel,
    PermissionProfile,
    RiskLevel,
    PermissionUsageEvent,
    PermissionUsageResult,
)


def _extract(granted, *, used=None, unused=None, status="active", owner="team", signals=None):
    return EventExtractionAgent().extract(
        NHIProfile(nhi_id="nhi-test", nhi_name="test-bot", owner=owner),
        PermissionProfile(permissions=granted),
        PermissionUsageResult(
            granted_permissions=granted,
            used_permissions=used or [],
            unused_permissions=unused or [],
            usage_status=status,
        ),
        signals=signals,
    )


def test_admin_permission_creates_high_risk_scope_event():
    events = _extract([PermissionLevel.ADMIN])

    event = next(event for event in events if event.event_type == "HIGH_RISK_SCOPE_GRANTED")
    assert event.access_level is PermissionLevel.ADMIN
    assert event.event_risk is RiskLevel.CRITICAL


def test_stale_usage_creates_stale_permission_event():
    events = _extract([PermissionLevel.READ], status="stale")

    event = next(event for event in events if event.event_type == "STALE_PERMISSION")
    assert event.access_level is PermissionLevel.READ


def test_stale_usage_without_permissions_has_unknown_access_level():
    events = _extract([], status="stale")

    event = next(event for event in events if event.event_type == "STALE_PERMISSION")
    assert event.access_level is None


def test_unused_admin_creates_unused_high_privilege_event():
    events = _extract(
        [PermissionLevel.READ, PermissionLevel.ADMIN],
        unused=[PermissionLevel.ADMIN],
    )

    assert any(event.event_type == "UNUSED_HIGH_PRIVILEGE" for event in events)


def test_missing_owner_creates_owner_missing_event():
    events = _extract([PermissionLevel.READ], owner=None)

    event = next(event for event in events if event.event_type == "OWNER_MISSING")
    assert event.access_level is PermissionLevel.READ


def test_missing_owner_without_permissions_has_unknown_access_level():
    events = _extract([], owner=None)

    event = next(event for event in events if event.event_type == "OWNER_MISSING")
    assert event.access_level is None


def test_read_only_grant_with_write_usage_creates_unauthorized_mutation():
    events = _extract(
        [PermissionLevel.READ],
        used=[PermissionLevel.WRITE],
    )

    assert any(event.event_type == "UNAUTHORIZED_MUTATION" for event in events)


def test_normal_read_only_usage_creates_no_unnecessary_risk_event():
    events = _extract([PermissionLevel.READ], used=[PermissionLevel.READ])

    assert events == []


def test_same_condition_does_not_duplicate_event_types():
    events = _extract(
        [PermissionLevel.ADMIN],
        unused=[PermissionLevel.ADMIN],
        status="stale",
        signals=AnalysisSignals(shared_projects=["project-a", "project-b"]),
    )

    event_types = [event.event_type for event in events]
    assert len(event_types) == len(set(event_types))


def test_shared_projects_without_permissions_have_unknown_access_level():
    events = _extract(
        [], signals=AnalysisSignals(shared_projects=["project-a", "project-b"])
    )

    event = next(
        event for event in events if event.event_type == "TOKEN_SHARED_ACROSS_PROJECTS"
    )
    assert event.access_level is None


def test_security_event_serializes_unknown_access_level_as_null():
    event = PermissionUsageEvent(
        event_id="event-1",
        nhi_id="nhi-1",
        event_type="OWNER_MISSING",
        resource_type="nhi",
        access_level=None,
    )

    assert event.to_dict()["access_level"] is None
