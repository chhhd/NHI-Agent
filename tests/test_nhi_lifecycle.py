"""NHI 생명주기 모델(core.nhi_lifecycle_models)과 전이 규칙
(backend.services.nhi_lifecycle)을 검증한다.

NHI 상태(관리적 축)는 Credential 상태(기술적 축, `SecretFinding.credential_active`/
`credential_revoked`)와 별개다 — 이 테스트는 그 분리와, "권한 변경"이 상태
전이가 아니라 이벤트로만 기록된다는 설계를 함께 확인한다.
"""

from __future__ import annotations

import pytest

from backend.services.nhi_lifecycle import (
    ALLOWED_TRANSITIONS,
    EVENT_TYPE_FOR_TRANSITION,
    event_type_for_transition,
    validate_transition,
)
from core.nhi_lifecycle_models import (
    STATUS_TRANSITION_EVENTS,
    NHILifecycleEvent,
    NHILifecycleEventType,
    NHILifecycleStatus,
)


# ---------------------------------------------------------------------------
# 상태 전이 규칙
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "current,target",
    [
        (NHILifecycleStatus.REGISTERED, NHILifecycleStatus.ACTIVE),
        (NHILifecycleStatus.REGISTERED, NHILifecycleStatus.DEACTIVATED),
        (NHILifecycleStatus.ACTIVE, NHILifecycleStatus.DEACTIVATED),
        (NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.ACTIVE),  # 재사용
        (NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.DECOMMISSIONED),
    ],
)
def test_allowed_transitions_do_not_raise(current, target):
    validate_transition(current, target)  # 예외 없이 통과해야 한다


@pytest.mark.parametrize(
    "current,target",
    [
        (NHILifecycleStatus.REGISTERED, NHILifecycleStatus.DECOMMISSIONED),
        (NHILifecycleStatus.ACTIVE, NHILifecycleStatus.REGISTERED),
        (NHILifecycleStatus.DECOMMISSIONED, NHILifecycleStatus.ACTIVE),
        (NHILifecycleStatus.DECOMMISSIONED, NHILifecycleStatus.REGISTERED),
        (NHILifecycleStatus.DECOMMISSIONED, NHILifecycleStatus.DEACTIVATED),
    ],
)
def test_disallowed_transitions_raise_value_error(current, target):
    with pytest.raises(ValueError) as exc_info:
        validate_transition(current, target)
    assert current.value in str(exc_info.value)
    assert target.value in str(exc_info.value)


def test_same_state_transition_is_a_noop():
    for status in NHILifecycleStatus:
        validate_transition(status, status)  # 예외 없이 통과


def test_decommissioned_is_a_terminal_state():
    """파기(DECOMMISSIONED) 이후에는 어떤 상태로도 전이할 수 없다."""
    assert ALLOWED_TRANSITIONS[NHILifecycleStatus.DECOMMISSIONED] == set()


def test_permission_changed_is_not_a_lifecycle_status():
    """'권한 변경'은 NHILifecycleStatus 값이 아니라 이벤트 유형으로만 존재한다."""
    status_values = {status.value for status in NHILifecycleStatus}
    assert "PERMISSION_CHANGED" not in status_values
    assert NHILifecycleEventType.PERMISSION_CHANGED.value == "PERMISSION_CHANGED"


def test_all_four_core_statuses_are_defined():
    assert {status.value for status in NHILifecycleStatus} == {
        "REGISTERED",
        "ACTIVE",
        "DEACTIVATED",
        "DECOMMISSIONED",
    }


def test_every_status_is_reachable_or_terminal():
    """DECOMMISSIONED를 제외한 모든 상태는 적어도 하나의 전이 경로를 가진다."""
    for status, targets in ALLOWED_TRANSITIONS.items():
        if status is NHILifecycleStatus.DECOMMISSIONED:
            continue
        assert targets, f"{status} 는 전이 경로가 없다"


# ---------------------------------------------------------------------------
# NHILifecycleEvent — 상태 전이 이벤트 vs 순수 이벤트(권한 변경) 구분
# ---------------------------------------------------------------------------
def test_status_transition_events_exclude_only_permission_changed():
    assert NHILifecycleEventType.PERMISSION_CHANGED not in STATUS_TRANSITION_EVENTS
    for event_type in NHILifecycleEventType:
        if event_type is NHILifecycleEventType.PERMISSION_CHANGED:
            continue
        assert event_type in STATUS_TRANSITION_EVENTS


def test_permission_changed_event_keeps_status_unchanged():
    event = NHILifecycleEvent(
        nhi_id="github:bot-1",
        event_type=NHILifecycleEventType.PERMISSION_CHANGED,
        from_status=NHILifecycleStatus.ACTIVE,
        to_status=NHILifecycleStatus.ACTIVE,
        actor="security@example.com",
        note="SCOPE_REDUCTION 적용 — ADMIN 제거",
    )

    assert event.changes_status is False
    data = event.to_dict()
    assert data["from_status"] == data["to_status"] == "ACTIVE"
    assert data["changes_status"] is False
    assert data["event_type"] == "PERMISSION_CHANGED"


def test_created_event_represents_a_real_status_transition():
    event = NHILifecycleEvent(
        nhi_id="github:bot-1",
        event_type=NHILifecycleEventType.CREATED,
        from_status=None,
        to_status=NHILifecycleStatus.REGISTERED,
        actor="system",
        note="최초 인벤토리 분석으로 등록",
    )

    assert event.changes_status is True
    data = event.to_dict()
    assert data["from_status"] is None
    assert data["to_status"] == "REGISTERED"
    assert data["changes_status"] is True


def test_event_detail_never_requires_raw_credential_value():
    """detail은 참고 정보(예: recommended_action)만 담고 원문 Secret은 다루지 않는다."""
    event = NHILifecycleEvent(
        nhi_id="aws:ci-deploy-user",
        event_type=NHILifecycleEventType.DEACTIVATED,
        from_status=NHILifecycleStatus.ACTIVE,
        to_status=NHILifecycleStatus.DEACTIVATED,
        actor="admin-api",
        note="TOKEN_REVOCATION 조치 승인에 따른 종료 처리",
        detail={"recommended_action": "TOKEN_REVOCATION", "analysis_id": "abc-123"},
    )

    data = event.to_dict()
    assert data["detail"] == {"recommended_action": "TOKEN_REVOCATION", "analysis_id": "abc-123"}
    assert "credential" not in data["detail"]


# ---------------------------------------------------------------------------
# PATCH API가 쓰는 (현재, 목표) → 이벤트 유형 매핑 — ALLOWED_TRANSITIONS와 동기화
# ---------------------------------------------------------------------------
def test_every_allowed_transition_has_a_mapped_event_type():
    """ALLOWED_TRANSITIONS에 전이가 추가되면 이 테스트가 깨져 매핑 갱신을 강제한다."""
    for current, targets in ALLOWED_TRANSITIONS.items():
        for target in targets:
            if target == current:
                continue
            assert (current, target) in EVENT_TYPE_FOR_TRANSITION, (current, target)


def test_event_type_for_transition_matches_expected_mapping():
    assert (
        event_type_for_transition(NHILifecycleStatus.REGISTERED, NHILifecycleStatus.ACTIVE)
        is NHILifecycleEventType.ACTIVATED
    )
    assert (
        event_type_for_transition(NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.ACTIVE)
        is NHILifecycleEventType.REACTIVATED
    )
    assert (
        event_type_for_transition(NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.DECOMMISSIONED)
        is NHILifecycleEventType.DECOMMISSIONED
    )


def test_event_type_for_transition_rejects_disallowed_transition():
    with pytest.raises(ValueError):
        event_type_for_transition(NHILifecycleStatus.REGISTERED, NHILifecycleStatus.DECOMMISSIONED)


def test_to_dict_is_json_serializable():
    import json

    event = NHILifecycleEvent(
        nhi_id="github:bot-1",
        event_type=NHILifecycleEventType.ACTIVATED,
        from_status=NHILifecycleStatus.REGISTERED,
        to_status=NHILifecycleStatus.ACTIVE,
        actor="system",
    )
    json.dumps(event.to_dict(), ensure_ascii=False)  # 예외 없이 직렬화돼야 한다
