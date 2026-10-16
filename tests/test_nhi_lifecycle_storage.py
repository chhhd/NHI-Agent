"""NHI 생명주기 저장소(storage/sqlite_store.py) 테스트.

`backend/services/finding_lifecycle.py` + `finding_status_history` 패턴을
그대로 재사용했는지, 상태 변경과 이력 기록이 하나의 트랜잭션으로 처리되는지,
`PERMISSION_CHANGED`가 상태를 바꾸지 않는지, 잘못된 전이가 막히는지,
민감정보가 저장되지 않는지, 과거(이 기능 도입 이전) NHI 데이터와 호환되는지를
확인한다.
"""

from __future__ import annotations

import json

import pytest

from core.destruction_models import DestructionEvidence, DestructionMethod, evidence_digest
from core.nhi_lifecycle_models import NHILifecycleEventType, NHILifecycleStatus
from storage.sqlite_store import SQLiteStorage


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


# ---------------------------------------------------------------------------
# 초기화 — 생성·등록
# ---------------------------------------------------------------------------
def test_get_lifecycle_state_returns_none_before_initialization(store):
    """이 기능 도입 이전부터 있던 NHI(초기화되지 않음)는 None — 과거 데이터 호환."""
    assert store.get_nhi_lifecycle_state("github:legacy-bot") is None
    assert store.get_nhi_lifecycle_history("github:legacy-bot") == []


def test_initialize_creates_registered_state_and_created_event(store):
    result = store.initialize_nhi_lifecycle(
        "github:bot-1", actor="system", note="최초 인벤토리 분석으로 등록"
    )

    assert result["status"] == NHILifecycleStatus.REGISTERED.value
    state = store.get_nhi_lifecycle_state("github:bot-1")
    assert state["status"] == NHILifecycleStatus.REGISTERED.value

    history = store.get_nhi_lifecycle_history("github:bot-1")
    assert len(history) == 1
    assert history[0]["event_type"] == NHILifecycleEventType.CREATED.value
    assert history[0]["from_status"] is None
    assert history[0]["to_status"] == NHILifecycleStatus.REGISTERED.value


def test_initialize_is_idempotent_for_repeated_analysis(store):
    """재분석마다 반복 호출돼도 상태/이력이 중복 생성되지 않는다."""
    first = store.initialize_nhi_lifecycle("github:bot-1", actor="system")
    second = store.initialize_nhi_lifecycle("github:bot-1", actor="system")

    assert first == second
    assert len(store.get_nhi_lifecycle_history("github:bot-1")) == 1


# ---------------------------------------------------------------------------
# 상태 전이 — 사용 시작/종료/재사용/파기
# ---------------------------------------------------------------------------
def test_status_transition_updates_state_and_appends_history_atomically(store):
    store.initialize_nhi_lifecycle("github:bot-1", actor="system")

    result = store.update_nhi_lifecycle_status(
        "github:bot-1",
        NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED,
        actor="security@example.com",
        note="실제 서비스에 사용 시작",
    )

    assert result["status"] == NHILifecycleStatus.ACTIVE.value
    assert store.get_nhi_lifecycle_state("github:bot-1")["status"] == NHILifecycleStatus.ACTIVE.value

    history = store.get_nhi_lifecycle_history("github:bot-1")
    assert [item["to_status"] for item in history] == ["REGISTERED", "ACTIVE"]
    assert history[-1]["event_type"] == NHILifecycleEventType.ACTIVATED.value
    assert history[-1]["from_status"] == "REGISTERED"


def test_full_lifecycle_path_registered_to_decommissioned(store):
    nhi_id = "aws:ci-deploy-user"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="admin-api",
        note="TOKEN_REVOCATION 조치 승인",
    )
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DECOMMISSIONED,
        event_type=NHILifecycleEventType.DECOMMISSIONED, actor="admin-api",
    )

    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.DECOMMISSIONED.value
    history = store.get_nhi_lifecycle_history(nhi_id)
    assert [item["event_type"] for item in history] == [
        "CREATED", "ACTIVATED", "DEACTIVATED", "DECOMMISSIONED",
    ]


def test_reactivation_after_deactivation_is_allowed(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )
    result = store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.REACTIVATED, actor="system",
        note="재승인 후 다시 사용",
    )

    assert result["status"] == NHILifecycleStatus.ACTIVE.value


# ---------------------------------------------------------------------------
# DECOMMISSIONED 파기 증적 (DestructionEvidence) — 팀원 설계 흡수
# ---------------------------------------------------------------------------
def _valid_evidence(**overrides) -> DestructionEvidence:
    fields = dict(
        method=DestructionMethod.PROVIDER_REVOKED,
        performed_by="alice",
        verified_by="bob",
        verification_check="GitHub API로 토큰 재사용 시도 → 401 확인",
        verification_result="AUTH_REJECTED_401",
    )
    fields.update(overrides)
    return DestructionEvidence(**fields)


def test_decommission_without_evidence_still_works_and_is_marked_unprovided(store):
    """하위 호환 — 증적 없이도 기존처럼 전이된다. 단, '증적 없음'이 명시적으로 남는다."""
    nhi_id = "github:bot-legacy"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DECOMMISSIONED,
        event_type=NHILifecycleEventType.DECOMMISSIONED, actor="system",
    )

    history = store.get_nhi_lifecycle_history(nhi_id)
    detail = history[-1]["detail"]
    assert detail["destruction_evidence_provided"] is False
    assert "evidence_digest" not in detail


def test_decommission_with_valid_evidence_records_full_detail_and_digest(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )
    before = store.get_nhi_lifecycle_history(nhi_id)[-1]["history_id"]

    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DECOMMISSIONED,
        event_type=NHILifecycleEventType.DECOMMISSIONED, actor="alice",
        destruction_evidence=_valid_evidence(),
    )

    history = store.get_nhi_lifecycle_history(nhi_id)
    detail = history[-1]["detail"]
    assert detail["destruction_evidence_provided"] is True
    assert detail["destruction_method"] == "PROVIDER_REVOKED"
    assert detail["destruction_performed_by"] == "alice"
    assert detail["destruction_verified_by"] == "bob"
    assert detail["destruction_verification_result"] == "AUTH_REJECTED_401"
    expected_digest = evidence_digest(_valid_evidence().to_dict(), before)
    # verified_at 타임스탬프가 포함돼 완전히 같을 수는 없지만, sha256: 접두사와
    # 64자 hex 전체가 마스킹 없이 그대로 보존됐는지는 길이로 확인한다.
    assert detail["evidence_digest"].startswith("sha256:")
    assert len(detail["evidence_digest"]) == len("sha256:") + 64


def test_decommission_rejects_same_performer_and_verifier(store):
    """수행자==검증자면 증적으로 인정하지 않는다 — 상태/이력 모두 바뀌지 않는다."""
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    with pytest.raises(ValueError):
        store.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.DECOMMISSIONED,
            event_type=NHILifecycleEventType.DECOMMISSIONED, actor="alice",
            destruction_evidence=_valid_evidence(performed_by="alice", verified_by="alice"),
        )

    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.DEACTIVATED.value
    assert len(store.get_nhi_lifecycle_history(nhi_id)) == 2  # CREATED, DEACTIVATED 만


def test_decommission_rejects_unaccepted_verification_result(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    with pytest.raises(ValueError):
        store.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.DECOMMISSIONED,
            event_type=NHILifecycleEventType.DECOMMISSIONED, actor="alice",
            destruction_evidence=_valid_evidence(verification_result="I_THINK_ITS_FINE"),
        )


def test_decommission_evidence_on_non_decommissioned_target_is_rejected(store):
    """destruction_evidence는 DECOMMISSIONED 전이에서만 쓴다."""
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")

    with pytest.raises(ValueError):
        store.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.ACTIVE,
            event_type=NHILifecycleEventType.ACTIVATED, actor="alice",
            destruction_evidence=_valid_evidence(),
        )


def test_destruction_evidence_field_names_survive_sanitization():
    """회귀 테스트 — verification_result(20자) 같은 구조화된 필드명이
    Change Preview replay snapshot 버그처럼 토큰으로 오인돼 마스킹되면 안 된다."""
    from security.redaction import sanitize_security_value

    evidence_dict = _valid_evidence().to_dict()
    result = sanitize_security_value(evidence_dict, preserve_top_level_keys=True)
    for field_name in (
        "method", "performed_by", "verified_by",
        "verification_check", "verification_result",
    ):
        assert field_name in result, f"{field_name} 키가 마스킹돼 사라짐"


# ---------------------------------------------------------------------------
# 잘못된 상태 전이 방지
# ---------------------------------------------------------------------------
def test_invalid_transition_is_rejected_and_nothing_is_written(store):
    """허용되지 않은 전이는 ValueError — 상태도 이력도 바뀌지 않는다."""
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")

    with pytest.raises(ValueError):
        store.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.DECOMMISSIONED,
            event_type=NHILifecycleEventType.DECOMMISSIONED, actor="system",
        )

    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.REGISTERED.value
    assert len(store.get_nhi_lifecycle_history(nhi_id)) == 1  # CREATED 만 남아야 한다


def test_decommissioned_state_rejects_any_further_transition(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DECOMMISSIONED,
        event_type=NHILifecycleEventType.DECOMMISSIONED, actor="system",
    )

    with pytest.raises(ValueError):
        store.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.ACTIVE,
            event_type=NHILifecycleEventType.REACTIVATED, actor="system",
        )


def test_unknown_nhi_raises_key_error_not_silent_creation(store):
    """초기화되지 않은 NHI에 전이를 시도하면 KeyError — 암묵적으로 만들어주지 않는다."""
    with pytest.raises(KeyError):
        store.update_nhi_lifecycle_status(
            "nhi:never-registered", NHILifecycleStatus.ACTIVE,
            event_type=NHILifecycleEventType.ACTIVATED, actor="system",
        )
    with pytest.raises(KeyError):
        store.record_nhi_permission_change("nhi:never-registered", actor="system")


def test_permission_changed_event_type_is_rejected_by_status_transition_method(store):
    """PERMISSION_CHANGED는 상태 전이 메서드가 아니라 전용 메서드로만 기록해야 한다."""
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")

    with pytest.raises(ValueError):
        store.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.REGISTERED,
            event_type=NHILifecycleEventType.PERMISSION_CHANGED, actor="system",
        )


# ---------------------------------------------------------------------------
# PERMISSION_CHANGED — 상태는 유지, 이벤트만 기록
# ---------------------------------------------------------------------------
def test_permission_change_does_not_alter_status(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    before_updated_at = store.get_nhi_lifecycle_state(nhi_id)["updated_at"]

    result = store.record_nhi_permission_change(
        nhi_id, actor="admin-api", note="SCOPE_REDUCTION 적용 — ADMIN 제거",
        detail={"recommended_action": "SCOPE_REDUCTION"},
    )

    assert result["status"] == NHILifecycleStatus.ACTIVE.value
    state = store.get_nhi_lifecycle_state(nhi_id)
    assert state["status"] == NHILifecycleStatus.ACTIVE.value
    assert state["updated_at"] == before_updated_at  # 상태 전이 시각은 바뀌지 않는다

    history = store.get_nhi_lifecycle_history(nhi_id)
    change_event = history[-1]
    assert change_event["event_type"] == NHILifecycleEventType.PERMISSION_CHANGED.value
    assert change_event["from_status"] == change_event["to_status"] == NHILifecycleStatus.ACTIVE.value
    assert change_event["detail"] == {"recommended_action": "SCOPE_REDUCTION"}


def test_multiple_permission_changes_accumulate_in_history_without_status_change(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    store.record_nhi_permission_change(nhi_id, actor="admin-api", note="1차 축소")
    store.record_nhi_permission_change(nhi_id, actor="admin-api", note="2차 축소")

    history = store.get_nhi_lifecycle_history(nhi_id)
    permission_events = [h for h in history if h["event_type"] == "PERMISSION_CHANGED"]
    assert len(permission_events) == 2
    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.ACTIVE.value


# ---------------------------------------------------------------------------
# NHI 상태 vs Credential 상태 — 서로 다른 축, 서로 영향 없음
# ---------------------------------------------------------------------------
def test_nhi_lifecycle_status_is_independent_of_credential_active_flag(store):
    """이 저장소 계층은 `SecretFinding.credential_active`를 전혀 참조/변경하지 않는다."""
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")
    store.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    # NHI는 종료(DEACTIVATED) 상태이지만, 이 모듈은 credential_active 값을
    # 전혀 건드리지 않았으므로 기존 nhi_identities 레코드는 그대로다.
    store.upsert_nhi(nhi_id, {"nhi_id": nhi_id, "provider": "github", "owner": None})
    record = store.get_nhi_record(nhi_id)
    assert "lifecycle_status" not in record  # 이번 단계에서는 get_nhi_record를 건드리지 않았다
    assert store.get_nhi_lifecycle_state(nhi_id)["status"] == NHILifecycleStatus.DEACTIVATED.value


# ---------------------------------------------------------------------------
# 민감정보 저장 방지
# ---------------------------------------------------------------------------
def test_note_with_credential_like_value_is_redacted_before_storage(store):
    nhi_id = "github:bot-1"
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    store.initialize_nhi_lifecycle(
        nhi_id, actor="system", note=f"발견된 토큰: {secret}"
    )

    history = store.get_nhi_lifecycle_history(nhi_id)
    serialized = json.dumps(history, ensure_ascii=False)
    assert secret not in serialized
    assert secret not in history[0]["note"]


def test_detail_with_credential_like_value_is_redacted_before_storage(store):
    nhi_id = "github:bot-1"
    secret = "xoxb-123456-abcdefghijklmno"
    store.initialize_nhi_lifecycle(
        nhi_id, actor="system",
        detail={"observed_header": f"Authorization: Bearer {secret}"},
    )

    history = store.get_nhi_lifecycle_history(nhi_id)
    assert secret not in json.dumps(history, ensure_ascii=False)


def test_empty_note_and_detail_round_trip_safely(store):
    nhi_id = "github:bot-1"
    store.initialize_nhi_lifecycle(nhi_id, actor="system")

    history = store.get_nhi_lifecycle_history(nhi_id)
    assert history[0]["note"] == ""
    assert history[0]["detail"] == {}


# ---------------------------------------------------------------------------
# demo workspace 정리 시 생명주기 데이터도 함께 삭제되는지
# ---------------------------------------------------------------------------
def test_clear_demo_workspace_removes_lifecycle_rows_for_demo_nhi(store):
    from backend.services.demo_workspace import seed_demo_workspace, clear_demo_workspace

    seed_demo_workspace(store)
    demo_nhi_ids = [row["nhi_id"] for row in store.list_nhi_records(limit=500)]
    assert demo_nhi_ids
    for nhi_id in demo_nhi_ids:
        store.initialize_nhi_lifecycle(nhi_id, actor="system")

    clear_demo_workspace(store)

    for nhi_id in demo_nhi_ids:
        assert store.get_nhi_lifecycle_state(nhi_id) is None
        assert store.get_nhi_lifecycle_history(nhi_id) == []
