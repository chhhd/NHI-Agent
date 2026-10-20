"""승인자 신원 확정 · 역할 · 직무 분리 테스트.

TestClient 없이 엔드포인트 함수를 직접 호출해 헤더 인증 → actor 파생 → 서비스 계층까지 검증한다.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from backend.services.change_control_service import (
    ApproverNotAuthorized,
    ChangeControlService,
    SeparationOfDutiesError,
)
from core.config import reset_settings
from core.governance_models import ChangeStatus, ChangeType
from security.admin_identity import AdminDirectory, AdminIdentityError
from storage.sqlite_store import SQLiteStorage

from tests.helpers_app import load_private_app, unload_private_app
from tests.test_governance import make_nhi

BOOTSTRAP = "bootstrap-shared-key-0123456789abcdef0123"
_current = {}


class _ApiProxy:
    """테스트마다 새로 로드한 `api.app` 복사본으로 속성 접근을 넘긴다."""

    def __getattr__(self, name):
        return getattr(_current["module"], name)


api = _ApiProxy()


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", BOOTSTRAP)
    monkeypatch.delenv("NHI_REQUIRE_VERIFIED_ADMIN", raising=False)
    module, name = load_private_app(tmp_path, monkeypatch)
    instance = SQLiteStorage(":memory:")
    monkeypatch.setattr(module, "storage", instance)
    _current["module"] = module
    reset_settings()
    yield instance
    _current.clear()
    unload_private_app(module, name)
    instance.close()


def code_of(exc_info):
    return exc_info.value.status_code


def make_admin(admin_id, roles):
    result = api.create_admin_principal(
        api.AdminPrincipalCreateRequest(admin_id=admin_id, roles=roles),
        x_nhi_admin_key=BOOTSTRAP,
    )
    return result["api_key"]


# ------------------------------------------------------------ 계정 / 키
def test_key_is_shown_once_and_only_a_digest_is_stored(store):
    directory = AdminDirectory(store, bootstrap_key=BOOTSTRAP)
    principal, key = directory.create("alice", ["ADMIN"])
    secret = key.split(".", 2)[2]
    stored = str(store.get_admin_principal("alice"))
    assert secret not in stored and "key_digest" in stored
    assert "key_digest" not in principal
    identity = directory.authenticate(key)
    assert (identity.admin_id, identity.verified, identity.via) == ("alice", True, "principal")


def test_wrong_secret_unknown_account_and_disabled_account_are_rejected(store):
    directory = AdminDirectory(store, bootstrap_key=BOOTSTRAP)
    _, key = directory.create("alice", ["ADMIN"])
    prefix = key.rsplit(".", 1)[0]
    for bad in (prefix + ".wrong", "nhik.ghost." + key.split(".", 2)[2], "garbage", ""):
        with pytest.raises(AdminIdentityError) as exc:
            directory.authenticate(bad)
        assert exc.value.status == 401
    directory.set_disabled("alice", True)
    with pytest.raises(AdminIdentityError):
        directory.authenticate(key)


def test_rotating_a_key_invalidates_the_old_one(store):
    directory = AdminDirectory(store, bootstrap_key=BOOTSTRAP)
    _, old = directory.create("alice", ["ADMIN"])
    _, new = directory.rotate_key("alice")
    assert old != new
    assert directory.authenticate(new).admin_id == "alice"
    with pytest.raises(AdminIdentityError):
        directory.authenticate(old)


@pytest.mark.parametrize("admin_id", ["Bad Name", "bootstrap", "", "a" * 41, "x.y"])
def test_invalid_admin_ids_are_rejected(store, admin_id):
    with pytest.raises(AdminIdentityError) as exc:
        AdminDirectory(store, bootstrap_key=BOOTSTRAP).create(admin_id, ["ADMIN"])
    assert exc.value.status == 422


def test_unknown_or_missing_roles_are_rejected(store):
    directory = AdminDirectory(store, bootstrap_key=BOOTSTRAP)
    for roles in ([], ["SUPERUSER"]):
        with pytest.raises(AdminIdentityError) as exc:
            directory.create("alice", roles)
        assert exc.value.status == 422


def test_only_the_shared_bootstrap_key_manages_accounts(store):
    alice_key = make_admin("alice", ["ADMIN", "SECURITY"])
    with pytest.raises(HTTPException) as exc:
        api.create_admin_principal(
            api.AdminPrincipalCreateRequest(admin_id="mallory", roles=["SECURITY"]),
            x_nhi_admin_key=alice_key,
        )
    assert code_of(exc) == 403  # 계정이 스스로 권한을 올릴 수 없다
    with pytest.raises(HTTPException) as exc:
        api.list_admin_principals(x_nhi_admin_key=alice_key)
    assert code_of(exc) == 403


# ------------------------------------------------------------ 모드 전환
def test_legacy_mode_accepts_shared_key_with_declared_actor_but_marks_it_unverified(store):
    actor, identity = api._acting_admin(BOOTSTRAP, "alice")
    assert actor == "alice" and identity.verified is False
    with pytest.raises(HTTPException) as exc:
        api._acting_admin(BOOTSTRAP, None)
    assert code_of(exc) == 422


def test_first_personal_account_switches_the_shared_key_to_break_glass_only(store):
    assert api._directory().strict is False
    make_admin("alice", ["ADMIN"])
    assert api._directory().strict is True
    with pytest.raises(HTTPException) as exc:
        api._acting_admin(BOOTSTRAP, "alice")
    assert code_of(exc) == 403
    # 계정 관리와 whoami 는 여전히 가능하다
    assert api.admin_whoami(x_nhi_admin_key=BOOTSTRAP)["via"] == "bootstrap"


def test_disabling_every_account_returns_to_legacy_unless_strict_is_forced(store, monkeypatch):
    make_admin("alice", ["ADMIN"])
    api.disable_admin_principal("alice", x_nhi_admin_key=BOOTSTRAP)
    assert api._directory().strict is False
    monkeypatch.setenv("NHI_REQUIRE_VERIFIED_ADMIN", "true")
    reset_settings()
    assert api._directory().strict is True  # 강제 설정이면 계정이 없어도 공유 키로 승인 불가


def test_actor_is_derived_from_the_key_and_a_different_name_is_refused(store):
    alice_key = make_admin("alice", ["ADMIN"])
    assert api._acting_admin(alice_key, None)[0] == "alice"
    assert api._acting_admin(alice_key, "alice")[0] == "alice"
    with pytest.raises(HTTPException) as exc:
        api._acting_admin(alice_key, "bob")  # 다른 사람 이름으로 승인하려는 시도
    assert code_of(exc) == 403


def test_demo_nhi_can_be_driven_without_a_key_but_real_nhi_cannot(store):
    make_nhi(store, nhi_id="demo-1", demo_workspace=True)
    make_nhi(store, nhi_id="real-1")
    make_admin("alice", ["ADMIN"])
    actor, identity = api._acting_admin_unless_demo("demo-1", None, "visitor")
    assert (actor, identity.via, identity.verified) == ("visitor", "demo", False)
    with pytest.raises(HTTPException) as exc:
        api._acting_admin_unless_demo("real-1", None, "visitor")
    assert code_of(exc) == 401


# ------------------------------------------------------------ 직무 분리 · 역할 (엔드포인트 경유)
def propose(key, nhi_id="nhi-1"):
    return api.propose_change(
        api.ChangeProposeRequest(nhi_id=nhi_id, change_type=ChangeType.TOKEN_REVOKE),
        x_nhi_admin_key=key,
    )


def approve(key, change_id, **kwargs):
    return api.approve_change(
        change_id, api.ChangeDecisionRequest(**kwargs), x_nhi_admin_key=key
    )


def test_separation_of_duties_cannot_be_bypassed_by_typing_another_name(store):
    make_nhi(store)  # HIGH 등급
    alice = make_admin("alice", ["ADMIN"])
    bob = make_admin("bob", ["ADMIN"])
    change = propose(alice)
    assert change["requested_by"] == "alice" and change["requested_by_verified"] is True

    # 이전 방식: 본문 actor 에 다른 이름을 적어 우회 → 이제 403
    with pytest.raises(HTTPException) as exc:
        approve(alice, change["change_id"], actor="bob")
    assert code_of(exc) == 403
    # 본인 승인은 직무 분리로 거부
    with pytest.raises(HTTPException) as exc:
        approve(alice, change["change_id"])
    assert code_of(exc) == 403 and "다른 관리자" in exc.value.detail

    applied = approve(bob, change["change_id"])
    assert applied["status"] == ChangeStatus.APPLIED.value
    assert applied["approved_by"] == "bob" and applied["approved_by_verified"] is True


def test_critical_change_requires_the_security_role(store):
    make_nhi(store, permissions=["READ", "WRITE", "DELETE"])  # CRITICAL 등급
    alice = make_admin("alice", ["ADMIN"])
    bob = make_admin("bob", ["ADMIN"])
    sam = make_admin("sam", ["SECURITY"])
    change = propose(alice)
    assert change["tier"] == "CRITICAL"

    with pytest.raises(HTTPException) as exc:
        approve(bob, change["change_id"], acknowledge_impact=True)
    assert code_of(exc) == 403 and "SECURITY" in exc.value.detail
    assert store.get_change_request(change["change_id"]).status is ChangeStatus.PENDING_APPROVAL

    done = approve(sam, change["change_id"], acknowledge_impact=True)
    assert done["status"] == ChangeStatus.APPLIED.value and done["approved_by"] == "sam"


def test_shared_key_cannot_approve_once_personal_accounts_exist(store):
    make_nhi(store)
    alice = make_admin("alice", ["ADMIN"])
    change = propose(alice)
    with pytest.raises(HTTPException) as exc:
        approve(BOOTSTRAP, change["change_id"], actor="bob")
    assert code_of(exc) == 403


def test_legacy_flow_still_works_before_any_account_exists_and_is_marked_unverified(store):
    make_nhi(store)
    change = propose_legacy = api.propose_change(
        api.ChangeProposeRequest(
            nhi_id="nhi-1", change_type=ChangeType.TOKEN_REVOKE, requested_by="alice"
        ),
        x_nhi_admin_key=BOOTSTRAP,
    )
    assert change["requested_by_verified"] is False
    applied = approve(BOOTSTRAP, change["change_id"], actor="bob")
    assert applied["approved_by"] == "bob" and applied["approved_by_verified"] is False


def test_service_layer_role_check_is_skipped_only_when_roles_are_unknown(store):
    make_nhi(store, permissions=["READ", "WRITE", "DELETE"])
    changes = ChangeControlService(store)
    change = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="alice")
    with pytest.raises(ApproverNotAuthorized):
        changes.approve(change.change_id, actor="bob", acknowledge_impact=True, roles=["ADMIN"])
    with pytest.raises(SeparationOfDutiesError):
        changes.approve(change.change_id, actor="alice", acknowledge_impact=True, roles=["SECURITY"])
    assert changes.approve(
        change.change_id, actor="bob", acknowledge_impact=True, roles=["SECURITY"], verified=True
    ).status is ChangeStatus.APPLIED


# ------------------------------------------------------------ 실시간 보류 승인
def test_realtime_hold_decision_records_the_verified_approver(store):
    from backend.services.control_approval import ControlApprovalService

    approvals = ControlApprovalService(store)
    store.save_control_approval(
        {
            "decision_id": "d1",
            "status": "PENDING",
            "agent_id": "deploy-agent",
            "nhi_id": "nhi-1",
            "rule_ids": [],
            "event_seq": None,
            "binding": {},
            "requested_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2999-01-01T00:00:00+00:00",
        }
    )
    alice = make_admin("alice", ["ADMIN"])
    result = api.approve_control_hold(
        "d1", api.ApprovalDecisionRequest(reason="확인함"), x_nhi_admin_key=alice
    )
    assert result["approval"]["decided_by"] == "alice"
    assert result["approval"]["decided_by_verified"] is True
    assert approvals.get("d1")["status"] == "APPROVED"
    audit = [e for e in store.list_audit_events() if e["event_type"] == "REALTIME_HOLD_APPROVED"]
    assert audit and audit[0]["detail"]["actor_verified"] is True
