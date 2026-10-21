"""공용 관리자 키와 단일 관리자 승인 정책 테스트."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from backend.services.change_control_service import ChangeControlService
from backend.services.control_approval import ControlApprovalService
from core.config import reset_settings
from core.governance_models import ChangeStatus, ChangeType
from storage.sqlite_store import SQLiteStorage
from tests.helpers_app import load_private_app, unload_private_app
from tests.test_governance import make_nhi

ADMIN = "shared-admin-key-0123456789abcdef012345"


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", ADMIN)
    module, name = load_private_app(tmp_path, monkeypatch)
    module.storage = SQLiteStorage(":memory:")
    reset_settings()
    yield module
    module.storage.close()
    unload_private_app(module, name)


def test_only_the_shared_admin_key_is_accepted(app):
    app._require_admin_key(ADMIN)
    for bad in (None, "", "wrong-key"):
        with pytest.raises(HTTPException) as exc:
            app._require_admin_key(bad)
        assert exc.value.status_code == 401


def test_actor_is_required_and_used_as_an_audit_label(app):
    assert app._acting_admin(ADMIN, "alice") == "alice"
    with pytest.raises(HTTPException) as exc:
        app._acting_admin(ADMIN, None)
    assert exc.value.status_code == 422


def test_personal_admin_routes_were_removed(app):
    paths = {route.path for route in app.app.routes}
    assert "/admin/whoami" not in paths
    assert "/admin/principals" not in paths
    assert not any(path.startswith("/admin/principals/") for path in paths)


def test_demo_bypasses_key_but_real_nhi_does_not(app):
    make_nhi(app.storage, nhi_id="demo-1", demo_workspace=True)
    make_nhi(app.storage, nhi_id="real-1")
    assert app._acting_admin_unless_demo("demo-1", None, "visitor") == "visitor"
    with pytest.raises(HTTPException) as exc:
        app._acting_admin_unless_demo("real-1", None, "visitor")
    assert exc.value.status_code == 401


def test_all_risk_tiers_use_one_admin_approval_without_sod_or_ack(app):
    make_nhi(app.storage, permissions=["READ", "WRITE", "DELETE"])
    proposed = app.propose_change(
        app.ChangeProposeRequest(
            nhi_id="nhi-1",
            change_type=ChangeType.TOKEN_REVOKE,
            requested_by="alice",
        ),
        x_nhi_admin_key=ADMIN,
    )
    assert proposed["tier"] == "CRITICAL"
    assert proposed["approval"]["separation_of_duties"] is False
    assert proposed["approval"]["impact_acknowledgement_required"] is False
    assert "requested_by_verified" not in proposed

    applied = app.approve_change(
        proposed["change_id"],
        app.ChangeDecisionRequest(actor="alice"),
        x_nhi_admin_key=ADMIN,
    )
    assert applied["status"] == ChangeStatus.APPLIED.value
    assert applied["approved_by"] == "alice"
    assert "approved_by_verified" not in applied


def test_low_risk_change_also_waits_for_admin(app):
    make_nhi(
        app.storage,
        environment="development",
        permissions=["READ"],
        blast_radius={},
        linked_ai_agent=None,
    )
    changes = ChangeControlService(app.storage)
    change = changes.propose(
        "nhi-1",
        ChangeType.TOKEN_ROTATE,
        requested_by="alice",
        params={"grace_period_hours": 2},
    )
    assert change.tier.value == "LOW"
    assert change.status is ChangeStatus.PENDING_APPROVAL
    assert changes.approve(change.change_id, actor="alice").status is ChangeStatus.APPLIED


def test_realtime_hold_records_shared_admin_auth_mode(app):
    approvals = ControlApprovalService(app.storage)
    app.storage.save_control_approval(
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
    result = app.approve_control_hold(
        "d1",
        app.ApprovalDecisionRequest(actor="alice", reason="확인함"),
        x_nhi_admin_key=ADMIN,
    )
    assert result["approval"]["decided_by"] == "alice"
    assert "decided_by_verified" not in result["approval"]
    assert approvals.get("d1")["status"] == "APPROVED"
    audit = [
        event
        for event in app.storage.list_audit_events()
        if event["event_type"] == "REALTIME_HOLD_APPROVED"
    ]
    assert audit[0]["detail"]["auth_mode"] == "shared_admin_key"
