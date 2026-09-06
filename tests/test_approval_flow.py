"""Human Approval 기본 흐름 테스트.

POST /nhi/{nhi_id}/approval-request → GET /approvals →
POST /approvals/{approval_id}/approve|reject.

실제 권한 변경(Credential 폐기/회전 등)은 이 단계에서 구현하지 않았으므로
다루지 않는다 — 승인 상태 전이와 감사 로그만 검증한다.
"""

from __future__ import annotations

import os

import pytest

from core.config import reset_settings


@pytest.fixture(autouse=True)
def _no_default_tokens(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    reset_settings()
    yield
    reset_settings()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """임시 DB 경로를 지정한 뒤 앱을 로딩한다 (프로젝트 디렉터리 오염 방지)."""
    os.environ["NHI_DB_PATH"] = str(tmp_path_factory.mktemp("db") / "test.db")
    os.environ["NHI_ADMIN_API_KEY"] = "test-admin-key"
    from fastapi.testclient import TestClient

    import api.app as app_module

    reset_settings()
    return TestClient(app_module.app)


def _seed(app_module, nhi_id, *, recommended_action="TOKEN_REVOCATION", risk_score=80):
    app_module.storage.upsert_nhi(
        nhi_id,
        {
            "nhi_id": nhi_id,
            "provider": "aws",
            "nhi_name": "ci-deploy-user",
            "risk_score": risk_score,
            "risk_level": "HIGH",
            "recommended_action": recommended_action,
        },
    )


ADMIN_HEADERS = {"X-NHI-Admin-Key": "test-admin-key"}


# ---------------------------------------------------------------------------
# POST /nhi/{nhi_id}/approval-request
# ---------------------------------------------------------------------------
def test_create_approval_request_returns_requested_fields(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-1", recommended_action="SCOPE_REDUCTION")

    response = client.post("/nhi/aws:approve-1/approval-request")

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {
        "id",
        "target_nhi_id",
        "recommended_action",
        "status",
        "created_at",
        "decided_at",
    }
    assert body["target_nhi_id"] == "aws:approve-1"
    assert body["recommended_action"] == "SCOPE_REDUCTION"
    assert body["status"] == "pending"
    assert body["created_at"]
    assert body["decided_at"] is None


def test_create_approval_request_returns_404_for_unknown_nhi(client):
    response = client.post("/nhi/does-not-exist/approval-request")

    assert response.status_code == 404


def test_create_approval_request_does_not_mutate_nhi_record(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-2")
    before = client.get("/nhi/aws:approve-2").json()

    client.post("/nhi/aws:approve-2/approval-request")

    after = client.get("/nhi/aws:approve-2").json()
    assert before == after


# ---------------------------------------------------------------------------
# GET /approvals
# ---------------------------------------------------------------------------
def test_list_approvals_includes_created_request(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-3")
    created = client.post("/nhi/aws:approve-3/approval-request").json()

    response = client.get("/approvals")

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"count", "approvals"}
    ids = {item["id"] for item in body["approvals"]}
    assert created["id"] in ids


# ---------------------------------------------------------------------------
# POST /approvals/{approval_id}/approve
# ---------------------------------------------------------------------------
def test_approve_requires_admin_key(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-4")
    approval = client.post("/nhi/aws:approve-4/approval-request").json()

    response = client.post(
        f"/approvals/{approval['id']}/approve",
        json={"actor": "security@example.com"},
    )

    assert response.status_code == 401


def test_approve_transitions_status_and_sets_decided_at(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-5")
    approval = client.post("/nhi/aws:approve-5/approval-request").json()

    response = client.post(
        f"/approvals/{approval['id']}/approve",
        json={"actor": "security@example.com", "reason": "reviewed"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"
    assert body["decided_at"] is not None
    assert body["id"] == approval["id"]


def test_approve_does_not_mutate_underlying_nhi_record(client):
    """승인해도 대상 NHI 레코드(권한/위험도 등)는 전혀 바뀌지 않는다 —
    실제 조치 실행은 이 단계에서 구현하지 않았다는 것을 행동으로 확인한다."""
    import api.app as app_module

    _seed(app_module, "aws:approve-11")
    before = client.get("/nhi/aws:approve-11").json()
    approval = client.post("/nhi/aws:approve-11/approval-request").json()

    client.post(
        f"/approvals/{approval['id']}/approve",
        json={"actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    after = client.get("/nhi/aws:approve-11").json()
    assert before == after


def test_approve_returns_404_for_unknown_approval(client):
    response = client.post(
        "/approvals/does-not-exist/approve",
        json={"actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404


def test_approve_twice_returns_409(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-6")
    approval = client.post("/nhi/aws:approve-6/approval-request").json()
    client.post(
        f"/approvals/{approval['id']}/approve",
        json={"actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    response = client.post(
        f"/approvals/{approval['id']}/approve",
        json={"actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 409


def test_approval_grant_is_audit_logged(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-7")
    approval = client.post("/nhi/aws:approve-7/approval-request").json()
    client.post(
        f"/approvals/{approval['id']}/approve",
        json={"actor": "security@example.com", "reason": "looks fine"},
        headers=ADMIN_HEADERS,
    )

    events = client.get("/audit?limit=200").json()["events"]
    matching = [e for e in events if e["target"] == approval["id"] and e["event_type"] == "APPROVAL_GRANTED"]
    assert matching
    assert matching[0]["actor"] == "security@example.com"


# ---------------------------------------------------------------------------
# POST /approvals/{approval_id}/reject
# ---------------------------------------------------------------------------
def test_reject_requires_admin_key(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-8")
    approval = client.post("/nhi/aws:approve-8/approval-request").json()

    response = client.post(
        f"/approvals/{approval['id']}/reject",
        json={"actor": "security@example.com"},
    )

    assert response.status_code == 401


def test_reject_transitions_status_and_sets_decided_at(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-9")
    approval = client.post("/nhi/aws:approve-9/approval-request").json()

    response = client.post(
        f"/approvals/{approval['id']}/reject",
        json={"actor": "security@example.com", "reason": "not needed"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "rejected"
    assert body["decided_at"] is not None


def test_rejection_is_audit_logged(client):
    import api.app as app_module

    _seed(app_module, "aws:approve-10")
    approval = client.post("/nhi/aws:approve-10/approval-request").json()
    client.post(
        f"/approvals/{approval['id']}/reject",
        json={"actor": "security@example.com", "reason": "false positive"},
        headers=ADMIN_HEADERS,
    )

    events = client.get("/audit?limit=200").json()["events"]
    matching = [e for e in events if e["target"] == approval["id"] and e["event_type"] == "APPROVAL_REJECTED"]
    assert matching
    assert matching[0]["detail"]["reason"] == "false positive"
