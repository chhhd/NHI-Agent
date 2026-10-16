"""POST /nhi/{id}/changes, /changes/{id}/{approve,reject,apply,rollback} — API 계층.

서비스 계층(`tests/test_change_control_service.py`)에서 이미 검증한 로직을
HTTP 경계에서 다시 확인한다: 관리자 키 필요, 상태 코드 매핑(403/409/422),
`/nhi/{owner}/{repo}` 와 라우트 충돌이 없는지, 응답에 `provider_call`이
항상 노출되는지, 감사 로그(`GET /audit`)에 남는지.
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
    os.environ["NHI_DB_PATH"] = str(tmp_path_factory.mktemp("db") / "test.db")
    os.environ["NHI_ADMIN_API_KEY"] = "test-admin-key"
    from fastapi.testclient import TestClient

    import api.app as app_module

    reset_settings()
    return TestClient(app_module.app)


ADMIN_HEADERS = {"X-NHI-Admin-Key": "test-admin-key"}


def _persist_with_action(app_module, action: str, *, suffix: str) -> str:
    from core.nhi_models import AnalysisSignals
    from agents.pipeline import NHIAnalysisPipeline
    from agents.dry_run_service import get_latest_analysis_snapshot
    from processing.analysis_persistence import persist_analysis
    from tests.test_nhi_agents import make_finding

    finding = make_finding(
        credential_active=True, file_path=f"config/{suffix}.env",
        account={"bot_id": f"change-control-api-{suffix}"},
    )
    finding.fingerprint = f"sha256:changeapi{suffix}"
    signals = AnalysisSignals(repository="acme/support")
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    persist_analysis(app_module.storage, analysis)
    nhi_id = analysis.profile.nhi_id
    snapshot = get_latest_analysis_snapshot(app_module.storage, nhi_id)
    snapshot["recommended_action"] = action
    app_module.storage.save_analysis(snapshot, repository="acme/support", fingerprint=finding.fingerprint)
    return nhi_id


def test_propose_requires_admin_key(client):
    response = client.post(
        "/nhi/whatever/changes",
        json={"requested_by": "alice", "idempotency_key": "x"},
    )
    assert response.status_code == 401


def test_propose_critical_without_acknowledgement_is_422(client):
    import api.app as app_module

    nhi_id = _persist_with_action(app_module, "TOKEN_REVOCATION", suffix="crit1")

    response = client.post(
        f"/nhi/{nhi_id}/changes",
        json={"requested_by": "alice", "idempotency_key": "api-k1"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 422


def test_full_flow_propose_approve_apply_exposes_internal_only_scope(client):
    import api.app as app_module

    nhi_id = _persist_with_action(app_module, "TOKEN_REVOCATION", suffix="crit2")

    proposed = client.post(
        f"/nhi/{nhi_id}/changes",
        json={
            "requested_by": "alice", "reason": "탈취 의심",
            "idempotency_key": "api-k2", "impact_acknowledged": True,
        },
        headers=ADMIN_HEADERS,
    ).json()
    assert proposed["tier"] == "CRITICAL"
    assert proposed["status"] == "PENDING_APPROVAL"
    change_id = proposed["change_id"]

    approved = client.post(
        f"/changes/{change_id}/approve",
        json={"approved_by": "bob"},
        headers=ADMIN_HEADERS,
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"

    applied = client.post(
        f"/changes/{change_id}/apply",
        json={"actor": "bob"},
        headers=ADMIN_HEADERS,
    )
    assert applied.status_code == 200
    body = applied.json()
    assert body["status"] == "APPLIED"
    # 내부 상태 변경과 실제 Provider 적용 여부를 API 응답에서 명확히 구분한다.
    assert body["executor_result"]["provider_call"] == "not_configured"
    assert body["executor_result"]["scope"] == "internal_only"

    detail = client.get(f"/nhi/{nhi_id}").json()
    assert detail["lifecycle_status"] == "DEACTIVATED"

    audit = client.get("/audit", headers=ADMIN_HEADERS).json()
    event_types = {item["event_type"] for item in audit["events"]}
    assert {"CHANGE_REQUEST_APPROVED", "CHANGE_REQUEST_APPLIED"} <= event_types


def test_separation_of_duties_is_enforced_as_403(client):
    import api.app as app_module

    nhi_id = _persist_with_action(app_module, "SCOPE_REDUCTION", suffix="sod1")

    proposed = client.post(
        f"/nhi/{nhi_id}/changes",
        json={"requested_by": "alice", "idempotency_key": "api-k3"},
        headers=ADMIN_HEADERS,
    ).json()

    response = client.post(
        f"/changes/{proposed['change_id']}/approve",
        json={"approved_by": "alice"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 403


def test_apply_without_approval_is_409(client):
    import api.app as app_module

    nhi_id = _persist_with_action(app_module, "SCOPE_REDUCTION", suffix="noappr1")

    proposed = client.post(
        f"/nhi/{nhi_id}/changes",
        json={"requested_by": "alice", "idempotency_key": "api-k4"},
        headers=ADMIN_HEADERS,
    ).json()

    response = client.post(
        f"/changes/{proposed['change_id']}/apply",
        json={"actor": "bob"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 409


def test_rollback_after_apply_then_expiry_check_via_list_endpoint(client):
    import api.app as app_module

    nhi_id = _persist_with_action(app_module, "TOKEN_REVOCATION", suffix="rb1")

    proposed = client.post(
        f"/nhi/{nhi_id}/changes",
        json={
            "requested_by": "alice", "idempotency_key": "api-k5",
            "impact_acknowledged": True,
        },
        headers=ADMIN_HEADERS,
    ).json()
    change_id = proposed["change_id"]
    client.post(f"/changes/{change_id}/approve", json={"approved_by": "bob"}, headers=ADMIN_HEADERS)
    client.post(f"/changes/{change_id}/apply", json={"actor": "bob"}, headers=ADMIN_HEADERS)

    rolled_back = client.post(
        f"/changes/{change_id}/rollback", json={"actor": "bob"}, headers=ADMIN_HEADERS
    )
    assert rolled_back.status_code == 200
    assert rolled_back.json()["status"] == "ROLLED_BACK"

    listed = client.get(f"/nhi/{nhi_id}/changes", headers=ADMIN_HEADERS).json()
    assert change_id in {item["change_id"] for item in listed["changes"]}


def test_get_unknown_change_is_404(client):
    response = client.get("/changes/does-not-exist")
    assert response.status_code == 404


def test_changes_route_does_not_collide_with_owner_repo_route(client):
    """`/nhi/{nhi_id}/changes` 가 `/nhi/{owner}/{repo}` 보다 먼저 등록돼
    스캔 기반 분석 조회 라우트로 잘못 매칭되지 않는지 확인한다."""
    import api.app as app_module

    nhi_id = _persist_with_action(app_module, "MONITOR", suffix="routecheck")
    response = client.get(f"/nhi/{nhi_id}/changes", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert "changes" in response.json()
