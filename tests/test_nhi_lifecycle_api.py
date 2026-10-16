"""NHI 생명주기 API — `GET /nhi/{id}`의 `lifecycle_status`,
`PATCH /nhi/{id}/lifecycle`, `GET /nhi/{id}/timeline`.

실제 Credential/권한은 전혀 바꾸지 않는다. 상태 전이는 관리자 API Key로만
허용되고, 변경은 감사 이력(`GET /audit`)에 남는다. 허용되지 않은 전이는
409로 거부된다.
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


def _seed(app_module, nhi_id, *, recommended_action="MONITOR", risk_score=40):
    app_module.storage.upsert_nhi(
        nhi_id,
        {
            "nhi_id": nhi_id,
            "provider": "aws",
            "nhi_name": "ci-deploy-user",
            "risk_score": risk_score,
            "risk_level": "MEDIUM",
            "recommended_action": recommended_action,
        },
    )


# ---------------------------------------------------------------------------
# GET /nhi/{id} — 하위 호환 + lifecycle_status 추가
# ---------------------------------------------------------------------------
def test_get_nhi_includes_null_lifecycle_fields_when_not_initialized(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-1")

    response = client.get("/nhi/aws:lc-1")

    assert response.status_code == 200
    body = response.json()
    assert body["lifecycle_status"] is None
    assert body["lifecycle_updated_at"] is None
    # 기존 필드는 그대로 남아있어야 한다 (하위 호환).
    assert body["nhi_id"] == "aws:lc-1"
    assert body["risk_score"] == 40


def test_get_nhi_returns_404_for_unknown_nhi(client):
    response = client.get("/nhi/does-not-exist")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /nhi/{id}/lifecycle — 권한 검증
# ---------------------------------------------------------------------------
def test_patch_lifecycle_requires_admin_key(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-2")

    response = client.patch(
        "/nhi/aws:lc-2/lifecycle", json={"status": "ACTIVE", "actor": "security@example.com"}
    )

    assert response.status_code == 401


def test_patch_lifecycle_rejects_wrong_admin_key(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-2b")

    response = client.patch(
        "/nhi/aws:lc-2b/lifecycle",
        json={"status": "ACTIVE", "actor": "security@example.com"},
        headers={"X-NHI-Admin-Key": "wrong-key"},
    )

    assert response.status_code == 401


def test_patch_lifecycle_returns_404_for_unknown_nhi(client):
    response = client.patch(
        "/nhi/does-not-exist/lifecycle",
        json={"status": "ACTIVE", "actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /nhi/{id}/lifecycle — 정상 전이, 초기화 보정, 감사 이력
# ---------------------------------------------------------------------------
def test_patch_lifecycle_auto_initializes_and_transitions_to_active(client):
    """이 기능 도입 이전부터 있던(초기화 안 된) NHI도 PATCH로 바로 전이할 수 있다."""
    import api.app as app_module

    _seed(app_module, "aws:lc-3")

    response = client.patch(
        "/nhi/aws:lc-3/lifecycle",
        json={"status": "ACTIVE", "actor": "security@example.com", "note": "운영 사용 시작"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ACTIVE"
    assert body["changed"] is True

    detail = client.get("/nhi/aws:lc-3").json()
    assert detail["lifecycle_status"] == "ACTIVE"


def test_patch_lifecycle_records_audit_event(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-4")
    client.patch(
        "/nhi/aws:lc-4/lifecycle",
        json={"status": "ACTIVE", "actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    audit = client.get("/audit").json()
    events = [
        event
        for event in audit["events"]
        if event["event_type"] == "NHI_LIFECYCLE_STATUS_CHANGED" and event["target"] == "aws:lc-4"
    ]
    assert len(events) == 1
    assert events[0]["detail"]["from_status"] == "REGISTERED"
    assert events[0]["detail"]["to_status"] == "ACTIVE"
    assert events[0]["actor"] == "security@example.com"


def test_patch_lifecycle_same_status_is_a_noop(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-5")
    client.patch(
        "/nhi/aws:lc-5/lifecycle",
        json={"status": "ACTIVE", "actor": "system"},
        headers=ADMIN_HEADERS,
    )

    response = client.patch(
        "/nhi/aws:lc-5/lifecycle",
        json={"status": "ACTIVE", "actor": "system"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["changed"] is False


def test_patch_lifecycle_rejects_invalid_transition(client):
    """REGISTERED → DECOMMISSIONED 는 허용되지 않은 전이라 409로 거부돼야 한다."""
    import api.app as app_module

    _seed(app_module, "aws:lc-6")

    response = client.patch(
        "/nhi/aws:lc-6/lifecycle",
        json={"status": "DECOMMISSIONED", "actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 409
    detail = client.get("/nhi/aws:lc-6").json()
    assert detail["lifecycle_status"] == "REGISTERED"  # 거부됐으니 바뀌지 않아야 한다


def test_patch_lifecycle_rejects_transition_from_decommissioned(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-7")
    client.patch(
        "/nhi/aws:lc-7/lifecycle",
        json={"status": "DEACTIVATED", "actor": "system"},
        headers=ADMIN_HEADERS,
    )
    client.patch(
        "/nhi/aws:lc-7/lifecycle",
        json={"status": "DECOMMISSIONED", "actor": "system"},
        headers=ADMIN_HEADERS,
    )

    response = client.patch(
        "/nhi/aws:lc-7/lifecycle",
        json={"status": "ACTIVE", "actor": "system"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 409


def test_patch_lifecycle_decommission_without_evidence_still_works(client):
    """하위 호환 — destruction_evidence 없이도 기존처럼 DECOMMISSIONED 된다."""
    import api.app as app_module

    _seed(app_module, "aws:lc-11")
    client.patch(
        "/nhi/aws:lc-11/lifecycle",
        json={"status": "DEACTIVATED", "actor": "system"},
        headers=ADMIN_HEADERS,
    )
    response = client.patch(
        "/nhi/aws:lc-11/lifecycle",
        json={"status": "DECOMMISSIONED", "actor": "system"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "DECOMMISSIONED"
    timeline = client.get("/nhi/aws:lc-11/timeline").json()
    decommissioned_event = next(
        e for e in timeline["timeline"] if e.get("event_type") == "DECOMMISSIONED"
    )
    assert decommissioned_event["detail"]["destruction_evidence_provided"] is False


def test_patch_lifecycle_decommission_with_valid_evidence_is_recorded(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-12")
    client.patch(
        "/nhi/aws:lc-12/lifecycle",
        json={"status": "DEACTIVATED", "actor": "system"},
        headers=ADMIN_HEADERS,
    )
    response = client.patch(
        "/nhi/aws:lc-12/lifecycle",
        json={
            "status": "DECOMMISSIONED",
            "actor": "alice",
            "destruction_evidence": {
                "method": "PROVIDER_REVOKED",
                "performed_by": "alice",
                "verified_by": "bob",
                "verification_check": "AWS IAM DeleteAccessKey 호출 후 기존 키로 호출 시도",
                "verification_result": "AUTH_REJECTED_403",
            },
        },
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    timeline = client.get("/nhi/aws:lc-12/timeline").json()
    decommissioned_event = next(
        e for e in timeline["timeline"] if e.get("event_type") == "DECOMMISSIONED"
    )
    detail = decommissioned_event["detail"]
    assert detail["destruction_evidence_provided"] is True
    assert detail["destruction_method"] == "PROVIDER_REVOKED"
    assert detail["destruction_verified_by"] == "bob"
    assert detail["evidence_digest"].startswith("sha256:")


def test_patch_lifecycle_decommission_rejects_same_performer_and_verifier(client):
    """수행자==검증자인 증적은 409로 거부되고, 상태도 바뀌지 않는다."""
    import api.app as app_module

    _seed(app_module, "aws:lc-13")
    client.patch(
        "/nhi/aws:lc-13/lifecycle",
        json={"status": "DEACTIVATED", "actor": "system"},
        headers=ADMIN_HEADERS,
    )
    response = client.patch(
        "/nhi/aws:lc-13/lifecycle",
        json={
            "status": "DECOMMISSIONED",
            "actor": "alice",
            "destruction_evidence": {
                "method": "SECRET_MATERIAL_DELETED",
                "performed_by": "alice",
                "verified_by": "alice",
                "verification_check": "self-check",
                "verification_result": "MATERIAL_ABSENT",
            },
        },
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 409
    detail = client.get("/nhi/aws:lc-13").json()
    assert detail["lifecycle_status"] == "DEACTIVATED"  # 거부됐으니 바뀌지 않아야 한다


def test_patch_lifecycle_does_not_change_credential_or_risk_fields(client):
    """실제 Credential/권한/위험 점수 등은 전혀 바뀌지 않는다."""
    import api.app as app_module

    _seed(app_module, "aws:lc-8", recommended_action="TOKEN_REVOCATION", risk_score=85)
    before = client.get("/nhi/aws:lc-8").json()

    client.patch(
        "/nhi/aws:lc-8/lifecycle",
        json={"status": "DEACTIVATED", "actor": "security@example.com"},
        headers=ADMIN_HEADERS,
    )

    after = client.get("/nhi/aws:lc-8").json()
    assert before["risk_score"] == after["risk_score"]
    assert before["recommended_action"] == after["recommended_action"]
    assert after["lifecycle_status"] == "DEACTIVATED"


# ---------------------------------------------------------------------------
# GET /nhi/{id}/timeline — lifecycle 이벤트 + 분석 이력 병합
# ---------------------------------------------------------------------------
def test_timeline_returns_404_for_unknown_nhi(client):
    response = client.get("/nhi/does-not-exist/timeline")
    assert response.status_code == 404


def test_timeline_contains_only_lifecycle_events_when_no_analysis_exists(client):
    import api.app as app_module

    _seed(app_module, "aws:lc-9")
    client.patch(
        "/nhi/aws:lc-9/lifecycle",
        json={"status": "ACTIVE", "actor": "system"},
        headers=ADMIN_HEADERS,
    )

    response = client.get("/nhi/aws:lc-9/timeline")

    assert response.status_code == 200
    body = response.json()
    assert body["lifecycle_status"] == "ACTIVE"
    assert body["count"] == 2  # CREATED + ACTIVATED
    assert all(item["type"] == "lifecycle_event" for item in body["timeline"])


def test_timeline_merges_lifecycle_events_and_analysis_snapshots_by_time(client):
    import time

    import api.app as app_module
    from agents.pipeline import NHIAnalysisPipeline
    from core.nhi_models import AnalysisSignals
    from tests.test_nhi_agents import make_finding

    finding = make_finding(credential_active=True)
    analysis = NHIAnalysisPipeline().analyze_finding(
        finding, repository="acme/timeline", signals=AnalysisSignals(repository_public=True)
    )
    app_module.persist_analysis(app_module.storage, analysis)
    nhi_id = analysis.profile.nhi_id

    time.sleep(0.01)
    client.patch(
        f"/nhi/{nhi_id}/lifecycle",
        json={"status": "ACTIVE", "actor": "security@example.com", "note": "운영 사용 시작"},
        headers=ADMIN_HEADERS,
    )

    response = client.get(f"/nhi/{nhi_id}/timeline")
    body = response.json()

    types = {item["type"] for item in body["timeline"]}
    assert types == {"lifecycle_event", "analysis_snapshot"}

    # 최신순 정렬 확인 — occurred_at 이 내림차순이어야 한다.
    occurred_at_values = [item["occurred_at"] for item in body["timeline"]]
    assert occurred_at_values == sorted(occurred_at_values, reverse=True)

    # 분석 스냅샷 항목에는 risk/정책 정보가, lifecycle 항목에는 전이 정보가 있어야 한다.
    analysis_items = [item for item in body["timeline"] if item["type"] == "analysis_snapshot"]
    lifecycle_items = [item for item in body["timeline"] if item["type"] == "lifecycle_event"]
    assert analysis_items[0]["risk_score"] is not None
    assert any(item["event_type"] == "ACTIVATED" for item in lifecycle_items)
    assert any(item["event_type"] == "CREATED" for item in lifecycle_items)
