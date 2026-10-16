"""POST /agent-access/evaluate — NHI 생명주기 상태·Credential 폐기 확인 연계.

Gateway가 보낸 `AgentApiObservation`에는 NHI 생명주기/Credential 상태를 담을
필드 자체가 없다 — 서버가 `storage.get_nhi_lifecycle_state()`와 최신 분석의
`replay_snapshot.finding.credential_revoked`만 조회해 판정에 반영하는지,
오래되거나 없는 정보는 미확인으로 처리하는지, 기존 API 응답 스키마와 감사
로그가 하위 호환을 유지하는지를 확인한다.
"""

from __future__ import annotations

import os

import pytest

from core.config import reset_settings
from core.nhi_lifecycle_models import NHILifecycleEventType, NHILifecycleStatus


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
FINGERPRINT = "sha256:agentcredential1234567890abcdef"


def _put_profile(client, agent_id: str, nhi_id: str):
    profile = {
        "agent_id": agent_id,
        "display_name": "테스트 Agent",
        "owner": "platform-team",
        "inventory_complete": True,
        "require_sender_constraint": True,
        "allowed_binding_methods": ["DPoP"],
        "grants": [
            {
                "grant_id": f"{agent_id}-grant",
                "provider": "github",
                "nhi_id": nhi_id,
                "credential_fingerprints": [FINGERPRINT],
                "credential_inventory_complete": True,
                "permissions": ["READ"],
                "permission_inventory_complete": True,
                "resources": ["github://acme/support/*"],
                "resource_inventory_complete": True,
            }
        ],
    }
    response = client.put(f"/agent-access/profiles/{agent_id}", json=profile, headers=ADMIN_HEADERS)
    assert response.status_code == 200


def _observation(agent_id: str, nhi_id: str, **overrides):
    values = {
        "event_id": f"evt-{agent_id}-{nhi_id}",
        "claimed_agent_id": agent_id,
        "authenticated_agent_id": agent_id,
        "provider": "github",
        "nhi_id": nhi_id,
        "credential_fingerprint": FINGERPRINT,
        "action": "GET /acme/support/contents",
        "permission": "READ",
        "resource": "github://acme/support/contents",
        "resource_sensitive": False,
        "sender_constrained": True,
        "binding_method": "DPoP",
        "sender_proof_valid": True,
    }
    values.update(overrides)
    return values


def _seed_analysis_with_credential_signal(app_module, nhi_id, *, credential_revoked, analyzed_at):
    """저장소에 직접 NHI 분석 snapshot을 심어 Credential 확인 신호를 만든다."""
    fingerprint = f"sha256:analysis-{nhi_id}"
    snapshot = {
        "fingerprint": fingerprint,
        "repository": "acme/support",
        "file_path": "config/support.env",
        "line_number": 1,
        "masked_value": "xoxb-****",
        "discovery": {"nhi_id": nhi_id, "nhi_name": nhi_id, "nhi_type": "GITHUB_MACHINE_USER"},
        "context_analysis": {"environment": "production"},
        "permission_detail": {"permissions": ["READ"], "raw_scopes": []},
        "risk_score": 40,
        "risk_level": "MEDIUM",
        "recommended_action": "MONITOR",
        "blast_radius": {"connected_services": ["GitHub"]},
        "analyzed_at": analyzed_at,
        "replay_snapshot": {
            "signals": {},
            "finding": {"credential_revoked": credential_revoked},
        },
    }
    app_module.storage.bind_credential_to_nhi(fingerprint, nhi_id, confidence=0.9, evidence=[])
    app_module.storage.save_analysis(
        snapshot, repository="acme/support", fingerprint=fingerprint
    )


# ---------------------------------------------------------------------------
# 하위 호환 — 기존 응답 필드는 유지, recommended_enforcement만 추가됨
# ---------------------------------------------------------------------------
def test_response_schema_keeps_existing_fields_and_adds_recommended_enforcement(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-schema", "github-schema-nhi"
    _put_profile(client, agent_id, nhi_id)

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {
        "decision_id", "event_id", "agent_id", "outcome", "overall_severity",
        "matched_grant_id", "findings", "observation", "evaluated_at",
        "recommended_enforcement",
    }
    assert set(body["recommended_enforcement"].keys()) == {
        "action", "reason", "credential_state", "mode", "directive",
    }


# ---------------------------------------------------------------------------
# NHI 생명주기 상태 연계
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "status", [NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.DECOMMISSIONED]
)
def test_deactivated_or_decommissioned_nhi_is_denied(client, status):
    import api.app as app_module

    agent_id, nhi_id = f"agent-{status.value.lower()}", f"github-{status.value.lower()}-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    if status is not NHILifecycleStatus.REGISTERED:
        app_module.storage.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.ACTIVE,
            event_type=NHILifecycleEventType.ACTIVATED, actor="system",
        )
    if status is NHILifecycleStatus.DECOMMISSIONED:
        app_module.storage.update_nhi_lifecycle_status(
            nhi_id, NHILifecycleStatus.DEACTIVATED,
            event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
        )
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, status,
        event_type=(
            NHILifecycleEventType.DEACTIVATED
            if status is NHILifecycleStatus.DEACTIVATED
            else NHILifecycleEventType.DECOMMISSIONED
        ),
        actor="system",
    )

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    assert body["outcome"] == "DENY"
    assert "NHI_LIFECYCLE_NOT_ACTIVE" in {f["rule_id"] for f in body["findings"]}


def test_registered_but_not_active_nhi_is_review(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-registered", "github-registered-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    assert body["outcome"] == "REVIEW"
    assert "NHI_LIFECYCLE_PENDING_ACTIVATION" in {f["rule_id"] for f in body["findings"]}


def test_nhi_with_no_lifecycle_record_is_review_as_unknown(client):
    agent_id, nhi_id = "agent-unknown", "github-unknown-nhi"
    _put_profile(client, agent_id, nhi_id)
    # 생명주기 초기화를 전혀 하지 않음 — 과거 데이터/미초기화 상태를 흉내낸다.

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    assert body["outcome"] == "REVIEW"
    assert "NHI_LIFECYCLE_UNKNOWN" in {f["rule_id"] for f in body["findings"]}


def test_active_nhi_with_clean_grant_match_is_allowed(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-active-clean", "github-active-clean-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    assert body["outcome"] == "ALLOW"
    assert body["findings"] == []


# ---------------------------------------------------------------------------
# Credential 폐기 확인 연계 — 최신 분석만 신뢰, 오래된 신호는 미확인
# ---------------------------------------------------------------------------
def test_fresh_analysis_confirming_revoked_credential_is_denied_even_if_active(client):
    import api.app as app_module
    from datetime import datetime, timezone

    agent_id, nhi_id = "agent-revoked", "github-revoked-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    _seed_analysis_with_credential_signal(
        app_module, nhi_id,
        credential_revoked=True,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    assert body["outcome"] == "DENY"
    rule_ids = {f["rule_id"] for f in body["findings"]}
    assert "CREDENTIAL_KNOWN_REVOKED" in rule_ids
    assert "NHI_LIFECYCLE_NOT_ACTIVE" not in rule_ids  # ACTIVE라 여긴 안 걸림


def test_stale_revoked_signal_is_treated_as_unknown_not_denied(client):
    """분석이 오래됐으면 credential_revoked=True라도 신뢰하지 않는다(미확인 처리)."""
    import api.app as app_module
    from datetime import datetime, timedelta, timezone

    agent_id, nhi_id = "agent-stale", "github-stale-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    old_timestamp = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    _seed_analysis_with_credential_signal(
        app_module, nhi_id, credential_revoked=True, analyzed_at=old_timestamp
    )

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    rule_ids = {f["rule_id"] for f in body["findings"]}
    assert "CREDENTIAL_KNOWN_REVOKED" not in rule_ids
    assert body["outcome"] == "ALLOW"


def test_no_analysis_at_all_leaves_credential_signal_unknown(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-no-analysis", "github-no-analysis-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )
    body = response.json()

    assert body["outcome"] == "ALLOW"
    assert body["findings"] == []


# ---------------------------------------------------------------------------
# Gateway가 보낸 값은 신뢰하지 않는다 — observation에 그런 필드 자체가 없음
# ---------------------------------------------------------------------------
def test_observation_schema_has_no_self_reported_lifecycle_field(client):
    """AgentApiObservation에 생명주기/Credential 상태를 자가 신고할 필드가 없어야 한다."""
    from core.agent_access_models import AgentApiObservation

    field_names = set(AgentApiObservation.model_fields.keys())
    assert "lifecycle_status" not in field_names
    assert "credential_known_revoked" not in field_names
    assert "nhi_lifecycle_status" not in field_names


# ---------------------------------------------------------------------------
# 감사 로그
# ---------------------------------------------------------------------------
def test_audit_log_records_lifecycle_and_credential_signals(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-audit", "github-audit-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )

    audit = client.get("/audit").json()
    events = [
        e for e in audit["events"]
        if e["event_type"] == "AGENT_API_ACCESS_EVALUATED" and e["target"] == agent_id
    ]
    assert len(events) == 1
    detail = events[0]["detail"]
    assert detail["outcome"] == "DENY"
    assert detail["nhi_lifecycle_status"] == "DEACTIVATED"
    assert detail["credential_known_revoked"] is None
    assert "NHI_LIFECYCLE_NOT_ACTIVE" in detail["rule_ids"]


def test_decision_history_reflects_lifecycle_deny(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-history", "github-history-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    decision = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    history = client.get(
        "/agent-access/decisions",
        params={"agent_id": agent_id, "outcome": "DENY"},
        headers=ADMIN_HEADERS,
    ).json()

    assert history["count"] == 1
    assert history["decisions"][0]["decision_id"] == decision["decision_id"]


# ---------------------------------------------------------------------------
# recommended_enforcement — ALLOW만 ALLOW, REVIEW/DENY는 전부 BLOCK
# ---------------------------------------------------------------------------
def test_recommended_enforcement_blocks_deactivated_nhi(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-enforce-deny", "github-enforce-deny-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "DENY"
    assert body["recommended_enforcement"]["action"] == "BLOCK"
    assert "NHI_LIFECYCLE_NOT_ACTIVE" in body["recommended_enforcement"]["reason"]


def test_monitor_mode_still_blocks_deactivated_nhi(client, monkeypatch):
    """monitor 모드가 비활성 Lifecycle(DENY)을 우회하면 안 된다 — 필수 보안 차단."""
    import api.app as app_module

    monkeypatch.setenv("NHI_CONTROL_MODE", "monitor")
    reset_settings()

    agent_id, nhi_id = "agent-monitor-deny", "github-monitor-deny-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "DENY"
    assert body["recommended_enforcement"]["action"] == "BLOCK"
    assert body["recommended_enforcement"]["mode"] == "monitor"


def test_monitor_mode_still_blocks_revoked_credential(client, monkeypatch):
    """monitor 모드가 폐기 확인된 Credential(DENY)을 우회하면 안 된다."""
    import api.app as app_module

    monkeypatch.setenv("NHI_CONTROL_MODE", "monitor")
    reset_settings()

    from datetime import datetime, timezone

    agent_id, nhi_id = "agent-monitor-revoked", "github-monitor-revoked-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    _seed_analysis_with_credential_signal(
        app_module, nhi_id, credential_revoked=True,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "DENY"
    assert body["recommended_enforcement"]["action"] == "BLOCK"


def test_monitor_mode_allows_review_only_finding(client, monkeypatch):
    """monitor 모드는 REVIEW(확정 못한, blocking=False)는 통과시킨다 — 섀도 모드."""
    import api.app as app_module

    monkeypatch.setenv("NHI_CONTROL_MODE", "monitor")
    reset_settings()

    agent_id, nhi_id = "agent-monitor-review", "github-monitor-review-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    # REGISTERED 로만 두고 ACTIVE 로 전이하지 않음 → NHI_LIFECYCLE_PENDING_ACTIVATION(REVIEW)

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "REVIEW"
    assert body["recommended_enforcement"]["action"] == "ALLOW"
    assert body["recommended_enforcement"]["directive"] == "ALERT_ONLY"


def test_human_in_the_loop_mode_blocks_review_pending_approval(client, monkeypatch):
    """human_in_the_loop 모드는 승인 전까지 REVIEW 를 실행하지 않는다 — enforce 와 동일하게 차단."""
    monkeypatch.setenv("NHI_CONTROL_MODE", "human_in_the_loop")
    reset_settings()

    agent_id, nhi_id = "agent-hitl-review", "github-hitl-review-nhi"
    _put_profile(client, agent_id, nhi_id)
    import api.app as app_module

    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "REVIEW"
    assert body["recommended_enforcement"]["action"] == "BLOCK"
    assert body["recommended_enforcement"]["directive"] == "REQUIRE_APPROVAL"


def test_human_in_the_loop_mode_still_blocks_deactivated_nhi(client, monkeypatch):
    """human_in_the_loop 모드에서도 DENY(비활성 Lifecycle)는 항상 차단된다."""
    import api.app as app_module

    monkeypatch.setenv("NHI_CONTROL_MODE", "human_in_the_loop")
    reset_settings()

    agent_id, nhi_id = "agent-hitl-deny", "github-hitl-deny-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.DEACTIVATED,
        event_type=NHILifecycleEventType.DEACTIVATED, actor="system",
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "DENY"
    assert body["recommended_enforcement"]["action"] == "BLOCK"
    assert body["recommended_enforcement"]["directive"] == "BLOCK"


def test_enforce_mode_is_the_default_when_env_var_is_unset(client, monkeypatch):
    monkeypatch.delenv("NHI_CONTROL_MODE", raising=False)
    reset_settings()

    agent_id, nhi_id = "agent-default-mode", "github-default-mode-nhi"
    _put_profile(client, agent_id, nhi_id)
    import api.app as app_module

    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["recommended_enforcement"]["mode"] == "enforce"
    assert body["recommended_enforcement"]["action"] == "BLOCK"  # REVIEW도 기존처럼 차단


def test_recommended_enforcement_blocks_review_outcome_by_default():
    """REVIEW는 '기본 차단' 정책이다 — ALLOW가 아니라 BLOCK이어야 한다."""
    from backend.services.access_enforcement import EnforcementAction, recommend_enforcement
    from core.agent_access_models import AgentAccessDecision, AgentAccessOutcome, AgentApiObservation

    decision = AgentAccessDecision(
        decision_id="d", event_id="e", agent_id="a",
        outcome=AgentAccessOutcome.REVIEW,
        observation=AgentApiObservation(
            event_id="e", claimed_agent_id="a", provider="github",
            nhi_id="n", action="GET /x",
        ),
    )
    assert recommend_enforcement(decision).action is EnforcementAction.BLOCK


def test_recommended_enforcement_allows_clean_active_nhi(client):
    import api.app as app_module

    agent_id, nhi_id = "agent-enforce-allow", "github-enforce-allow-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "ALLOW"
    assert body["recommended_enforcement"]["action"] == "ALLOW"
    assert body["recommended_enforcement"]["credential_state"] == "unknown"


def test_recommended_enforcement_reports_revoked_credential_as_confirmed(client):
    import api.app as app_module
    from datetime import datetime, timezone

    agent_id, nhi_id = "agent-enforce-revoked", "github-enforce-revoked-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    _seed_analysis_with_credential_signal(
        app_module, nhi_id, credential_revoked=True,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "DENY"
    assert body["recommended_enforcement"]["action"] == "BLOCK"
    assert body["recommended_enforcement"]["credential_state"] == "revoked_confirmed"


def test_recommended_enforcement_reports_not_revoked_confirmed(client):
    import api.app as app_module
    from datetime import datetime, timezone

    agent_id, nhi_id = "agent-enforce-notrevoked", "github-enforce-notrevoked-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    _seed_analysis_with_credential_signal(
        app_module, nhi_id, credential_revoked=False,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["outcome"] == "ALLOW"
    assert body["recommended_enforcement"]["action"] == "ALLOW"
    assert body["recommended_enforcement"]["credential_state"] == "not_revoked_confirmed"


def test_recommended_enforcement_reports_unknown_for_stale_signal(client):
    import api.app as app_module
    from datetime import datetime, timedelta, timezone

    agent_id, nhi_id = "agent-enforce-stale", "github-enforce-stale-nhi"
    _put_profile(client, agent_id, nhi_id)
    app_module.storage.initialize_nhi_lifecycle(nhi_id, actor="system")
    app_module.storage.update_nhi_lifecycle_status(
        nhi_id, NHILifecycleStatus.ACTIVE,
        event_type=NHILifecycleEventType.ACTIVATED, actor="system",
    )
    old_timestamp = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    _seed_analysis_with_credential_signal(
        app_module, nhi_id, credential_revoked=True, analyzed_at=old_timestamp
    )

    body = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    ).json()

    assert body["recommended_enforcement"]["credential_state"] == "unknown"


# ---------------------------------------------------------------------------
# 평가기 내부 실패 — fail-closed(BLOCK), 500이 아니라 200 + DENY로 응답
# ---------------------------------------------------------------------------
def test_evaluator_internal_failure_fails_closed_instead_of_500(client, monkeypatch):
    import api.app as app_module

    agent_id, nhi_id = "agent-evaluator-crash", "github-evaluator-crash-nhi"
    _put_profile(client, agent_id, nhi_id)

    def _boom(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(app_module.agent_access_evaluator, "evaluate", _boom)

    response = client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )

    assert response.status_code == 200  # 500이 아니라 well-formed fail-closed 응답
    body = response.json()
    assert body["outcome"] == "DENY"
    assert body["recommended_enforcement"]["action"] == "BLOCK"
    assert any(f["rule_id"] == "EVALUATOR_UNAVAILABLE" for f in body["findings"])


def test_evaluator_internal_failure_is_audited_distinctly(client, monkeypatch):
    import api.app as app_module

    agent_id, nhi_id = "agent-evaluator-crash-2", "github-evaluator-crash-2-nhi"
    _put_profile(client, agent_id, nhi_id)

    def _boom(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(app_module.agent_access_evaluator, "evaluate", _boom)

    client.post(
        "/agent-access/evaluate", headers=ADMIN_HEADERS, json=_observation(agent_id, nhi_id)
    )

    audit = client.get("/audit").json()
    events = [
        e for e in audit["events"]
        if e["event_type"] == "AGENT_ACCESS_EVALUATOR_UNAVAILABLE" and e["target"] == agent_id
    ]
    assert len(events) == 1
    assert events[0]["detail"]["outcome"] == "DENY"
    assert events[0]["detail"]["nhi_lifecycle_status"] is None


def test_existing_401_and_404_style_errors_are_unaffected_by_fail_closed_handling(client):
    """관리자 키 누락은 기존처럼 401이어야 한다 — fail-closed 핸들러가 가로채면 안 된다."""
    response = client.post(
        "/agent-access/evaluate",
        json=_observation("agent-x", "nhi-x"),
    )
    assert response.status_code == 401
