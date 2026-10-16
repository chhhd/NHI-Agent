"""DPoP sender-constrained token과 runtime gateway 회귀 테스트."""

from __future__ import annotations

import base64
import hashlib
import json
from time import time
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from core.config import reset_settings
from security.dpop import (
    InMemoryReplayCache,
    RuntimeTokenService,
    TokenBindingError,
    access_token_hash,
)


SIGNING_KEY = "test-runtime-signing-key-at-least-32-bytes-long"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_b64(value) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _public_jwk(private_key: ec.EllipticCurvePrivateKey):
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _proof(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    method: str,
    htu: str,
    now: int,
    token: str | None = None,
    jti: str | None = None,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": _public_jwk(private_key)}
    payload = {
        "jti": jti or str(uuid4()),
        "htm": method.upper(),
        "htu": htu,
        "iat": now,
    }
    if token is not None:
        payload["ath"] = access_token_hash(token)
    encoded_header = _json_b64(header)
    encoded_payload = _json_b64(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"{encoded_header}.{encoded_payload}.{signature}"


@pytest.fixture
def service():
    return RuntimeTokenService(
        signing_key=SIGNING_KEY,
        issuer="test-issuer",
        audience="test-api",
        token_ttl_seconds=300,
        proof_max_age_seconds=120,
        clock_skew_seconds=10,
        replay_cache=InMemoryReplayCache(),
    )


def _issue(service, key, *, now=1_700_000_000):
    htu = "https://api.example.test/runtime/tokens/issue"
    return service.issue_token(
        agent_id="trusted-agent-007",
        scopes=["runtime:invoke"],
        dpop_proof=_proof(key, method="POST", htu=htu, now=now),
        method="POST",
        htu=htu,
        now=now,
    )["access_token"]


def test_legitimate_agent_with_bound_key_is_allowed(service):
    now = 1_700_000_000
    key = ec.generate_private_key(ec.SECP256R1())
    token = _issue(service, key, now=now)
    htu = "https://api.example.test/runtime/protected"

    principal = service.authorize(
        authorization=f"DPoP {token}",
        dpop_proof=_proof(key, method="GET", htu=htu, token=token, now=now),
        method="GET",
        htu=htu,
        now=now,
    )

    assert principal.agent_id == "trusted-agent-007"
    assert principal.scopes == ("runtime:invoke",)


def test_stolen_token_with_attacker_key_is_denied(service):
    now = 1_700_000_000
    trusted_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    token = _issue(service, trusted_key, now=now)
    htu = "https://api.example.test/runtime/protected"

    with pytest.raises(TokenBindingError) as caught:
        service.authorize(
            authorization=f"DPoP {token}",
            dpop_proof=_proof(attacker_key, method="GET", htu=htu, token=token, now=now),
            method="GET",
            htu=htu,
            now=now,
        )

    assert caught.value.code == "sender_key_mismatch"
    assert caught.value.context["agent_id"] == "trusted-agent-007"


def test_copied_token_and_proof_cannot_be_replayed(service):
    now = 1_700_000_000
    key = ec.generate_private_key(ec.SECP256R1())
    token = _issue(service, key, now=now)
    htu = "https://api.example.test/runtime/protected"
    proof = _proof(key, method="GET", htu=htu, token=token, now=now)

    service.authorize(
        authorization=f"DPoP {token}", dpop_proof=proof, method="GET", htu=htu, now=now
    )
    with pytest.raises(TokenBindingError) as caught:
        service.authorize(
            authorization=f"DPoP {token}",
            dpop_proof=proof,
            method="GET",
            htu=htu,
            now=now,
        )

    assert caught.value.code == "dpop_proof_replay"


def test_bearer_scheme_and_stale_proof_are_denied(service):
    now = 1_700_000_000
    key = ec.generate_private_key(ec.SECP256R1())
    token = _issue(service, key, now=now)
    htu = "https://api.example.test/runtime/protected"

    with pytest.raises(TokenBindingError) as bearer:
        service.authorize(
            authorization=f"Bearer {token}",
            dpop_proof=None,
            method="GET",
            htu=htu,
            now=now,
        )
    assert bearer.value.code == "bearer_not_allowed"

    with pytest.raises(TokenBindingError) as stale:
        service.authorize(
            authorization=f"DPoP {token}",
            dpop_proof=_proof(
                key,
                method="GET",
                htu=htu,
                token=token,
                now=now - 121,
            ),
            method="GET",
            htu=htu,
            now=now,
        )
    assert stale.value.code == "stale_dpop_proof"


def test_runtime_api_denies_stolen_token_and_persists_analysis_signals(monkeypatch):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_ISSUER", "api-test-issuer")
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_AUDIENCE", "api-test-audience")
    reset_settings()

    from fastapi.testclient import TestClient
    import api.app as app_module

    app_module._runtime_replay_cache.clear()
    client = TestClient(app_module.app)
    trusted_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())

    issue_url = "http://testserver/runtime/tokens/issue"
    issued = client.post(
        "/runtime/tokens/issue",
        json={"agent_id": "trusted-agent-007", "scopes": ["runtime:invoke"]},
        headers={
            "X-NHI-Admin-Key": "test-admin-key",
            "DPoP": _proof(trusted_key, method="POST", htu=issue_url, now=now),
        },
    )
    assert issued.status_code == 200
    assert issued.headers["cache-control"] == "no-store"
    token = issued.json()["access_token"]
    binding_jkt = issued.json()["cnf"]["jkt"]

    # /runtime/protected가 이제 DPoP 검증(인증) 뒤에 Agent Access Evaluator
    # (인가)도 통과해야 ALLOW한다 — 등록되지 않은 Agent/NHI는 기본 차단이다.
    # 이 Agent를 "신뢰함"으로 만들려면 (1) NHI 생명주기를 ACTIVE로, (2) Agent
    # 접근 기준선에 이 DPoP 키(jkt)로의 grant를 등록해야 한다.
    saas_registration = client.post(
        "/nhi/inventory/saas/analyze",
        json={
            "nhi": {
                "provider": "runtime",
                "nhi_id": "trusted-agent-007",
                "nhi_name": "trusted-agent-007",
                "active": True,
            }
        },
    )
    assert saas_registration.status_code == 200
    runtime_nhi_id = saas_registration.json()["discovery"]["nhi_id"]

    activated = client.patch(
        f"/nhi/{runtime_nhi_id}/lifecycle",
        json={"status": "ACTIVE", "actor": "security-admin"},
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )
    assert activated.status_code == 200

    profile_registered = client.put(
        f"/agent-access/profiles/trusted-agent-007",
        json={
            "agent_id": "trusted-agent-007",
            "display_name": "Trusted Runtime Agent",
            "owner": "platform-team",
            "inventory_complete": True,
            "require_sender_constraint": True,
            "allowed_binding_methods": ["DPoP"],
            "grants": [
                {
                    "grant_id": "trusted-agent-007-runtime-grant",
                    "provider": "runtime",
                    "nhi_id": runtime_nhi_id,
                    "credential_fingerprints": [f"jkt:{binding_jkt}"],
                    "credential_inventory_complete": True,
                    "permissions": ["READ"],
                    "permission_inventory_complete": True,
                    "resources": ["/runtime/protected"],
                    "resource_inventory_complete": True,
                }
            ],
        },
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )
    assert profile_registered.status_code == 200

    resource_url = "http://testserver/runtime/protected"
    allowed = client.get(
        "/runtime/protected",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": _proof(
                trusted_key, method="GET", htu=resource_url, token=token, now=now
            ),
            "User-Agent": "trusted-agent/1.0",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "ALLOW"
    assert allowed.json()["authenticated_as"] == "trusted-agent-007"
    assert "agent_access_decision_id" in allowed.json()

    denied = client.get(
        "/runtime/protected",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": _proof(
                attacker_key, method="GET", htu=resource_url, token=token, now=now
            ),
            "User-Agent": "curl/8.0",
        },
    )
    assert denied.status_code == 401
    assert denied.json()["decision"] == "DENY"
    assert denied.json()["reason"] == "sender_key_mismatch"

    observations = app_module.storage.list_observations(
        fingerprint="nhi:runtime:trusted-agent-007", limit=20
    )
    incident = next(
        item
        for item in observations
        if item.raw_metadata.get("reason") == "sender_key_mismatch"
    )
    signals = incident.raw_metadata["analysis_signals"]
    assert signals["token_replay_suspected"] is True
    assert signals["token_binding_method"] == "DPoP"
    assert signals["request_user_agent"] == "curl/8.0"

    analyses = app_module.storage.list_analyses(limit=20)
    incident_analysis = next(
        item
        for item in analyses
        if item.get("fingerprint") == "nhi:runtime:trusted-agent-007"
    )
    assert incident_analysis["risk_level"] == "CRITICAL"
    assert "TOKEN_REPLAY_SUSPECTED" in {
        item["rule_id"] for item in incident_analysis["risk_detail"]["forced_rules"]
    }

    reset_settings()


# ---------------------------------------------------------------------------
# /runtime/protected — DPoP 통과 이후의 Agent Access 인가 계층 (엄격한 기본 차단)
# ---------------------------------------------------------------------------
def _setup_runtime_client(monkeypatch):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", "test-admin-key")
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_ISSUER", "api-test-issuer")
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_AUDIENCE", "api-test-audience")
    reset_settings()

    from fastapi.testclient import TestClient
    import api.app as app_module

    app_module._runtime_replay_cache.clear()
    return TestClient(app_module.app), app_module


def _issue_runtime_token(client, agent_id: str, key, *, now: int):
    issue_url = "http://testserver/runtime/tokens/issue"
    issued = client.post(
        "/runtime/tokens/issue",
        json={"agent_id": agent_id, "scopes": ["runtime:invoke"]},
        headers={
            "X-NHI-Admin-Key": "test-admin-key",
            "DPoP": _proof(key, method="POST", htu=issue_url, now=now),
        },
    )
    assert issued.status_code == 200
    return issued.json()["access_token"], issued.json()["cnf"]["jkt"]


def _call_protected(client, agent_id: str, key, token: str, *, now: int):
    resource_url = "http://testserver/runtime/protected"
    return client.get(
        "/runtime/protected",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": _proof(key, method="GET", htu=resource_url, token=token, now=now),
            "User-Agent": f"{agent_id}/1.0",
        },
    )


def test_valid_dpop_but_unregistered_agent_is_denied_by_access_control(monkeypatch):
    """DPoP 인증은 통과해도, Agent Access Registry에 없는 Agent는 인가 단계에서 차단된다."""
    client, app_module = _setup_runtime_client(monkeypatch)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    token, _jkt = _issue_runtime_token(client, "never-registered-agent", key, now=now)

    response = _call_protected(client, "never-registered-agent", key, token, now=now)

    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "DENY"
    assert body["reason"] == "UNREGISTERED_AGENT"
    reset_settings()


def test_deactivated_nhi_is_denied_even_with_valid_dpop_and_registered_agent(monkeypatch):
    """DPoP도 통과하고 Agent도 등록돼 있지만, 연결된 NHI가 종료 상태면 차단된다."""
    client, app_module = _setup_runtime_client(monkeypatch)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    agent_id = "deactivated-nhi-agent"
    token, jkt = _issue_runtime_token(client, agent_id, key, now=now)

    saas_registration = client.post(
        "/nhi/inventory/saas/analyze",
        json={"nhi": {"provider": "runtime", "nhi_id": agent_id, "nhi_name": agent_id, "active": True}},
    )
    nhi_id = saas_registration.json()["discovery"]["nhi_id"]
    client.patch(
        f"/nhi/{nhi_id}/lifecycle",
        json={"status": "DEACTIVATED", "actor": "security-admin"},
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )
    client.put(
        f"/agent-access/profiles/{agent_id}",
        json={
            "agent_id": agent_id,
            "display_name": "Deactivated NHI Agent",
            "owner": "platform-team",
            "inventory_complete": True,
            "require_sender_constraint": True,
            "allowed_binding_methods": ["DPoP"],
            "grants": [
                {
                    "grant_id": f"{agent_id}-grant",
                    "provider": "runtime",
                    "nhi_id": nhi_id,
                    "credential_fingerprints": [f"jkt:{jkt}"],
                    "credential_inventory_complete": True,
                    "permissions": ["READ"],
                    "permission_inventory_complete": True,
                    "resources": ["/runtime/protected"],
                    "resource_inventory_complete": True,
                }
            ],
        },
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )

    response = _call_protected(client, agent_id, key, token, now=now)

    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "DENY"
    assert body["reason"] == "NHI_LIFECYCLE_NOT_ACTIVE"
    reset_settings()


def test_evaluator_internal_failure_fails_closed_on_runtime_protected(monkeypatch):
    """평가 로직이 내부적으로 실패해도 ALLOW로 새지 않고 기본 차단된다."""
    client, app_module = _setup_runtime_client(monkeypatch)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    agent_id = "evaluator-crash-agent"
    token, _jkt = _issue_runtime_token(client, agent_id, key, now=now)

    def _boom(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(app_module.agent_access_evaluator, "evaluate", _boom)

    response = _call_protected(client, agent_id, key, token, now=now)

    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "DENY"
    assert body["reason"] == "EVALUATOR_UNAVAILABLE"

    audit = client.get(
        "/agent-access/decisions",
        params={"agent_id": agent_id},
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    ).json()
    assert audit["count"] == 1
    assert audit["decisions"][0]["outcome"] == "DENY"
    reset_settings()


def test_token_binding_failures_are_unaffected_by_access_control_layer(monkeypatch):
    """DPoP 자체 실패(stolen key 등)는 기존처럼 401/400이며, 새 인가 계층 이전에 멈춘다."""
    client, app_module = _setup_runtime_client(monkeypatch)
    trusted_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    agent_id = "token-binding-check-agent"
    token, _jkt = _issue_runtime_token(client, agent_id, trusted_key, now=now)

    resource_url = "http://testserver/runtime/protected"
    response = client.get(
        "/runtime/protected",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": _proof(
                attacker_key, method="GET", htu=resource_url, token=token, now=now
            ),
            "User-Agent": "attacker/1.0",
        },
    )

    assert response.status_code == 401
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "sender_key_mismatch"
    reset_settings()


# ---------------------------------------------------------------------------
# AccessControlMode(monitor/human_in_the_loop) — /runtime/protected 가 실제로
# 집행하는 유일한 경계이므로, 여기서 모드가 필수 보안 차단을 우회하지 못하는지
# 끝까지(DPoP → Agent Access Evaluator → 실제 HTTP 응답) 확인한다.
# ---------------------------------------------------------------------------
def test_monitor_mode_does_not_affect_dpop_failure_on_runtime_protected(monkeypatch):
    """monitor 모드여도 DPoP 자체 검증 실패는 기존과 동일하게 401 — 이 계층은 모드보다 먼저다."""
    monkeypatch.setenv("NHI_CONTROL_MODE", "monitor")
    client, app_module = _setup_runtime_client(monkeypatch)
    trusted_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    agent_id = "monitor-mode-dpop-check"
    token, _jkt = _issue_runtime_token(client, agent_id, trusted_key, now=now)

    response = _call_protected(client, agent_id, attacker_key, token, now=now)

    assert response.status_code == 401
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "sender_key_mismatch"
    reset_settings()


def test_monitor_mode_does_not_bypass_deactivated_nhi_on_runtime_protected(monkeypatch):
    """monitor 모드여도 비활성 Lifecycle(DENY)은 /runtime/protected 에서 여전히 403."""
    monkeypatch.setenv("NHI_CONTROL_MODE", "monitor")
    client, app_module = _setup_runtime_client(monkeypatch)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    agent_id = "monitor-mode-deactivated-agent"
    token, jkt = _issue_runtime_token(client, agent_id, key, now=now)

    saas_registration = client.post(
        "/nhi/inventory/saas/analyze",
        json={"nhi": {"provider": "runtime", "nhi_id": agent_id, "nhi_name": agent_id, "active": True}},
    )
    nhi_id = saas_registration.json()["discovery"]["nhi_id"]
    client.patch(
        f"/nhi/{nhi_id}/lifecycle",
        json={"status": "DEACTIVATED", "actor": "security-admin"},
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )
    client.put(
        f"/agent-access/profiles/{agent_id}",
        json={
            "agent_id": agent_id,
            "display_name": "Monitor Mode Deactivated Agent",
            "owner": "platform-team",
            "inventory_complete": True,
            "require_sender_constraint": True,
            "allowed_binding_methods": ["DPoP"],
            "grants": [
                {
                    "grant_id": f"{agent_id}-grant",
                    "provider": "runtime",
                    "nhi_id": nhi_id,
                    "credential_fingerprints": [f"jkt:{jkt}"],
                    "credential_inventory_complete": True,
                    "permissions": ["READ"],
                    "permission_inventory_complete": True,
                    "resources": ["/runtime/protected"],
                    "resource_inventory_complete": True,
                }
            ],
        },
        headers={"X-NHI-Admin-Key": "test-admin-key"},
    )

    response = _call_protected(client, agent_id, key, token, now=now)

    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "DENY"
    assert body["reason"] == "NHI_LIFECYCLE_NOT_ACTIVE"
    reset_settings()


def test_monitor_mode_fail_closed_on_evaluator_failure_is_unaffected(monkeypatch):
    """monitor 모드여도 평가기 내부 실패는 fail-closed(BLOCK) — 모드가 장애 상황을 완화하지 않는다."""
    monkeypatch.setenv("NHI_CONTROL_MODE", "monitor")
    client, app_module = _setup_runtime_client(monkeypatch)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time())
    agent_id = "monitor-mode-evaluator-crash-agent"
    token, _jkt = _issue_runtime_token(client, agent_id, key, now=now)

    def _boom(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(app_module.agent_access_evaluator, "evaluate", _boom)

    response = _call_protected(client, agent_id, key, token, now=now)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "EVALUATOR_UNAVAILABLE"
    reset_settings()
