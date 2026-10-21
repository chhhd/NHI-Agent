"""DPoP 런타임 엔드포인트 · 저장소 기반 replay 차단 · Gateway sender 증거 서버 검증 테스트.

TestClient 없이 엔드포인트 함수를 직접 호출한다(`api.app` 은 임시 DB 로 로드한 비공개 복사본).
"""

from __future__ import annotations

import json
from time import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from starlette.requests import Request

from core.config import reset_settings
from security.dpop import TokenBindingError
from security.replay_store import StorageReplayCache
from storage.sqlite_store import SQLiteStorage

from tests.helpers_app import load_private_app, unload_private_app
from tests.test_agent_access_control import call, make_nhi, make_profile
from tests.test_dpop_security import SIGNING_KEY, _proof

ADMIN = "bootstrap-shared-key-0123456789abcdef0123"
ISSUE_URL = "http://testserver/runtime/tokens/issue"
RESOURCE_URL = "http://testserver/runtime/protected"
ORIGINAL_URL = "https://api.example.test/repos/acme/backend"


def make_request(method: str, path: str, headers=None, ip="203.0.113.5") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
            "client": (ip, 50000),
            "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        }
    )


def body_of(response) -> dict:
    return json.loads(response.body)


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", ADMIN)
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_ISSUER", "api-test-issuer")
    monkeypatch.setenv("NHI_RUNTIME_TOKEN_AUDIENCE", "api-test-audience")
    module, name = load_private_app(tmp_path, monkeypatch)
    module.storage = SQLiteStorage(":memory:")
    reset_settings()
    yield module
    module.storage.close()
    unload_private_app(module, name)


def issue(app, key, agent_id="trusted-agent-007", admin=ADMIN, now=None):
    now = now or int(time())
    proof = _proof(key, method="POST", htu=ISSUE_URL, now=now)
    request = make_request("POST", "/runtime/tokens/issue", {"DPoP": proof})
    response = app.issue_runtime_token(
        app.RuntimeTokenIssueRequest(agent_id=agent_id),
        request,
        dpop=proof,
        x_nhi_admin_key=admin,
    )
    return response


def token_of(response) -> str:
    assert response.status_code == 200, body_of(response)
    return body_of(response)["access_token"]


def protected(app, key, token, *, now=None, jti=None, ua="trusted-agent/1.0"):
    now = now or int(time())
    proof = _proof(key, method="GET", htu=RESOURCE_URL, token=token, now=now, jti=jti)
    headers = {"Authorization": f"DPoP {token}", "DPoP": proof, "User-Agent": ua}
    request = make_request("GET", "/runtime/protected", headers)
    result = app.runtime_protected_resource(request, authorization=headers["Authorization"], dpop=proof)
    return result, headers


# ------------------------------------------------------------ 발급 · 보호 API
def test_issuing_requires_an_admin_key_and_records_who_issued(app):
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(HTTPException) as exc:
        issue(app, key, admin=None)
    assert exc.value.status_code == 401

    response = issue(app, key)
    assert response.headers["cache-control"] == "no-store"
    assert "token_jti" not in body_of(response) and "proof_jti" not in body_of(response)
    audit = [e for e in app.storage.list_audit_events() if e["event_type"] == "RUNTIME_ACCESS_ALLOW"]
    assert audit[0]["detail"]["issued_by"] == "admin"
    assert audit[0]["detail"]["auth_mode"] == "shared_admin_key"
    assert "access_token" not in str(audit)


def test_shared_key_is_the_only_admin_credential_for_token_issuance(app):
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(HTTPException) as exc:
        issue(app, key, admin="personal-looking-key")
    assert exc.value.status_code == 401
    assert issue(app, key, admin=ADMIN).status_code == 200


def test_stolen_token_with_attacker_key_is_denied_and_feeds_the_risk_engine(app):
    trusted = ec.generate_private_key(ec.SECP256R1())
    attacker = ec.generate_private_key(ec.SECP256R1())
    token = token_of(issue(app, trusted))

    allowed, _ = protected(app, trusted, token)
    assert allowed["decision"] == "ALLOW" and allowed["authenticated_as"] == "trusted-agent-007"

    denied, _ = protected(app, attacker, token, ua="curl/8.0")
    assert denied.status_code == 401
    assert body_of(denied)["reason"] == "sender_key_mismatch"
    assert denied.headers["www-authenticate"].startswith("DPoP")

    incident = next(
        o for o in app.storage.list_observations(fingerprint="nhi:runtime:trusted-agent-007", limit=20)
        if o.raw_metadata.get("reason") == "sender_key_mismatch"
    )
    signals = incident.raw_metadata["analysis_signals"]
    assert signals["token_replay_suspected"] is True and signals["request_user_agent"] == "curl/8.0"
    # IP/User-Agent 는 상관분석 증거일 뿐 — 거부 사유는 키 불일치다
    assert body_of(denied)["reason"] != "untrusted_ip"

    nhi = app.storage.get_nhi_record("runtime:trusted-agent-007")
    assert nhi is not None and nhi["risk_level"] == "CRITICAL"
    analyzed = [e for e in app.storage.list_audit_events() if e["event_type"] == "RUNTIME_REPLAY_ANALYZED"]
    assert "TOKEN_REPLAY_SUSPECTED" in analyzed[0]["detail"]["forced_rules"]


def test_copied_token_and_proof_cannot_be_replayed_even_after_a_restart(app):
    trusted = ec.generate_private_key(ec.SECP256R1())
    token = token_of(issue(app, trusted))
    now = int(time())
    first, _ = protected(app, trusted, token, now=now, jti="fixed-proof-id")
    assert first["decision"] == "ALLOW"
    # 서비스 인스턴스는 호출마다 새로 만들어진다 = 프로세스 재시작과 같은 조건
    second, _ = protected(app, trusted, token, now=now, jti="fixed-proof-id")
    assert second.status_code == 401 and body_of(second)["reason"] == "dpop_proof_replay"


# ------------------------------------------------------------ 저장소 기반 replay 캐시
def test_storage_replay_cache_is_single_use_expires_and_fails_closed_when_full():
    store = SQLiteStorage(":memory:")
    cache = StorageReplayCache(store, max_entries=2)
    assert cache.consume("a", expires_at=200.0, now=100.0) is True
    assert cache.consume("a", expires_at=200.0, now=100.0) is False
    assert cache.consume("b", expires_at=200.0, now=100.0) is True
    with pytest.raises(TokenBindingError) as exc:
        cache.consume("c", expires_at=200.0, now=100.0)
    assert exc.value.code == "dpop_replay_cache_full" and exc.value.status_code == 503
    # 만료되면 같은 key 를 다시 받을 수 있고, 자리도 비워진다
    assert cache.consume("a", expires_at=400.0, now=300.0) is True
    store.close()


def test_replay_cache_stores_only_hashes_of_proof_ids():
    store = SQLiteStorage(":memory:")
    StorageReplayCache(store).consume("super-secret-proof-jti", expires_at=2.0, now=1.0)
    rows = store._conn.execute("SELECT digest FROM dpop_replay").fetchall()
    assert rows and "super-secret-proof-jti" not in rows[0]["digest"]
    store.close()


# ------------------------------------------------------------ Gateway 가 전달한 sender 증거를 서버가 검증
def gateway_call(app, *, token, key, claimed="deploy-agent", extra=None, now=None, jti=None):
    now = now or int(time())
    proof = _proof(key, method="GET", htu=ORIGINAL_URL, token=token, now=now, jti=jti)
    payload = {
        **call(claimed_agent_id=claimed, authenticated_agent_id=None).model_dump(),
        "sender_evidence": {
            "authorization": f"DPoP {token}",
            "dpop_proof": proof,
            "http_method": "GET",
            "http_url": ORIGINAL_URL,
        },
        **(extra or {}),
    }
    return app.control_agent_call(
        app.AgentCallRequest(**payload), x_nhi_admin_key=ADMIN, x_nhi_approval_grant=None
    )


@pytest.fixture
def governed(app):
    make_nhi(app.storage)
    make_profile(app.storage, require_sender_constraint=True)
    return app


def test_valid_dpop_evidence_makes_the_server_derive_the_authenticated_agent(governed):
    key = ec.generate_private_key(ec.SECP256R1())
    token = token_of(issue(governed, key, agent_id="deploy-agent"))
    result = gateway_call(governed, token=token, key=key)
    assert result["directive"] == "PASS" and result["allowed"] is True


def test_attacker_key_with_stolen_token_is_blocked_even_if_the_caller_vouches_for_it(governed):
    trusted = ec.generate_private_key(ec.SECP256R1())
    attacker = ec.generate_private_key(ec.SECP256R1())
    token = token_of(issue(governed, trusted, agent_id="deploy-agent"))

    result = gateway_call(
        governed,
        token=token,
        key=attacker,
        # 호출자가 거짓으로 "인증됨·proof 유효"라고 주장해도 서버 검증 결과가 우선한다
        extra={"authenticated_agent_id": "deploy-agent", "sender_proof_valid": True},
    )
    ids = {rule["rule_id"] for rule in result["rules"]}
    assert result["directive"] == "BLOCK" and result["allowed"] is False
    assert {"SENDER_PROOF_INVALID", "TOKEN_REPLAY_SUSPECTED"} <= ids
    assert result["follow_up_change_ids"], "탈취 의심 차단은 교체 승인 요청을 만든다"
    # 검증에 실패한 증거라면 호출자가 적은 "인증된 Agent" 를 감사 기록에 사실처럼 남기지 않는다
    recorded = governed.storage.list_control_events(nhi_id="nhi-1", limit=5)[0]["attributes"]["observation"]
    assert recorded["authenticated_agent_id"] is None
    assert recorded["sender_proof_valid"] is False and recorded["binding_method"] == "DPoP"


def test_token_of_another_agent_cannot_be_used_to_act_as_the_claimed_agent(governed):
    key = ec.generate_private_key(ec.SECP256R1())
    token = token_of(issue(governed, key, agent_id="other-agent"))
    result = gateway_call(governed, token=token, key=key, claimed="deploy-agent")
    assert result["directive"] == "BLOCK"
    assert "CLAIMED_IDENTITY_MISMATCH" in {rule["rule_id"] for rule in result["rules"]}


def test_forwarding_the_same_evidence_twice_is_a_replay(governed):
    key = ec.generate_private_key(ec.SECP256R1())
    token = token_of(issue(governed, key, agent_id="deploy-agent"))
    now = int(time())
    first = gateway_call(governed, token=token, key=key, now=now, jti="same-proof")
    second = gateway_call(
        governed, token=token, key=key, now=now, jti="same-proof", extra={"event_id": "second-try"}
    )
    assert first["directive"] == "PASS"
    assert second["directive"] == "BLOCK"
    assert "TOKEN_REPLAY_SUSPECTED" in {rule["rule_id"] for rule in second["rules"]}


def test_requests_without_evidence_keep_the_previous_behaviour(governed):
    result = governed.control_agent_call(
        governed.AgentCallRequest(**call(authenticated_agent_id="deploy-agent").model_dump()),
        x_nhi_admin_key=ADMIN,
        x_nhi_approval_grant=None,
    )
    # 프로파일이 sender constraint 를 요구하는데 증명이 없으므로 차단
    assert "SENDER_CONSTRAINT_REQUIRED" in {rule["rule_id"] for rule in result["rules"]}
    assert result["allowed"] is False
