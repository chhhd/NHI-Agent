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
