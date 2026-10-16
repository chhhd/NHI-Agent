"""실행 중인 API에서 DPoP 정상 호출과 탈취 token 재사용 차단을 재현한다.

준비:
    NHI_ADMIN_API_KEY와 NHI_RUNTIME_TOKEN_SIGNING_KEY를 설정한 뒤 API를 실행한다.

실행:
    python scripts/demo_dpop_replay.py

민감한 access token과 private key는 출력하거나 파일에 저장하지 않는다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_b64(value: object) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    method: str,
    htu: str,
    token: str | None = None,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": _jwk(key)}
    payload = {
        "jti": str(uuid4()),
        "htm": method.upper(),
        "htu": htu,
        "iat": int(time.time()),
    }
    if token:
        payload["ath"] = _b64(hashlib.sha256(token.encode("ascii")).digest())
    encoded_header = _json_b64(header)
    encoded_payload = _json_b64(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"{encoded_header}.{encoded_payload}.{signature}"


def _result(label: str, response: httpx.Response) -> None:
    payload = response.json()
    print(
        json.dumps(
            {
                "step": label,
                "http_status": response.status_code,
                "decision": payload.get("decision", "TOKEN_ISSUED"),
                "authenticated_as": payload.get("authenticated_as"),
                "reason": payload.get("reason"),
            },
            ensure_ascii=False,
        )
    )


def main() -> None:
    base_url = os.getenv("NHI_RUNTIME_DEMO_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    admin_key = os.getenv("NHI_ADMIN_API_KEY", "")
    if not admin_key:
        raise SystemExit("NHI_ADMIN_API_KEY를 환경변수로 설정하세요.")

    trusted_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    issue_url = f"{base_url}/runtime/tokens/issue"
    resource_url = f"{base_url}/runtime/protected"

    with httpx.Client(timeout=10.0) as client:
        issued = client.post(
            issue_url,
            json={"agent_id": "trusted-agent-007", "scopes": ["runtime:invoke"]},
            headers={
                "X-NHI-Admin-Key": admin_key,
                "DPoP": _proof(trusted_key, method="POST", htu=issue_url),
            },
        )
        issued.raise_for_status()
        token = issued.json()["access_token"]
        binding_jkt = issued.json()["cnf"]["jkt"]
        _result("1. DPoP-bound token 발급", issued)

        # /runtime/protected는 DPoP 검증(인증)만으로 ALLOW하지 않는다 — 이어서
        # Agent Access Evaluator(인가)도 통과해야 한다. 등록되지 않은 Agent나
        # 승인되지 않은 NHI/자원은 기본 차단(BLOCK)이므로, 정상 경로(2번)를
        # 보여주려면 먼저 이 Agent를 NHI 생명주기·Agent Access 기준선에
        # 등록해야 한다.
        registration = client.post(
            f"{base_url}/nhi/inventory/saas/analyze",
            json={
                "nhi": {
                    "provider": "runtime",
                    "nhi_id": "trusted-agent-007",
                    "nhi_name": "trusted-agent-007",
                    "active": True,
                }
            },
        )
        registration.raise_for_status()
        runtime_nhi_id = registration.json()["discovery"]["nhi_id"]

        activated = client.patch(
            f"{base_url}/nhi/{runtime_nhi_id}/lifecycle",
            json={"status": "ACTIVE", "actor": "demo-script"},
            headers={"X-NHI-Admin-Key": admin_key},
        )
        activated.raise_for_status()

        profile_registered = client.put(
            f"{base_url}/agent-access/profiles/trusted-agent-007",
            json={
                "agent_id": "trusted-agent-007",
                "display_name": "Trusted Runtime Agent (demo)",
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
            headers={"X-NHI-Admin-Key": admin_key},
        )
        profile_registered.raise_for_status()
        print(
            json.dumps(
                {"step": "1b. NHI 생명주기 ACTIVE + Agent Access 기준선 등록", "http_status": 200},
                ensure_ascii=False,
            )
        )

        legitimate_proof = _proof(
            trusted_key, method="GET", htu=resource_url, token=token
        )
        allowed = client.get(
            resource_url,
            headers={
                "Authorization": f"DPoP {token}",
                "DPoP": legitimate_proof,
                "User-Agent": "trusted-agent/1.0",
            },
        )
        _result("2. 정상 Agent key", allowed)

        stolen_token = client.get(
            resource_url,
            headers={
                "Authorization": f"DPoP {token}",
                "DPoP": _proof(attacker_key, method="GET", htu=resource_url, token=token),
                "User-Agent": "curl/8.0",
            },
        )
        _result("3. 탈취 token + 공격자 key", stolen_token)

        copied_proof = client.get(
            resource_url,
            headers={
                "Authorization": f"DPoP {token}",
                "DPoP": legitimate_proof,
                "User-Agent": "curl/8.0",
            },
        )
        _result("4. 탈취 token + 복사 proof", copied_proof)


if __name__ == "__main__":
    main()
