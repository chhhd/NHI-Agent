"""RFC 9449 DPoP 기반 런타임 토큰 바인딩.

이 모듈은 연구용 FastAPI 게이트웨이에 필요한 최소 범위를 구현한다.

* ES256 DPoP proof 검증
* RFC 7638 JWK thumbprint(`cnf.jkt`) 기반 access token 바인딩
* HTTP method/URI, access token hash(`ath`), 발급 시각 검증
* proof `jti` 단일 사용을 통한 재전송 차단
* 짧은 수명의 내부 HS256 access token 발급/검증

토큰이나 private key 원문은 로그/영속 저장소에 전달하지 않는다. 다중 인스턴스
운영에서는 :class:`InMemoryReplayCache`를 Redis 같은 공유 TTL 저장소로 교체해야 한다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_MAX_JWT_LENGTH = 32_768
_MAX_JTI_LENGTH = 200
_SCOPE_RE = re.compile(r"^[A-Za-z0-9:._/-]{1,100}$")


class TokenBindingError(ValueError):
    """토큰 또는 proof 검증 실패.

    ``code``는 API 응답과 감사 이벤트에서 안정적으로 사용할 수 있는 식별자다.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 401,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.context = dict(context or {})


@dataclass(frozen=True)
class DPoPProof:
    jkt: str
    jti: str
    public_jwk: Dict[str, str]


@dataclass(frozen=True)
class RuntimePrincipal:
    agent_id: str
    scopes: tuple[str, ...]
    token_id: str
    expires_at: int
    binding_jkt: str
    proof_jti: str


class InMemoryReplayCache:
    """단일 프로세스용 DPoP proof ``jti`` TTL 캐시."""

    def __init__(self, *, max_entries: int = 100_000) -> None:
        self._entries: Dict[str, float] = {}
        self._lock = threading.Lock()
        self.max_entries = max(1, int(max_entries))

    def consume(self, key: str, *, expires_at: float, now: float) -> bool:
        """처음 본 key면 저장 후 True, 유효한 중복이면 False를 반환한다."""
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        with self._lock:
            expired = [item for item, expiry in self._entries.items() if expiry <= now]
            for item in expired:
                self._entries.pop(item, None)
            if self._entries.get(digest, 0) > now:
                return False
            if len(self._entries) >= self.max_entries:
                raise TokenBindingError(
                    "dpop_replay_cache_full",
                    "DPoP replay cache가 가득 차 fail-closed 처리했습니다.",
                    status_code=503,
                )
            self._entries[digest] = expires_at
            return True

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object, *, field: str) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise TokenBindingError("malformed_jwt", f"{field}가 올바른 base64url 값이 아닙니다.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise TokenBindingError(
            "malformed_jwt", f"{field} base64url 디코딩에 실패했습니다."
        ) from exc


def _json_segment(value: str, *, field: str) -> Dict[str, Any]:
    raw = _b64url_decode(value, field=field)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenBindingError("malformed_jwt", f"{field}가 JSON 객체가 아닙니다.") from exc
    if not isinstance(parsed, dict):
        raise TokenBindingError("malformed_jwt", f"{field}는 JSON 객체여야 합니다.")
    return parsed


def _split_jwt(value: object) -> tuple[str, str, str, Dict[str, Any], Dict[str, Any]]:
    if not isinstance(value, str) or not value or len(value) > _MAX_JWT_LENGTH:
        raise TokenBindingError("malformed_jwt", "JWT가 없거나 허용 크기를 초과했습니다.")
    parts = value.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise TokenBindingError("malformed_jwt", "JWT는 세 개의 segment로 구성되어야 합니다.")
    encoded_header, encoded_payload, signature = parts
    return (
        encoded_header,
        encoded_payload,
        signature,
        _json_segment(encoded_header, field="JWT header"),
        _json_segment(encoded_payload, field="JWT payload"),
    )


def _json_bytes(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _integer_claim(payload: Dict[str, Any], name: str) -> int:
    value = payload.get(name)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
    ):
        raise TokenBindingError("invalid_claim", f"{name} claim이 숫자가 아닙니다.")
    return int(value)


def _normalize_percent_encoding(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "%" and index + 2 < len(value):
            pair = value[index + 1 : index + 3]
            try:
                decoded = chr(int(pair, 16))
            except ValueError:
                output.append(value[index])
                index += 1
                continue
            output.append(decoded if decoded in _UNRESERVED else f"%{pair.upper()}")
            index += 3
            continue
        output.append(value[index])
        index += 1
    return "".join(output)


def normalize_htu(value: str) -> str:
    """DPoP 비교용 HTTP URI를 query/fragment 없이 정규화한다."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise TokenBindingError("invalid_htu", "HTTP target URI 형식이 올바르지 않습니다.") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise TokenBindingError("invalid_htu", "HTTP target URI에는 http(s) scheme과 host가 필요합니다.")
    if parsed.username is not None or parsed.password is not None:
        raise TokenBindingError("invalid_htu", "HTTP target URI에는 사용자 정보가 포함될 수 없습니다.")

    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    include_port = port is not None and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    )
    netloc = f"{host}:{port}" if include_port else host
    path = _normalize_percent_encoding(parsed.path or "/")
    return urlunsplit((scheme, netloc, path, "", ""))


def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """지원하는 EC P-256 public JWK의 RFC 7638 SHA-256 thumbprint."""
    public = _validate_public_jwk(jwk)
    canonical = {name: public[name] for name in ("crv", "kty", "x", "y")}
    return _b64url_encode(hashlib.sha256(_json_bytes(canonical)).digest())


def access_token_hash(access_token: str) -> str:
    try:
        encoded = access_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TokenBindingError("invalid_access_token", "access token은 ASCII 값이어야 합니다.") from exc
    return _b64url_encode(hashlib.sha256(encoded).digest())


def _validate_public_jwk(jwk: object) -> Dict[str, str]:
    if not isinstance(jwk, dict):
        raise TokenBindingError("invalid_dpop_key", "DPoP header에 public JWK가 필요합니다.")
    if _PRIVATE_JWK_MEMBERS.intersection(jwk):
        raise TokenBindingError("invalid_dpop_key", "DPoP proof에 private JWK material을 넣을 수 없습니다.")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise TokenBindingError("unsupported_dpop_alg", "현재 DPoP key는 EC P-256만 지원합니다.")
    x = jwk.get("x")
    y = jwk.get("y")
    x_bytes = _b64url_decode(x, field="JWK x")
    y_bytes = _b64url_decode(y, field="JWK y")
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise TokenBindingError("invalid_dpop_key", "P-256 JWK 좌표는 각각 32 bytes여야 합니다.")
    return {"kty": "EC", "crv": "P-256", "x": str(x), "y": str(y)}


def _verify_es256(
    *, encoded_header: str, encoded_payload: str, encoded_signature: str, jwk: Dict[str, str]
) -> None:
    signature = _b64url_decode(encoded_signature, field="JWT signature")
    if len(signature) != 64:
        raise TokenBindingError("invalid_dpop_signature", "ES256 signature 길이가 올바르지 않습니다.")
    x = int.from_bytes(_b64url_decode(jwk["x"], field="JWK x"), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"], field="JWK y"), "big")
    try:
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        der_signature = encode_dss_signature(
            int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        )
        public_key.verify(
            der_signature,
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError) as exc:
        raise TokenBindingError(
            "invalid_dpop_signature", "DPoP proof signature 검증에 실패했습니다."
        ) from exc


class RuntimeTokenService:
    """연구용 authorization/resource server의 DPoP 보안 핵심 로직."""

    def __init__(
        self,
        *,
        signing_key: str,
        issuer: str,
        audience: str,
        token_ttl_seconds: int = 300,
        proof_max_age_seconds: int = 120,
        clock_skew_seconds: int = 30,
        replay_cache: Optional[InMemoryReplayCache] = None,
    ) -> None:
        if len(signing_key.encode("utf-8")) < 32:
            raise TokenBindingError(
                "runtime_security_not_configured",
                "NHI_RUNTIME_TOKEN_SIGNING_KEY는 최소 32 bytes여야 합니다.",
                status_code=503,
            )
        if not issuer or not audience:
            raise TokenBindingError(
                "runtime_security_not_configured",
                "runtime token issuer와 audience가 필요합니다.",
                status_code=503,
            )
        self._key = signing_key.encode("utf-8")
        self.issuer = issuer
        self.audience = audience
        self.token_ttl_seconds = max(30, min(int(token_ttl_seconds), 900))
        self.proof_max_age_seconds = max(10, min(int(proof_max_age_seconds), 300))
        self.clock_skew_seconds = max(0, min(int(clock_skew_seconds), 120))
        self.replay_cache = replay_cache or InMemoryReplayCache()

    def validate_proof(
        self,
        proof_jwt: object,
        *,
        method: str,
        htu: str,
        access_token: Optional[str] = None,
        now: Optional[int] = None,
    ) -> DPoPProof:
        if proof_jwt is None or proof_jwt == "":
            raise TokenBindingError("missing_dpop_proof", "DPoP proof header가 필요합니다.")
        encoded_header, encoded_payload, signature, header, payload = _split_jwt(proof_jwt)
        if header.get("typ") != "dpop+jwt":
            raise TokenBindingError("invalid_dpop_typ", "DPoP proof typ은 dpop+jwt여야 합니다.")
        if header.get("alg") != "ES256":
            raise TokenBindingError("unsupported_dpop_alg", "현재 DPoP proof는 ES256만 허용합니다.")

        public_jwk = _validate_public_jwk(header.get("jwk"))
        _verify_es256(
            encoded_header=encoded_header,
            encoded_payload=encoded_payload,
            encoded_signature=signature,
            jwk=public_jwk,
        )

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti or len(jti) > _MAX_JTI_LENGTH:
            raise TokenBindingError("invalid_dpop_jti", "DPoP proof jti가 없거나 너무 깁니다.")
        if payload.get("htm") != method.upper():
            raise TokenBindingError("dpop_method_mismatch", "DPoP proof의 HTTP method가 다릅니다.")
        if not isinstance(payload.get("htu"), str) or normalize_htu(payload["htu"]) != normalize_htu(
            htu
        ):
            raise TokenBindingError("dpop_uri_mismatch", "DPoP proof의 HTTP target URI가 다릅니다.")

        issued_at = _integer_claim(payload, "iat")
        current = int(time.time()) if now is None else int(now)
        if issued_at < current - self.proof_max_age_seconds:
            raise TokenBindingError("stale_dpop_proof", "DPoP proof 허용 시간이 지났습니다.")
        if issued_at > current + self.clock_skew_seconds:
            raise TokenBindingError("future_dpop_proof", "DPoP proof 발급 시각이 허용 범위를 벗어났습니다.")

        if access_token is not None:
            expected_ath = access_token_hash(access_token)
            actual_ath = payload.get("ath")
            if not isinstance(actual_ath, str) or not hmac.compare_digest(actual_ath, expected_ath):
                raise TokenBindingError("dpop_token_hash_mismatch", "DPoP proof가 access token과 일치하지 않습니다.")
        elif "ath" in payload:
            raise TokenBindingError(
                "unexpected_dpop_ath", "token 발급 요청용 DPoP proof에는 ath를 넣지 않습니다."
            )

        jkt = jwk_thumbprint(public_jwk)
        replay_key = "|".join((jkt, method.upper(), normalize_htu(htu), jti))
        replay_expiry = current + self.proof_max_age_seconds + self.clock_skew_seconds
        if not self.replay_cache.consume(replay_key, expires_at=replay_expiry, now=current):
            raise TokenBindingError("dpop_proof_replay", "이미 사용된 DPoP proof입니다.")
        return DPoPProof(jkt=jkt, jti=jti, public_jwk=public_jwk)

    def issue_token(
        self,
        *,
        agent_id: str,
        scopes: Iterable[str],
        dpop_proof: object,
        method: str,
        htu: str,
        now: Optional[int] = None,
    ) -> Dict[str, Any]:
        subject = agent_id.strip()
        if not subject or len(subject) > 200:
            raise TokenBindingError("invalid_agent_id", "agent_id가 없거나 너무 깁니다.", status_code=400)
        current = int(time.time()) if now is None else int(now)
        proof = self.validate_proof(dpop_proof, method=method, htu=htu, now=current)
        normalized_scopes = tuple(
            dict.fromkeys(scope.strip() for scope in scopes if isinstance(scope, str) and scope.strip())
        )
        if len(normalized_scopes) > 50 or any(
            not _SCOPE_RE.fullmatch(scope) for scope in normalized_scopes
        ):
            raise TokenBindingError(
                "invalid_scope",
                "scope는 최대 50개이며 영문자·숫자와 : . _ / - 문자만 사용할 수 있습니다.",
                status_code=400,
            )
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": self.audience,
            "iat": current,
            "nbf": current,
            "exp": current + self.token_ttl_seconds,
            "jti": str(uuid4()),
            "scope": " ".join(normalized_scopes),
            "cnf": {"jkt": proof.jkt},
        }
        token = self._encode_access_token(payload)
        return {
            "access_token": token,
            "token_type": "DPoP",
            "expires_in": self.token_ttl_seconds,
            "scope": payload["scope"],
            "cnf": payload["cnf"],
            "proof_jti": proof.jti,
            "token_jti": payload["jti"],
        }

    def authorize(
        self,
        *,
        authorization: object,
        dpop_proof: object,
        method: str,
        htu: str,
        now: Optional[int] = None,
    ) -> RuntimePrincipal:
        if not isinstance(authorization, str) or " " not in authorization:
            raise TokenBindingError("missing_dpop_token", "Authorization: DPoP <token>이 필요합니다.")
        scheme, token = authorization.split(" ", 1)
        token = token.strip()
        if scheme.lower() != "dpop" or not token:
            raise TokenBindingError(
                "bearer_not_allowed", "이 리소스는 Bearer token을 허용하지 않고 DPoP token만 허용합니다."
            )

        current = int(time.time()) if now is None else int(now)
        payload = self._decode_access_token(token, now=current)
        token_context = {
            "agent_id": str(payload["sub"]),
            "token_jti": str(payload["jti"]),
            "binding_jkt": str((payload.get("cnf") or {}).get("jkt") or ""),
            "scopes": [
                scope
                for scope in str(payload.get("scope") or "").split(" ")
                if scope
            ],
        }
        try:
            proof = self.validate_proof(
                dpop_proof, method=method, htu=htu, access_token=token, now=current
            )
        except TokenBindingError as exc:
            exc.context.update({key: value for key, value in token_context.items() if value})
            raise
        bound_jkt = (payload.get("cnf") or {}).get("jkt")
        if not isinstance(bound_jkt, str) or not hmac.compare_digest(bound_jkt, proof.jkt):
            raise TokenBindingError(
                "sender_key_mismatch",
                "access token 발급 시 바인딩한 key와 요청 proof의 key가 다릅니다.",
                context={**token_context, "proof_jkt": proof.jkt, "proof_jti": proof.jti},
            )

        scope_value = payload.get("scope", "")
        scopes = tuple(scope for scope in scope_value.split(" ") if scope) if isinstance(scope_value, str) else ()
        return RuntimePrincipal(
            agent_id=str(payload["sub"]),
            scopes=scopes,
            token_id=str(payload["jti"]),
            expires_at=int(payload["exp"]),
            binding_jkt=bound_jkt,
            proof_jti=proof.jti,
        )

    def _encode_access_token(self, payload: Dict[str, Any]) -> str:
        header = {"alg": "HS256", "typ": "at+jwt"}
        encoded_header = _b64url_encode(_json_bytes(header))
        encoded_payload = _b64url_encode(_json_bytes(payload))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(self._key, signing_input, hashlib.sha256).digest()
        return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"

    def _decode_access_token(self, token: str, *, now: int) -> Dict[str, Any]:
        encoded_header, encoded_payload, encoded_signature, header, payload = _split_jwt(token)
        if header != {"alg": "HS256", "typ": "at+jwt"}:
            raise TokenBindingError("invalid_access_token", "access token header가 허용 정책과 다릅니다.")
        actual_signature = _b64url_decode(encoded_signature, field="access token signature")
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(self._key, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_signature, expected_signature):
            raise TokenBindingError("invalid_access_token", "access token signature가 올바르지 않습니다.")

        for claim in ("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cnf"):
            if claim not in payload:
                raise TokenBindingError("invalid_access_token", f"access token에 {claim} claim이 없습니다.")
        if payload.get("iss") != self.issuer:
            raise TokenBindingError("invalid_access_token", "access token issuer가 다릅니다.")
        audience = payload.get("aud")
        if audience != self.audience and not (
            isinstance(audience, list) and self.audience in audience
        ):
            raise TokenBindingError("invalid_access_token", "access token audience가 다릅니다.")
        if not isinstance(payload.get("sub"), str) or not payload["sub"]:
            raise TokenBindingError("invalid_access_token", "access token subject가 올바르지 않습니다.")
        if not isinstance(payload.get("jti"), str) or not payload["jti"]:
            raise TokenBindingError("invalid_access_token", "access token jti가 올바르지 않습니다.")

        issued_at = _integer_claim(payload, "iat")
        not_before = _integer_claim(payload, "nbf")
        expires_at = _integer_claim(payload, "exp")
        if issued_at > now + self.clock_skew_seconds or not_before > now + self.clock_skew_seconds:
            raise TokenBindingError("invalid_access_token", "access token이 아직 유효하지 않습니다.")
        if expires_at <= now - self.clock_skew_seconds:
            raise TokenBindingError("expired_access_token", "access token이 만료되었습니다.")
        if expires_at <= issued_at:
            raise TokenBindingError("invalid_access_token", "access token 수명 claim이 올바르지 않습니다.")

        cnf = payload.get("cnf")
        if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str) or not cnf["jkt"]:
            raise TokenBindingError("invalid_access_token", "access token에 cnf.jkt 바인딩이 없습니다.")
        return payload


__all__ = [
    "DPoPProof",
    "InMemoryReplayCache",
    "RuntimePrincipal",
    "RuntimeTokenService",
    "TokenBindingError",
    "access_token_hash",
    "jwk_thumbprint",
    "normalize_htu",
]
