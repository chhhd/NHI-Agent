"""GitHubAppConnector.generate_jwt() — RS256 JWT 생성 검증.

실제 GitHub API 호출은 아직 없으므로 네트워크 모킹 없이, 순수 서명·클레임
검증만 다룬다.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from connectors.base_connector import AuthenticationError
from connectors.github_app_connector import GitHubAppConnector
from core.config import GitHubAppSettings, get_settings, reset_settings

FIXED_NOW = 1_700_000_000  # 결정적 테스트를 위한 고정 기준 시각


def _b64url_decode(segment: str) -> bytes:
    padding_needed = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding_needed)


def _rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture(scope="module")
def rsa_private_key_pem() -> str:
    return _rsa_pem()


@pytest.fixture
def app_settings(rsa_private_key_pem: str) -> GitHubAppSettings:
    return GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)


def _decode_jwt(token: str) -> tuple[dict, dict, bytes, str]:
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    signature = _b64url_decode(signature_b64)
    signing_input = f"{header_b64}.{payload_b64}"
    return header, payload, signature, signing_input


# ---------------------------------------------------------------------------
# 정상 케이스 — 구조 / 클레임 / 서명
# ---------------------------------------------------------------------------
def test_generate_jwt_header_uses_rs256(app_settings: GitHubAppSettings):
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt(now=FIXED_NOW)

    header, _, _, _ = _decode_jwt(token)
    assert header == {"alg": "RS256", "typ": "JWT"}


def test_generate_jwt_claims_include_iat_exp_iss(app_settings: GitHubAppSettings):
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt(now=FIXED_NOW)

    _, payload, _, _ = _decode_jwt(token)
    assert payload["iss"] == "123456"
    # iat 는 시계 오차 보정을 위해 60초 과거
    assert payload["iat"] == FIXED_NOW - 60
    assert payload["exp"] > payload["iat"]


def test_generate_jwt_expiry_is_within_github_ten_minute_limit(app_settings: GitHubAppSettings):
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt(now=FIXED_NOW)

    _, payload, _, _ = _decode_jwt(token)
    # GitHub 요구사항: exp 는 발급 시각 기준 10분(600초) 이내여야 한다.
    assert payload["exp"] - payload["iat"] <= 600
    # 현재 시각(FIXED_NOW) 기준으로도 10분 한도를 넘지 않아야 한다.
    assert payload["exp"] - FIXED_NOW <= 600
    assert payload["exp"] > FIXED_NOW


def test_generate_jwt_signature_is_verifiable_with_matching_public_key(
    app_settings: GitHubAppSettings,
):
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt(now=FIXED_NOW)

    _, _, signature, signing_input = _decode_jwt(token)
    private_key = serialization.load_pem_private_key(
        app_settings.private_key.encode("utf-8"), password=None
    )
    public_key = private_key.public_key()

    # 예외 없이 통과하면 서명이 유효하다는 뜻이다.
    public_key.verify(
        signature,
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_generate_jwt_signature_rejects_tampered_payload(app_settings: GitHubAppSettings):
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt(now=FIXED_NOW)

    header_b64, payload_b64, signature_b64 = token.split(".")
    tampered_payload = json.loads(_b64url_decode(payload_b64))
    tampered_payload["iss"] = "999999"
    tampered_b64 = base64.urlsafe_b64encode(
        json.dumps(tampered_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).rstrip(b"=").decode("ascii")

    private_key = serialization.load_pem_private_key(
        app_settings.private_key.encode("utf-8"), password=None
    )
    public_key = private_key.public_key()
    signature = _b64url_decode(signature_b64)

    with pytest.raises(Exception):
        public_key.verify(
            signature,
            f"{header_b64}.{tampered_b64}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


def test_generate_jwt_uses_wall_clock_when_now_not_given(
    app_settings: GitHubAppSettings, monkeypatch
):
    monkeypatch.setattr(
        "connectors.github_app_connector.time.time", lambda: float(FIXED_NOW)
    )
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt()

    _, payload, _, _ = _decode_jwt(token)
    assert payload["iat"] == FIXED_NOW - 60


# ---------------------------------------------------------------------------
# 설정 누락 / 잘못된 키 → AuthenticationError
# ---------------------------------------------------------------------------
def test_generate_jwt_raises_authentication_error_when_app_id_missing(
    rsa_private_key_pem: str,
):
    settings = GitHubAppSettings(app_id="", private_key=rsa_private_key_pem)
    connector = GitHubAppConnector(settings=settings)

    with pytest.raises(AuthenticationError) as error:
        connector.generate_jwt(now=FIXED_NOW)
    assert error.value.status_code == 401
    assert rsa_private_key_pem not in str(error.value)


def test_generate_jwt_raises_authentication_error_when_private_key_missing():
    settings = GitHubAppSettings(app_id="123456", private_key="")
    connector = GitHubAppConnector(settings=settings)

    with pytest.raises(AuthenticationError) as error:
        connector.generate_jwt(now=FIXED_NOW)
    assert error.value.status_code == 401


def test_generate_jwt_raises_authentication_error_on_malformed_private_key():
    garbage_key = "-----BEGIN RSA PRIVATE KEY-----\nnot-a-real-key\n-----END RSA PRIVATE KEY-----\n"
    settings = GitHubAppSettings(app_id="123456", private_key=garbage_key)
    connector = GitHubAppConnector(settings=settings)

    with pytest.raises(AuthenticationError) as error:
        connector.generate_jwt(now=FIXED_NOW)
    assert error.value.status_code == 401
    # 원본 키 텍스트가 예외 메시지에 노출되지 않아야 한다.
    assert "not-a-real-key" not in str(error.value)


def test_generate_jwt_rejects_non_rsa_private_key():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    settings = GitHubAppSettings(app_id="123456", private_key=ec_pem)
    connector = GitHubAppConnector(settings=settings)

    with pytest.raises(AuthenticationError) as error:
        connector.generate_jwt(now=FIXED_NOW)
    assert error.value.status_code == 401


# ---------------------------------------------------------------------------
# 노출 방지 — 토큰/개인키가 예외·repr·로그에 섞이지 않는지
# ---------------------------------------------------------------------------
def test_generate_jwt_token_and_key_never_appear_in_connector_repr(
    app_settings: GitHubAppSettings,
):
    connector = GitHubAppConnector(settings=app_settings)
    token = connector.generate_jwt(now=FIXED_NOW)

    text = repr(connector)
    assert token not in text
    assert app_settings.private_key not in text


def test_generate_jwt_error_messages_never_contain_private_key_material(
    rsa_private_key_pem: str,
):
    settings = GitHubAppSettings(app_id="", private_key=rsa_private_key_pem)
    connector = GitHubAppConnector(settings=settings)

    with pytest.raises(AuthenticationError) as error:
        connector.generate_jwt(now=FIXED_NOW)

    assert "BEGIN" not in str(error.value)
    assert "PRIVATE KEY" not in str(error.value)


# ---------------------------------------------------------------------------
# 기본 생성자 — get_settings().github_app 사용
# ---------------------------------------------------------------------------
def test_connector_defaults_to_global_settings(monkeypatch, rsa_private_key_pem: str):
    monkeypatch.setenv("GITHUB_APP_ID", "42")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", rsa_private_key_pem.replace("\n", "\\n"))
    reset_settings()
    try:
        connector = GitHubAppConnector()
        assert connector.settings is get_settings().github_app

        token = connector.generate_jwt(now=FIXED_NOW)
        _, payload, _, _ = _decode_jwt(token)
        assert payload["iss"] == "42"
    finally:
        reset_settings()
