"""CredentialVerifier 가 provider 별 Connector 로 라우팅되는지 검증."""

from __future__ import annotations

import httpx

from core.models import DetectorType, SecretFinding, Severity
from rescan.credential_verifier import CredentialVerifier


def _finding(secret_type, provider, raw):
    return SecretFinding(
        secret_type=secret_type,
        provider=provider,
        masked_value="masked",
        fingerprint=f"sha256:{secret_type}",
        file_path="a.env",
        line_number=1,
        detector=DetectorType.REGEX,
        severity=Severity.HIGH,
        _raw_value=raw,
    )


def test_verify_skips_when_no_raw_value():
    """DB 재조회 finding(원문 없음)은 검증 대상에서 제외된다."""
    f = _finding("SLACK_BOT_TOKEN", "slack", raw="")
    verifier = CredentialVerifier()
    assert verifier.check_status(f) is None


def test_verify_skips_unverifiable_type():
    f = _finding("JWT_TOKEN", "generic", raw="eyJ.eyJ.sig")
    verifier = CredentialVerifier()
    assert verifier.check_status(f) is None


def test_verify_gitlab_routes_to_connector(monkeypatch):
    """gitlab finding 이 GitLabConnector 로 검증되는지 (네트워크 모킹)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/personal_access_tokens/self"):
            return httpx.Response(
                200, json={"active": True, "revoked": False, "scopes": ["read_api"]}
            )
        return httpx.Response(200, json={})

    import connectors

    def fake_get_connector(provider, token=None):
        from connectors.gitlab_connector import GitLabConnector

        return GitLabConnector(
            token, client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    monkeypatch.setattr("rescan.credential_verifier.get_connector", fake_get_connector)

    f = _finding("GITLAB_PAT", "gitlab", raw="glpat-realtoken1234567890")
    verifier = CredentialVerifier()
    result = verifier.verify(f)

    assert result.credential_active is True
    assert result.credential_revoked is False
    assert "read_api" in result.raw_scopes


def test_verify_caches_by_fingerprint(monkeypatch):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if request.url.path.endswith("auth.test"):
            return httpx.Response(
                200, json={"ok": True, "team": "T"}, headers={"x-oauth-scopes": "chat:write"}
            )
        return httpx.Response(200, json={"ok": True, "channels": []})

    def fake_get_connector(provider, token=None):
        from connectors.slack_connector import SlackConnector

        return SlackConnector(
            token, client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    monkeypatch.setattr("rescan.credential_verifier.get_connector", fake_get_connector)

    f1 = _finding("SLACK_BOT_TOKEN", "slack", raw="xoxb-1-2-abc")
    f2 = _finding("SLACK_BOT_TOKEN", "slack", raw="xoxb-1-2-abc")  # 동일 fingerprint

    verifier = CredentialVerifier()
    verifier.verify(f1)
    before = calls["count"]
    verifier.verify(f2)  # 캐시 히트 → 추가 호출 없음
    assert calls["count"] == before
