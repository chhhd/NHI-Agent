"""`credential_verified` — GitHub App Installation Token 실검증 연결 회귀 테스트.

확인 범위:
  * core/inventory_models.py   — `GitHubNHIInput.credential_verified` 필드
  * agents/inventory_adapter.py — `build_github_app_nhi_input()` / `build_credential_record()`
  * agents/github_inventory_service.py — `analyze_github_app_nhi_from_connector()`

검증 실패는 `credential_active=False` 가 아니라 `None`(상태 불명) 이 되어야 하고,
PAT 경로(`build_github_nhi_input`)와 risk 가중치(`policy/scoring.py`)는 전혀
바뀌지 않아야 한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agents.github_inventory_service import analyze_github_app_nhi_from_connector
from agents.inventory_adapter import (
    build_credential_record,
    build_github_app_nhi_input,
    build_github_nhi_input,
)
from connectors.github_app_connector import GitHubAppConnector
from core.config import GitHubAppSettings
from core.inventory_models import GitHubNHIInput, GitHubNHIType

FIXED_NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# core/inventory_models.py — 필드 기본값
# ---------------------------------------------------------------------------
def test_credential_verified_defaults_to_none():
    nhi = GitHubNHIInput(nhi_id="x", nhi_name="x", nhi_type=GitHubNHIType.GITHUB_APP)
    assert nhi.credential_verified is None


def test_credential_verified_accepts_true_and_false():
    assert (
        GitHubNHIInput(
            nhi_id="x", nhi_name="x", nhi_type=GitHubNHIType.GITHUB_APP, credential_verified=True
        ).credential_verified
        is True
    )
    assert (
        GitHubNHIInput(
            nhi_id="x", nhi_name="x", nhi_type=GitHubNHIType.GITHUB_APP, credential_verified=False
        ).credential_verified
        is False
    )


# ---------------------------------------------------------------------------
# agents/inventory_adapter.py — build_github_app_nhi_input() 이 값을 그대로 전달하는지
# ---------------------------------------------------------------------------
_INSTALLATION = {
    "installation_id": 1,
    "account_login": "acme-org",
    "account_type": "Organization",
    "repository_selection": "all",
    "permissions": {"contents": "write"},
    "suspended": False,
}


@pytest.mark.parametrize("value", [True, False, None])
def test_build_github_app_nhi_input_passes_through_credential_verified(value):
    nhi = build_github_app_nhi_input(_INSTALLATION, [], credential_verified=value)
    assert nhi.credential_verified is value


def test_build_github_app_nhi_input_defaults_credential_verified_to_none():
    nhi = build_github_app_nhi_input(_INSTALLATION, [])
    assert nhi.credential_verified is None


# ---------------------------------------------------------------------------
# agents/inventory_adapter.py — build_credential_record() 의 3분기 결합 로직
# ---------------------------------------------------------------------------
def test_credential_active_true_when_active_and_verified_true():
    nhi = build_github_app_nhi_input(_INSTALLATION, [], credential_verified=True)
    record = build_credential_record(nhi)
    assert record.credential_active is True


def test_credential_active_is_none_when_active_but_verification_failed():
    """검증 실패는 False(비활성 단정)가 아니라 None(상태 불명)이어야 한다."""
    nhi = build_github_app_nhi_input(_INSTALLATION, [], credential_verified=False)
    record = build_credential_record(nhi)
    assert record.credential_active is None
    assert record.credential_active is not False


def test_credential_active_true_when_verification_not_attempted():
    """credential_verified=None (검증 자체를 안 함) 이면 기존처럼 active 값을 그대로 쓴다."""
    nhi = build_github_app_nhi_input(_INSTALLATION, [], credential_verified=None)
    record = build_credential_record(nhi)
    assert record.credential_active is True


def test_suspended_installation_overrides_verified_true_to_false():
    """정지된 Installation 은 검증이 성공했더라도(예: 캐시된 토큰) False 가 우선한다."""
    suspended = {**_INSTALLATION, "suspended": True}
    nhi = build_github_app_nhi_input(suspended, [], credential_verified=True)
    record = build_credential_record(nhi)
    assert record.credential_active is False


def test_suspended_installation_stays_false_regardless_of_verification():
    suspended = {**_INSTALLATION, "suspended": True}
    for verified in (True, False, None):
        nhi = build_github_app_nhi_input(suspended, [], credential_verified=verified)
        assert build_credential_record(nhi).credential_active is False


def test_credential_revoked_stays_none_even_when_verification_fails():
    """검증 실패는 '폐기'와 다르다 — credential_revoked 는 여전히 None 이어야 한다."""
    nhi = build_github_app_nhi_input(_INSTALLATION, [], credential_verified=False)
    record = build_credential_record(nhi)
    assert record.credential_revoked is None


# ---------------------------------------------------------------------------
# PAT 경로는 전혀 영향받지 않는지
# ---------------------------------------------------------------------------
def test_pat_credential_active_is_unaffected():
    nhi = build_github_nhi_input({"login": "octocat", "id": 1}, [])
    assert nhi.credential_verified is None  # PAT 은 이 필드를 아예 설정하지 않는다
    record = build_credential_record(nhi)
    assert record.credential_active is True  # 이전과 동일


# ---------------------------------------------------------------------------
# risk 채점 — 검증 성공/실패가 올바른 credential_state 사유로 이어지는지
# ---------------------------------------------------------------------------
def test_risk_score_treats_verification_failure_as_unknown_not_inactive():
    from agents.pipeline import NHIAnalysisPipeline

    verified_analysis = NHIAnalysisPipeline().analyze_github_nhi(
        build_github_app_nhi_input(_INSTALLATION, [], credential_verified=True)
    )
    failed_analysis = NHIAnalysisPipeline().analyze_github_nhi(
        build_github_app_nhi_input(_INSTALLATION, [], credential_verified=False)
    )

    def _credential_state_reasons(analysis):
        factor = next(f for f in analysis.risk.factors if f.area == "credential_state")
        return factor

    verified_factor = _credential_state_reasons(verified_analysis)
    failed_factor = _credential_state_reasons(failed_analysis)

    assert "외부 검증 결과 활성 Token" in verified_factor.reasons
    assert verified_factor.score >= 8

    assert "자격 증명 상태 미확인 — 보수적으로 평가" in failed_factor.reasons
    assert "외부 검증 결과 활성 Token" not in failed_factor.reasons
    assert "비활성 자격 증명" not in failed_factor.reasons
    # 미확인(5) < 활성 확인됨(8) — 확인 실패를 활성 확인과 동일하게 취급하지 않는다.
    assert failed_factor.score < verified_factor.score


# ---------------------------------------------------------------------------
# agents/github_inventory_service.py — 실제 API 호출 성공/실패를 연결
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def rsa_private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture
def app_settings(rsa_private_key_pem: str) -> GitHubAppSettings:
    return GitHubAppSettings(app_id="123456", private_key=rsa_private_key_pem)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


_INSTALLATION_OK = {
    "id": 1,
    "account": {"login": "acme-org", "id": 7, "type": "Organization"},
    "repository_selection": "all",
    "permissions": {"contents": "write"},
    "suspended_at": None,
}

_INSTALLATION_BROKEN = {
    "id": 2,
    "account": {"login": "octocat", "id": 8, "type": "User"},
    "repository_selection": "all",
    "permissions": {"administration": "write"},
    "suspended_at": None,
}


def _make_handler():
    """installation 1 은 정상, installation 2 는 저장소 조회에서 403 을 낸다."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/app/installations":
            return httpx.Response(200, json=[_INSTALLATION_OK, _INSTALLATION_BROKEN])

        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            installation_id = int(request.url.path.split("/")[3])
            return httpx.Response(
                201,
                json={
                    "token": f"ghs-installation-token-{installation_id}",
                    "expires_at": _iso(FIXED_NOW + timedelta(hours=1)),
                    "permissions": {},
                    "repository_selection": "all",
                },
            )

        if request.method == "GET" and request.url.path == "/installation/repositories":
            token = request.headers.get("authorization", "").removeprefix("Bearer ")
            if token == "ghs-installation-token-2":
                return httpx.Response(403, json={"message": "Application suspended"})
            return httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "repositories": [
                        {"full_name": "acme/backend", "private": True, "owner": {"login": "acme-org"}}
                    ],
                },
            )

        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    return handler


def test_successful_installation_gets_credential_verified_true(
    app_settings: GitHubAppSettings,
):
    handler = _make_handler()
    with GitHubAppConnector(
        app_settings, client=httpx.Client(transport=httpx.MockTransport(handler))
    ) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    by_id = {a.profile.nhi_id: a for a, _ in analyses}
    ok = by_id["github:github-app-installation-1"]
    credential_state = next(f for f in ok.risk.factors if f.area == "credential_state")
    assert "외부 검증 결과 활성 Token" in credential_state.reasons


def test_failed_installation_gets_credential_active_none_not_crash_whole_batch(
    app_settings: GitHubAppSettings,
):
    """저장소 조회가 실패해도 전체 분석이 죽지 않고, 실패한 installation 은
    None(상태 불명)으로 기록되며 다른 installation 은 정상 분석된다."""
    handler = _make_handler()
    with GitHubAppConnector(
        app_settings, client=httpx.Client(transport=httpx.MockTransport(handler))
    ) as connector:
        analyses = analyze_github_app_nhi_from_connector(connector)

    assert len(analyses) == 2  # 둘 다 분석 결과가 생성됨 (배치 전체가 죽지 않음)
    by_id = {a.profile.nhi_id: a for a, _ in analyses}

    broken = by_id["github:github-app-installation-2"]
    broken_factor = next(f for f in broken.risk.factors if f.area == "credential_state")
    assert "자격 증명 상태 미확인 — 보수적으로 평가" in broken_factor.reasons
    assert "외부 검증 결과 활성 Token" not in broken_factor.reasons
    assert "비활성 자격 증명" not in broken_factor.reasons

    # 저장소 조회가 실패했으므로 접근 가능 저장소도 0건으로 정직하게 반영된다.
    assert broken.blast_radius.accessible_resources == 0

    ok = by_id["github:github-app-installation-1"]
    ok_factor = next(f for f in ok.risk.factors if f.area == "credential_state")
    assert "외부 검증 결과 활성 Token" in ok_factor.reasons


def test_failed_installation_does_not_leak_token_in_log(
    app_settings: GitHubAppSettings, caplog
):
    handler = _make_handler()
    with caplog.at_level("WARNING"):
        with GitHubAppConnector(
            app_settings, client=httpx.Client(transport=httpx.MockTransport(handler))
        ) as connector:
            analyze_github_app_nhi_from_connector(connector)

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "ghs-installation-token-2" not in log_text
    assert app_settings.private_key not in log_text
