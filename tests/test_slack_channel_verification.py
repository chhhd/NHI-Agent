"""Slack 채널 조회 "성공+0개" vs "조회 실패" 구분 회귀 테스트.

이전에는 `_safe_channels()` 가 둘 다 `[]` 로 반환해 downstream 어디서도
구분할 수 없었다. 이번 수정은 다음을 확인한다:

  * `connectors/slack_connector.py` — `_safe_channels()` 가 실패 사유를 함께 반환
  * `core/models.py` — `CredentialStatus.accessible_resources_error`
  * `core/slack_inventory_models.py` — `SlackNHIInput.channels_error`
  * `agents/inventory_adapter.py` — `build_slack_nhi_input`/`build_slack_signals`
  * `policy/rules.py` — `EvaluationContext.accessible_resources_verification_attempted`/`accessible_resources_error`
  * `policy/scoring.py` — `_exposure_access_scope()` 의 "확인된 0개" vs "미확인" 분기
  * `agents/policy_evidence_agent.py` — 실패 사유가 evidence 에 그대로 노출됨

GitHub 경로는 이 신호를 전혀 채우지 않으므로 어떤 지점에서도 동작이
바뀌지 않아야 한다.
"""

from __future__ import annotations

import httpx
import pytest

from agents.inventory_adapter import build_github_nhi_input, build_slack_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from connectors.base_connector import PermissionDeniedError
from connectors.slack_connector import SlackConnector
from core.models import CredentialStatus
from policy.rules import EvaluationContext, PolicyConfig
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    ContextInsight,
    NHIProfile,
    PermissionProfile,
)
from tests.test_nhi_agents import make_finding


def _status(**overrides) -> CredentialStatus:
    defaults = dict(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["channels:history"],
        account={
            "token_kind": "bot",
            "team_id": "T1",
            "user": "support-bot",
            "user_id": "U1",
            "bot_id": "B1",
        },
        accessible_resources=[],
        accessible_resources_error=None,
    )
    defaults.update(overrides)
    return CredentialStatus(**defaults)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# connectors/slack_connector.py — _safe_channels() 이 실패 사유를 함께 반환하는지
# ---------------------------------------------------------------------------
def test_safe_channels_returns_none_error_on_success():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "channels": []})

    connector = SlackConnector("xoxb-token", client=_client(handler))
    channels, error = connector._safe_channels("xoxb-token")

    assert channels == []
    assert error is None


def test_safe_channels_returns_failure_reason_on_missing_scope():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "missing_scope"})

    connector = SlackConnector("xoxb-token", client=_client(handler))
    channels, error = connector._safe_channels("xoxb-token")

    assert channels == []
    assert error is not None
    assert "missing_scope" in error


def test_validate_credential_propagates_channel_fetch_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("auth.test"):
            return httpx.Response(
                200,
                json={"ok": True, "team_id": "T1", "user": "bot", "user_id": "U1", "bot_id": "B1"},
                headers={"x-oauth-scopes": "chat:write"},
            )
        return httpx.Response(200, json={"ok": False, "error": "missing_scope"})

    with SlackConnector("xoxb-token", client=_client(handler)) as connector:
        status = connector.validate_credential()

    assert status.accessible_resources == []
    assert status.accessible_resources_error is not None
    assert "missing_scope" in status.accessible_resources_error


def test_validate_credential_leaves_error_none_on_successful_empty_list():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("auth.test"):
            return httpx.Response(
                200,
                json={"ok": True, "team_id": "T1", "user": "bot", "user_id": "U1", "bot_id": "B1"},
                headers={"x-oauth-scopes": "chat:write"},
            )
        return httpx.Response(200, json={"ok": True, "channels": []})

    with SlackConnector("xoxb-token", client=_client(handler)) as connector:
        status = connector.validate_credential()

    assert status.accessible_resources == []
    assert status.accessible_resources_error is None


# ---------------------------------------------------------------------------
# agents/inventory_adapter.py — build_slack_nhi_input() 이 실패 사유를 전달하는지
# ---------------------------------------------------------------------------
def test_build_slack_nhi_input_carries_channels_error_through():
    status = _status(accessible_resources_error="Slack 권한 부족 (conversations.list): missing_scope")
    nhi = build_slack_nhi_input(status, [])
    assert nhi.channels_error == "Slack 권한 부족 (conversations.list): missing_scope"


def test_build_slack_nhi_input_channels_error_defaults_to_none():
    nhi = build_slack_nhi_input(_status(), [])
    assert nhi.channels_error is None


# ---------------------------------------------------------------------------
# policy/rules.py — EvaluationContext 프로퍼티
# ---------------------------------------------------------------------------
def _ctx(*, provider: str, extra: dict) -> EvaluationContext:
    return EvaluationContext(
        finding=make_finding(provider=provider),
        profile=NHIProfile(nhi_id="x", nhi_name="x", provider=provider),
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=AnalysisSignals(extra=extra),
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )


def test_verification_attempted_is_false_when_signal_absent():
    """GitHub 처럼 신호 자체가 없으면 '조회 시도 안 함' — 기존 동작 유지 대상."""
    ctx = _ctx(provider="github", extra={"repositories": []})
    assert ctx.accessible_resources_verification_attempted is False
    assert ctx.accessible_resources_error is None


def test_verification_attempted_is_true_with_error_none_on_success():
    ctx = _ctx(
        provider="slack", extra={"channels": [], "accessible_resources_error": None}
    )
    assert ctx.accessible_resources_verification_attempted is True
    assert ctx.accessible_resources_error is None


def test_verification_attempted_is_true_with_error_string_on_failure():
    ctx = _ctx(
        provider="slack",
        extra={"channels": [], "accessible_resources_error": "missing_scope"},
    )
    assert ctx.accessible_resources_verification_attempted is True
    assert ctx.accessible_resources_error == "missing_scope"


# ---------------------------------------------------------------------------
# policy/scoring.py — _exposure_access_scope() 의 세 갈래 분기
# ---------------------------------------------------------------------------
def _exposure_factor(ctx: EvaluationContext):
    from policy.scoring import RiskScorer

    assessment = RiskScorer().score(ctx, [])
    return next(f for f in assessment.factors if f.area == "exposure_location")


def test_confirmed_empty_scores_lower_than_unknown():
    confirmed = _exposure_factor(
        _ctx(provider="slack", extra={"channels": [], "accessible_resources_error": None})
    )
    failed = _exposure_factor(
        _ctx(
            provider="slack",
            extra={"channels": [], "accessible_resources_error": "missing_scope"},
        )
    )
    unknown_github = _exposure_factor(_ctx(provider="github", extra={"repositories": []}))

    assert confirmed.score == 2
    assert "확인됨" in confirmed.reasons[0]

    assert failed.score == 8
    assert "미확인" in failed.reasons[0]

    assert unknown_github.score == 8
    assert "미확인" in unknown_github.reasons[0]

    assert confirmed.score < failed.score == unknown_github.score


def test_github_zero_repositories_score_and_wording_unchanged():
    """GitHub 은 이 기능 도입 이전과 완전히 동일한 점수·문구를 받아야 한다."""
    ctx = _ctx(provider="github", extra={"repositories": []})
    factor = _exposure_factor(ctx)
    assert factor.score == 8
    assert factor.reasons == ["접근 가능한 저장소 목록 미확인 — 보수적으로 평가"]


# ---------------------------------------------------------------------------
# agents/policy_evidence_agent.py — evidence 에 실패 사유가 그대로 노출되는지
# ---------------------------------------------------------------------------
def test_evidence_exposes_actual_slack_failure_reason():
    status = _status(accessible_resources_error="Slack 권한 부족 (conversations.list): missing_scope")
    nhi = build_slack_nhi_input(status, [])
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    matching = [line for line in analysis.policy.evidence if "missing_scope" in line]
    assert matching, analysis.policy.evidence
    assert "조회 실패" in matching[0]


def test_evidence_says_confirmed_when_fetch_succeeded_with_zero_channels():
    nhi = build_slack_nhi_input(_status(), [])
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    assert any("확인됨" in line for line in analysis.policy.evidence)
    assert not any("조회 실패" in line for line in analysis.policy.evidence)


def test_evidence_github_zero_repositories_unchanged():
    nhi = build_github_nhi_input({"login": "octocat", "id": 1}, [])
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)

    assert "접근 가능 저장소 목록 미제공 — 노출 면적 점수는 보수적 기본값" in analysis.policy.evidence


# ---------------------------------------------------------------------------
# end-to-end — 실제 커넥터 호출 (MockTransport) 부터 분석까지
# ---------------------------------------------------------------------------
def test_end_to_end_missing_scope_reaches_analysis_with_reason_visible():
    from agents.slack_inventory_service import analyze_slack_nhi_from_connector

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("auth.test"):
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "team_id": "T1",
                    "user": "support-bot",
                    "user_id": "U1",
                    "bot_id": "B1",
                },
                headers={"x-oauth-scopes": "chat:write"},  # channels:read 없음
            )
        return httpx.Response(200, json={"ok": False, "error": "missing_scope"})

    with SlackConnector("xoxb-live-token", client=_client(handler)) as connector:
        analysis = analyze_slack_nhi_from_connector(connector)

    exposure_factor = next(
        f for f in analysis.risk.factors if f.area == "exposure_location"
    )
    assert exposure_factor.score == 8
    assert any("missing_scope" in line for line in analysis.policy.evidence)
    assert analysis.blast_radius.accessible_resources == 0
