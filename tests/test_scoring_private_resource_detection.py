"""`_exposure_access_scope()` 의 private 판정이 provider 데이터 구조를
정확히 구분하는지 확인하는 회귀 테스트.

수정 전에는 Slack 채널 dict(`{"name","is_private","is_sensitive"}`)에
`visibility` 키가 없어 `repo.get("visibility", "private")` 가 항상
기본값 `"private"` 로 떨어졌고, 그 결과 `is_private=False` 인 공개 채널까지
전부 "비공개"로 잘못 집계됐다. GitHub 는 `visibility` 기준을 그대로 쓰고,
Slack 은 `is_private` 값을 직접 읽도록 고쳤다. `is_sensitive` 판정은 애초에
provider 무관 공통 키라 이번 수정 대상이 아니다.
"""

from __future__ import annotations

from policy.rules import EvaluationContext, PolicyConfig
from policy.scoring import RiskScorer, _is_private_resource
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    ContextInsight,
    NHIProfile,
    PermissionProfile,
)
from tests.test_nhi_agents import make_finding


def _ctx(*, provider: str, resources: list) -> EvaluationContext:
    key = "repositories" if provider == "github" else "channels"
    return EvaluationContext(
        finding=make_finding(provider=provider),
        profile=NHIProfile(nhi_id="x", nhi_name="x", provider=provider),
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=AnalysisSignals(extra={key: resources}),
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )


def _exposure_factor(ctx: EvaluationContext):
    assessment = RiskScorer().score(ctx, [])
    return next(f for f in assessment.factors if f.area == "exposure_location")


# ---------------------------------------------------------------------------
# _is_private_resource() 단위 테스트
# ---------------------------------------------------------------------------
def test_slack_public_channel_is_not_private():
    assert _is_private_resource("slack", {"name": "general", "is_private": False}) is False


def test_slack_private_channel_is_private():
    assert _is_private_resource("slack", {"name": "incidents", "is_private": True}) is True


def test_slack_missing_is_private_key_defaults_to_not_private():
    """GitHub 처럼 '값이 없으면 비공개로 간주'하지 않는다 — Slack 은 명시값만 신뢰한다."""
    assert _is_private_resource("slack", {"name": "general"}) is False


def test_github_missing_visibility_key_still_defaults_to_private():
    """기존 GitHub 동작(visibility 미확인 시 비공개로 간주)은 그대로 유지된다."""
    assert _is_private_resource("github", {"full_name": "acme/repo"}) is True


def test_github_public_visibility_is_not_private():
    assert _is_private_resource("github", {"full_name": "acme/repo", "visibility": "public"}) is False


def test_github_private_visibility_is_private():
    assert _is_private_resource("github", {"full_name": "acme/repo", "visibility": "private"}) is True


# ---------------------------------------------------------------------------
# _exposure_access_scope() 전체 흐름 — 잘못된 과대 집계가 사라졌는지
# ---------------------------------------------------------------------------
def test_slack_public_channels_are_not_counted_as_private():
    resources = [
        {"name": "general", "is_private": False},
        {"name": "random", "is_private": False},
    ]
    factor = _exposure_factor(_ctx(provider="slack", resources=resources))
    assert not any("비공개 채널" in reason for reason in factor.reasons)


def test_slack_mixed_channels_count_only_actual_private_ones():
    resources = [
        {"name": "general", "is_private": False},
        {"name": "incidents", "is_private": True},
        {"name": "security-alerts", "is_private": True},
    ]
    factor = _exposure_factor(_ctx(provider="slack", resources=resources))
    assert "비공개 채널 2개 접근 가능" in factor.reasons


def test_github_private_repositories_still_counted_via_visibility():
    """기존 GitHub 동작(visibility 기준)은 이번 수정으로 바뀌지 않는다."""
    resources = [
        {"full_name": "acme/backend", "visibility": "private"},
        {"full_name": "acme/frontend", "visibility": "public"},
    ]
    factor = _exposure_factor(_ctx(provider="github", resources=resources))
    assert "비공개 저장소 1개 접근 가능" in factor.reasons


def test_github_repository_without_visibility_key_still_counts_as_private():
    """GitHub 의 '값 없으면 비공개로 간주' 보수적 기본값은 그대로다."""
    resources = [{"full_name": "acme/legacy-repo"}]
    factor = _exposure_factor(_ctx(provider="github", resources=resources))
    assert "비공개 저장소 1개 접근 가능" in factor.reasons


def test_is_sensitive_detection_unaffected_by_this_fix():
    """is_sensitive 는 원래부터 provider 공통 키였다 — 이번 수정 대상이 아니다."""
    resources = [
        {"name": "general", "is_private": False, "is_sensitive": False},
        {"name": "finance-reports", "is_private": True, "is_sensitive": True},
    ]
    factor = _exposure_factor(_ctx(provider="slack", resources=resources))
    assert "민감 채널 1개 접근 가능" in factor.reasons


# ---------------------------------------------------------------------------
# end-to-end — 실제 파이프라인을 통해 확인
# ---------------------------------------------------------------------------
def test_end_to_end_slack_public_only_channels_score_lower_than_before_fix():
    from agents.inventory_adapter import build_slack_nhi_input
    from agents.pipeline import NHIAnalysisPipeline
    from core.models import CredentialStatus

    status = CredentialStatus(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["channels:history"],
        account={
            "token_kind": "bot",
            "team_id": "T1",
            "user": "bot",
            "user_id": "U1",
            "bot_id": "B1",
        },
        accessible_resources=[
            {"name": "general", "is_private": False},
            {"name": "random", "is_private": False},
        ],
    )
    nhi = build_slack_nhi_input(status, status.accessible_resources)
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    factor = next(f for f in analysis.risk.factors if f.area == "exposure_location")
    # 수정 전에는 두 채널 모두 "비공개"로 잘못 집계되어 +3 이 가산됐다.
    assert not any("비공개" in reason for reason in factor.reasons)
    assert factor.score == 8  # 2개 채널 접근 가능(8) + 비공개(0) + 민감(0)
