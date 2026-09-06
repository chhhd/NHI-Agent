"""`_exposure_access_scope()` 리스크 사유 문구의 provider 별 표시 회귀 테스트.

`policy/scoring.py::RiskScorer._exposure_access_scope()` 가 접근 자원을
provider 와 무관하게 "저장소"로 하드코딩하던 문제를 고쳤다 — GitHub 은
"저장소", Slack 은 "채널", 그 외는 "자원"으로 표시한다. 점수 계산 로직
(분기 조건·가산치)은 변경하지 않았다는 것도 함께 확인한다.
"""

from __future__ import annotations

from policy.rules import EvaluationContext, PolicyConfig
from policy.scoring import RiskScorer
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
# 문구 — provider 별로 정확히 갈리는지
# ---------------------------------------------------------------------------
def test_github_uses_repository_wording():
    factor = _exposure_factor(_ctx(provider="github", resources=[{"full_name": "a/b"}]))
    assert any("저장소" in reason for reason in factor.reasons)
    assert not any("채널" in reason for reason in factor.reasons)


def test_slack_uses_channel_wording():
    factor = _exposure_factor(_ctx(provider="slack", resources=[{"name": "general"}]))
    assert any("채널" in reason for reason in factor.reasons)
    assert not any("저장소" in reason for reason in factor.reasons)


def test_unknown_provider_falls_back_to_generic_resource_wording():
    factor = _exposure_factor(_ctx(provider="notion", resources=[]))
    assert any("자원" in reason for reason in factor.reasons)
    assert not any("저장소" in reason for reason in factor.reasons)
    assert not any("채널" in reason for reason in factor.reasons)


# ---------------------------------------------------------------------------
# 각 분기(0개 / 광범위 / 2개 이상 / 단일 / 비공개 / 민감)에서 문구가 정확한지
# ---------------------------------------------------------------------------
def test_slack_zero_channels_wording():
    factor = _exposure_factor(_ctx(provider="slack", resources=[]))
    assert "접근 가능한 채널 목록 미확인 — 보수적으로 평가" in factor.reasons


def test_slack_single_channel_wording():
    factor = _exposure_factor(_ctx(provider="slack", resources=[{"name": "general"}]))
    assert "단일 채널에만 접근 가능" in factor.reasons


def test_slack_broad_access_wording():
    resources = [{"name": f"ch-{i}"} for i in range(6)]  # 기본 threshold=5
    factor = _exposure_factor(_ctx(provider="slack", resources=resources))
    assert any("채널에 광범위하게 접근 가능" in reason for reason in factor.reasons)


def test_slack_sensitive_channel_wording():
    resources = [
        {"name": "general", "is_sensitive": False},
        {"name": "incidents", "is_sensitive": True},
    ]
    factor = _exposure_factor(_ctx(provider="slack", resources=resources))
    assert any("민감 채널 1개 접근 가능" in reason for reason in factor.reasons)


def test_github_broad_access_wording_is_unaffected():
    resources = [{"full_name": f"acme/repo-{i}"} for i in range(6)]
    factor = _exposure_factor(_ctx(provider="github", resources=resources))
    assert any("저장소에 광범위하게 접근 가능" in reason for reason in factor.reasons)


# ---------------------------------------------------------------------------
# 점수 계산 로직 자체는 변경되지 않았는지 (문구만 바뀜)
# ---------------------------------------------------------------------------
def test_score_values_are_identical_between_providers_for_equivalent_input():
    """동일한 개수/비공개/민감 구성이면 provider 와 무관하게 점수가 같아야 한다
    (문구만 바뀌었을 뿐 분기 조건·가산치는 그대로임을 보증).

    GitHub 은 `visibility` 로, Slack 은 `is_private` 로 비공개 여부를 명시한다
    (`tests/test_scoring_private_resource_detection.py` 참고) — 두 provider 가
    각자의 방식으로 "저장소/채널 1개는 비공개, 1개는 공개"를 표현하면
    점수가 같아야 한다는 것만 확인한다.
    """
    github_resources = [
        {"full_name": "acme/backend", "visibility": "private"},
        {"full_name": "acme/frontend", "visibility": "public"},
    ]
    slack_resources = [
        {"name": "backend-alerts", "is_private": True},
        {"name": "frontend-alerts", "is_private": False},
    ]
    github_factor = _exposure_factor(_ctx(provider="github", resources=github_resources))
    slack_factor = _exposure_factor(_ctx(provider="slack", resources=slack_resources))

    assert github_factor.score == slack_factor.score


def test_exposure_location_area_max_is_unchanged():
    from policy.scoring import AREA_MAX

    assert AREA_MAX["exposure_location"] == 20
