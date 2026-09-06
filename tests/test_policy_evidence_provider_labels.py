"""정책 evidence 문구가 provider 별로 정확히 표시되는지 확인하는 회귀 테스트.

원인: `agents/policy_evidence_agent.py::_provenance()` 가 인벤토리 경로의
"입력: ... NHI 인벤토리"/"접근 ...개" 문구를 "GitHub"/"저장소"로 하드코딩하고
있어, Slack 분석 결과에도 그대로 노출됐다. 근본 원인을 추적하면
`policy/rules.py::EvaluationContext.accessible_repositories` 가
`signals.extra["repositories"]`(GitHub 전용 키) 만 읽어 Slack 의
`signals.extra["channels"]` 를 못 봐서, 접근 자원 개수 자체도 항상 0으로
계산되던 문제까지 함께 있었다.

이 테스트는 두 지점을 모두 검증한다:
  * `agents/policy_evidence_agent.py` — provider 별 정확한 라벨
  * `policy/rules.py` — provider 와 무관하게 접근 자원 개수를 정확히 셈
"""

from __future__ import annotations

from agents.inventory_adapter import build_github_nhi_input, build_slack_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from core.models import CredentialStatus
from policy.rules import EvaluationContext, PolicyConfig
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    ContextInsight,
    NHIProfile,
    NHIType,
    PermissionProfile,
)
from tests.test_nhi_agents import make_finding


def _slack_status(**overrides):
    defaults = dict(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["channels:history"],
        account={
            "token_kind": "bot",
            "team": "Acme",
            "team_id": "T1",
            "user": "support-bot",
            "user_id": "U1",
            "bot_id": "B1",
        },
        accessible_resources=[
            {"name": "general", "is_private": False},
            {"name": "incidents", "is_private": True},
        ],
    )
    defaults.update(overrides)
    return CredentialStatus(**defaults)


# ---------------------------------------------------------------------------
# agents/policy_evidence_agent.py — provider 별 evidence 문구
# ---------------------------------------------------------------------------
def test_slack_analysis_evidence_says_slack_not_github():
    nhi = build_slack_nhi_input(_slack_status(), _slack_status().accessible_resources)
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    provenance = next(
        line for line in analysis.policy.evidence if line.startswith("입력:")
    )
    assert provenance.startswith("입력: Slack NHI 인벤토리")
    assert "GitHub" not in provenance


def test_slack_analysis_evidence_says_channel_not_repository():
    nhi = build_slack_nhi_input(_slack_status(), _slack_status().accessible_resources)
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    provenance = next(
        line for line in analysis.policy.evidence if line.startswith("입력:")
    )
    assert "접근 채널 2개" in provenance
    assert "저장소" not in provenance


def test_github_analysis_evidence_still_says_github_and_repository():
    """기존 GitHub 동작은 변경되지 않아야 한다."""
    nhi = build_github_nhi_input(
        {"login": "octocat", "id": 1},
        [{"full_name": "octocat/repo", "private": True}],
    )
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)

    provenance = next(
        line for line in analysis.policy.evidence if line.startswith("입력:")
    )
    assert provenance.startswith("입력: GitHub NHI 인벤토리")
    assert "접근 저장소 1개" in provenance
    assert "Slack" not in provenance
    assert "채널" not in provenance


def test_slack_analysis_confirmed_empty_channels_uses_channel_wording():
    """채널 조회가 성공했고 실제로 0개인 경우 — '확인됨' 문구, 저장소 표현 없음.

    `policy/rules.py::EvaluationContext.accessible_resources_verification_attempted`
    도입 이후의 정확한 동작이다(빈 채널 목록 + 오류 없음 = 확인된 0개, 조회
    실패와는 다른 문구를 쓴다 — 아래 실패 케이스 테스트와 비교).
    """
    nhi = build_slack_nhi_input(_slack_status(), [])  # 조회 성공 + 채널 없음
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    assert any(
        "조회 결과 접근 가능한 채널 없음" in line for line in analysis.policy.evidence
    )
    assert not any("저장소" in line for line in analysis.policy.evidence)


def test_slack_analysis_channel_fetch_failure_uses_channel_wording_in_fallback_note():
    """채널 조회 자체가 실패한 경우 — 실패 사유가 evidence 에 노출되고 저장소 표현 없음."""
    status = _slack_status(
        accessible_resources=[],
        accessible_resources_error="Slack 권한 부족 (conversations.list): missing_scope",
    )
    nhi = build_slack_nhi_input(status, [])
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    assert any(
        "접근 가능 채널 목록 조회 실패" in line and "missing_scope" in line
        for line in analysis.policy.evidence
    )
    assert not any("저장소" in line for line in analysis.policy.evidence)


def test_github_analysis_missing_repositories_uses_repository_wording_in_fallback_note():
    nhi = build_github_nhi_input({"login": "octocat", "id": 1}, [])  # 저장소 없음
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)

    assert any(
        "접근 가능 저장소 목록 미제공" in line for line in analysis.policy.evidence
    )
    assert not any("채널" in line for line in analysis.policy.evidence)


def test_unknown_provider_falls_back_to_capitalized_name_and_generic_resource_label():
    """향후 새 provider 가 추가돼도 하드코딩된 문구가 남지 않는지 방어적으로 확인."""
    finding = make_finding(secret_type="NOTION_INTEGRATION_TOKEN", provider="notion")
    profile = NHIProfile(
        nhi_id="x", nhi_name="x", nhi_type=NHIType.NOTION_INTEGRATION, provider="notion"
    )
    ctx = EvaluationContext(
        finding=finding,
        profile=profile,
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=AnalysisSignals(),
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )

    from agents.policy_evidence_agent import PolicyEvidenceAgent

    evidence = PolicyEvidenceAgent._provenance(ctx)
    provenance = next(line for line in evidence if line.startswith("입력:"))
    assert provenance.startswith("입력: Notion NHI 인벤토리")
    assert "접근 자원 0개" in provenance


# ---------------------------------------------------------------------------
# policy/rules.py — EvaluationContext.accessible_repositories 의 근본 원인 수정
# ---------------------------------------------------------------------------
def test_accessible_repositories_reads_slack_channels_key():
    signals = AnalysisSignals(extra={"channels": [{"name": "general"}, {"name": "random"}]})
    ctx = EvaluationContext(
        finding=make_finding(),
        profile=NHIProfile(nhi_id="x", nhi_name="x", provider="slack"),
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=signals,
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )
    assert len(ctx.accessible_repositories) == 2


def test_accessible_repositories_still_reads_github_repositories_key():
    signals = AnalysisSignals(extra={"repositories": [{"full_name": "acme/backend"}]})
    ctx = EvaluationContext(
        finding=make_finding(),
        profile=NHIProfile(nhi_id="x", nhi_name="x", provider="github"),
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=signals,
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )
    assert len(ctx.accessible_repositories) == 1


def test_accessible_repositories_prefers_repositories_key_when_both_present():
    """GitHub 키가 있으면 그걸 우선한다 — 기존 동작 순서를 바꾸지 않는다."""
    signals = AnalysisSignals(
        extra={
            "repositories": [{"full_name": "acme/backend"}],
            "channels": [{"name": "general"}, {"name": "random"}],
        }
    )
    ctx = EvaluationContext(
        finding=make_finding(),
        profile=NHIProfile(nhi_id="x", nhi_name="x", provider="github"),
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=signals,
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )
    assert len(ctx.accessible_repositories) == 1


def test_slack_exposure_score_reflects_actual_channel_count_not_always_unknown():
    """수정 전에는 accessible_repositories 가 항상 빈 목록이라 노출 면적
    점수가 항상 '미확인' 고정값이었다 — 이제는 실제 채널 수를 반영한다."""
    status = _slack_status(
        accessible_resources=[
            {"name": "general", "is_private": False},
            {"name": "incidents", "is_private": True},
        ]
    )
    nhi = build_slack_nhi_input(status, status.accessible_resources)
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    exposure_factor = next(
        f for f in analysis.risk.factors if f.area == "exposure_location"
    )
    assert "접근 가능한 저장소 목록 미확인 — 보수적으로 평가" not in exposure_factor.reasons
    assert any("2개" in reason for reason in exposure_factor.reasons)
