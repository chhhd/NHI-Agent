"""GitHub App Installation Token 에 대한 PAT 전용 rotation 정책 억제 회귀 테스트.

`EvaluationContext.is_github_app_installation_token` 가드를 세 지점에서 확인한다:
  * policy/rules.py       — _rotation_period() (ROTATION_PERIOD 위반)
  * policy/scoring.py     — _credential_state() ("만료일 없는 활성 Token", "Rotation 이력 없음")
  * agents/recommendation_agent.py — _rotation_reason() (TOKEN_ROTATION 권고)

기존 PAT 인벤토리 경로와, 코드 스캔에서 Bot 계정으로 분류된 GITHUB_APP
(discovery_agent.py) 은 이 가드의 영향을 받지 않아야 한다는 것도 함께 확인한다.
GitHub App private key 자체의 rotation/수명 판단은 이번 단계에서 다루지 않는다.
"""

from __future__ import annotations

from typing import List

from agents.inventory_adapter import build_github_app_nhi_input, build_github_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from agents.recommendation_agent import RecommendationAgent
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    ContextInsight,
    NHIProfile,
    NHIType,
    PermissionProfile,
    RecommendedAction,
)
from policy.rules import EvaluationContext, PolicyConfig, _rotation_period
from policy.scoring import RiskScorer
from tests.test_nhi_agents import make_finding


def _ctx(
    *,
    nhi_type: NHIType,
    source: AnalysisSource,
    credential_active: bool = True,
) -> EvaluationContext:
    """rotation 관련 신호(created_at/last_rotated_at/expires_at)가 전부 없는
    상태 — 지금 GitHub App installation 경로가 실제로 만드는 값과 동일하다."""
    finding = make_finding(
        secret_type="GITHUB_APP_INSTALLATION_TOKEN",
        provider="github",
        credential_active=credential_active,
    )
    profile = NHIProfile(nhi_id="x", nhi_name="x", nhi_type=nhi_type)
    return EvaluationContext(
        finding=finding,
        profile=profile,
        context=ContextInsight(),
        permissions=PermissionProfile(),
        signals=AnalysisSignals(),
        config=PolicyConfig(),
        source=source,
    )


# ---------------------------------------------------------------------------
# EvaluationContext.is_github_app_installation_token
# ---------------------------------------------------------------------------
def test_flag_true_only_for_inventory_github_app():
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.INVENTORY)
    assert ctx.is_github_app_installation_token is True


def test_flag_false_for_pat_inventory():
    ctx = _ctx(nhi_type=NHIType.GITHUB_MACHINE_USER, source=AnalysisSource.INVENTORY)
    assert ctx.is_github_app_installation_token is False


def test_flag_false_for_github_app_found_via_code_scan():
    """discovery_agent 가 Bot 계정을 GITHUB_APP 으로 분류한 코드 스캔 결과는 영향받지 않는다."""
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.CODE_SCAN)
    assert ctx.is_github_app_installation_token is False


def test_flag_false_for_pat_code_scan():
    ctx = _ctx(nhi_type=NHIType.GITHUB_MACHINE_USER, source=AnalysisSource.CODE_SCAN)
    assert ctx.is_github_app_installation_token is False


# ---------------------------------------------------------------------------
# policy/rules.py — _rotation_period()
# ---------------------------------------------------------------------------
def test_rotation_period_violation_suppressed_for_github_app_installation_token():
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.INVENTORY)
    assert _rotation_period(ctx) is None


def test_rotation_period_violation_still_fires_for_pat_inventory():
    ctx = _ctx(nhi_type=NHIType.GITHUB_MACHINE_USER, source=AnalysisSource.INVENTORY)
    violation = _rotation_period(ctx)
    assert violation is not None
    assert violation.policy_id == "ROTATION_PERIOD"


def test_rotation_period_violation_still_fires_for_github_app_code_scan():
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.CODE_SCAN)
    violation = _rotation_period(ctx)
    assert violation is not None
    assert violation.policy_id == "ROTATION_PERIOD"


# ---------------------------------------------------------------------------
# policy/scoring.py — _credential_state() reasons
# ---------------------------------------------------------------------------
def _credential_state_reasons(ctx: EvaluationContext) -> List[str]:
    assessment = RiskScorer().score(ctx, [])
    factor = next(f for f in assessment.factors if f.area == "credential_state")
    return factor.reasons


def test_credential_state_excludes_expiry_and_rotation_reasons_for_github_app():
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.INVENTORY)
    reasons = _credential_state_reasons(ctx)
    assert "만료일 없는 활성 Token" not in reasons
    assert "Rotation 이력 없음" not in reasons


def test_credential_state_includes_expiry_and_rotation_reasons_for_pat_inventory():
    ctx = _ctx(nhi_type=NHIType.GITHUB_MACHINE_USER, source=AnalysisSource.INVENTORY)
    reasons = _credential_state_reasons(ctx)
    assert "만료일 없는 활성 Token" in reasons
    assert "Rotation 이력 없음" in reasons


def test_credential_state_includes_reasons_for_github_app_code_scan():
    """코드 스캔에서 Bot 계정으로 분류된 GITHUB_APP 은 기존 채점을 그대로 받는다."""
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.CODE_SCAN)
    reasons = _credential_state_reasons(ctx)
    assert "만료일 없는 활성 Token" in reasons
    assert "Rotation 이력 없음" in reasons


# ---------------------------------------------------------------------------
# agents/recommendation_agent.py — _rotation_reason()
# ---------------------------------------------------------------------------
def test_rotation_reason_none_for_github_app_installation_token():
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.INVENTORY)
    assert RecommendationAgent._rotation_reason(ctx) is None


def test_rotation_reason_present_for_pat_inventory():
    ctx = _ctx(nhi_type=NHIType.GITHUB_MACHINE_USER, source=AnalysisSource.INVENTORY)
    assert RecommendationAgent._rotation_reason(ctx) is not None


def test_rotation_reason_present_for_github_app_code_scan():
    ctx = _ctx(nhi_type=NHIType.GITHUB_APP, source=AnalysisSource.CODE_SCAN)
    assert RecommendationAgent._rotation_reason(ctx) is not None


# ---------------------------------------------------------------------------
# End-to-end — 기존 파이프라인 전체로 확인 (Live E2E 와 동일 경로)
# ---------------------------------------------------------------------------
def _app_nhi():
    installation = {
        "installation_id": 1,
        "account_login": "acme-org",
        "account_type": "Organization",
        "repository_selection": "all",
        "permissions": {"contents": "write"},
        "suspended": False,
    }
    return build_github_app_nhi_input(installation, [])


def _pat_nhi():
    return build_github_nhi_input({"login": "octocat", "id": 1}, [])


def test_end_to_end_github_app_analysis_has_no_rotation_period_or_token_rotation():
    analysis = NHIAnalysisPipeline().analyze_github_nhi(_app_nhi())

    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "ROTATION_PERIOD" not in violation_ids

    actions = {r.action for r in analysis.recommendations}
    assert RecommendedAction.TOKEN_ROTATION not in actions

    credential_state = next(
        f for f in analysis.risk.factors if f.area == "credential_state"
    )
    assert "만료일 없는 활성 Token" not in credential_state.reasons
    assert "Rotation 이력 없음" not in credential_state.reasons


def test_end_to_end_pat_analysis_still_flags_rotation():
    """기존 PAT 인벤토리 경로는 이번 수정으로 전혀 바뀌지 않아야 한다."""
    analysis = NHIAnalysisPipeline().analyze_github_nhi(_pat_nhi())

    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "ROTATION_PERIOD" in violation_ids

    actions = {r.action for r in analysis.recommendations}
    assert RecommendedAction.TOKEN_ROTATION in actions

    credential_state = next(
        f for f in analysis.risk.factors if f.area == "credential_state"
    )
    assert "만료일 없는 활성 Token" in credential_state.reasons
    assert "Rotation 이력 없음" in credential_state.reasons
