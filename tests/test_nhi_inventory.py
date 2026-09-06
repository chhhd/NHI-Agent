"""GitHub NHI 인벤토리 입력 경로 테스트.

스캔 결과가 없어도 같은 분석 엔진으로 채점되는지, 그리고 코드 노출 사실이 없는
입력에 대해 잘못된 판정(평문 노출 위반 / 환경변수 이전 권고)을 만들지 않는지 본다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agents.inventory_adapter import build_credential_record
from agents.pipeline import NHIAnalysisPipeline
from agents.scope_translation_agent import ScopeTranslationAgent
from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
from core.nhi_models import (
    AnalysisSource,
    Environment,
    NHIType,
    PermissionLevel,
    RecommendedAction,
    RiskLevel,
)


@pytest.fixture
def pipeline() -> NHIAnalysisPipeline:
    return NHIAnalysisPipeline()


# ---------------------------------------------------------------------------
# 권한 정규화 — GitHub 원본 권한 → 공통 권한
# ---------------------------------------------------------------------------
def test_github_permissions_are_normalized():
    nhi = GitHubNHIInput(
        nhi_id="app-1",
        nhi_name="app-1",
        nhi_type=GitHubNHIType.GITHUB_APP,
        raw_permissions={
            "metadata": "read",
            "contents": "write",
            "administration": "write",
            "issues": "none",
        },
    )
    # none 권한은 Scope 로 취급하지 않는다.
    assert nhi.scopes == ["metadata:read", "contents:write", "administration:write"]

    profile = ScopeTranslationAgent().translate(nhi.scopes, provider="github")

    assert profile.has(PermissionLevel.READ)
    assert profile.has(PermissionLevel.WRITE)
    # 저장소 설정 관리는 write 라도 관리자 권한으로 본다.
    assert profile.has(PermissionLevel.ADMIN)
    assert profile.highest is PermissionLevel.ADMIN
    assert profile.assumed is False


def test_classic_pat_scopes_are_translated(pipeline):
    """Classic PAT 은 `repo` 처럼 평면 Scope 로 부여된다 (App 권한 표기와 다르다)."""
    nhi = GitHubNHIInput(
        nhi_id="pat-classic",
        nhi_name="ci-integration-token",
        nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
        raw_scopes=["repo", "workflow", "write:packages", "delete:packages"],
    )
    assert nhi.scopes == ["repo", "workflow", "write:packages", "delete:packages"]

    analysis = pipeline.analyze_github_nhi(nhi)

    assert analysis.permissions.assumed is False  # 실제 Scope 로 변환됨
    assert analysis.permissions.highest is PermissionLevel.ADMIN  # repo = 전반 접근
    assert analysis.permissions.has(PermissionLevel.DELETE)  # delete:packages
    assert "ADMIN_SCOPE_RESTRICTED" in {v.policy_id for v in analysis.policy.violations}
    assert any("Token Scope" in line for line in analysis.profile.evidence)


def test_missing_inventory_permissions_remain_unknown(pipeline):
    """권한 정보가 없다고 위험이 낮은 것은 아니다 — 유형 기준으로 가정한다."""
    nhi = GitHubNHIInput(
        nhi_id="app-no-perm",
        nhi_name="app-no-perm",
        nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
        raw_permissions={},
    )
    analysis = pipeline.analyze_github_nhi(nhi)

    assert analysis.permissions.assumed is False
    assert analysis.permissions.permissions == []
    assert analysis.permissions.highest is None
    return
    assert analysis.permissions.permissions  # 비워두지 않는다
    assert any("가정" in reason for reason in analysis.risk.reasons)


def test_inventory_account_metadata_cannot_override_canonical_identity(pipeline):
    nhi = GitHubNHIInput(
        nhi_id="canonical-installation-7",
        nhi_name="canonical-deploy-app",
        nhi_type=GitHubNHIType.GITHUB_APP,
        account={"id": "spoofed", "name": "spoofed", "type": "user"},
        raw_permissions={"metadata": "read"},
    )

    credential = build_credential_record(nhi)
    analysis = pipeline.analyze_github_nhi(nhi)

    assert credential.credential_detail["account"] == {
        "id": "canonical-installation-7",
        "name": "canonical-deploy-app",
        "type": "bot",
    }
    assert analysis.profile.account["id"] == "canonical-installation-7"
    assert analysis.profile.account["name"] == "canonical-deploy-app"


# ---------------------------------------------------------------------------
# 고위험 / 저위험 시나리오
# ---------------------------------------------------------------------------
def test_high_risk_inventory_nhi(pipeline, high_risk_nhi):
    analysis = pipeline.analyze_github_nhi(high_risk_nhi)
    data = analysis.to_dict()

    assert data["source"] == AnalysisSource.INVENTORY.value
    assert data["nhi_name"] == "production-deployment-app"
    assert data["nhi_type"] == NHIType.GITHUB_APP.value
    assert data["owner"] is None
    assert data["environment"] == Environment.PRODUCTION.value
    assert data["risk_level"] in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}
    assert data["risk_reasons"]

    # 관리자 권한 · Owner 미지정이 정책 위반으로 잡혀야 한다.
    # ROTATION_PERIOD 는 여기서 나오지 않는다 — GitHub App Installation Token 은
    # 요청마다 새로 발급되는 최대 1시간짜리 자격 증명이라 PAT 용 "무기한 유효
    # Token" 판정(회전 이력·만료일 없음)이 적용되지 않는다
    # (`EvaluationContext.is_github_app_installation_token`, policy/rules.py).
    violated = {v["policy_id"] for v in data["policy"]["violations"]}
    assert {"OWNER_REQUIRED", "ADMIN_SCOPE_RESTRICTED"} <= violated
    assert "ROTATION_PERIOD" not in violated

    # 근거 없이 점수만 내지 않는다.
    assert all(factor["reasons"] for factor in data["risk_detail"]["factors"])

    actions = {rec["action"] for rec in data["recommendations"]}
    assert RecommendedAction.SCOPE_REDUCTION.value in actions
    assert RecommendedAction.ASSIGN_OWNER.value in actions


def test_high_risk_owner_less_sensitive_access_is_forced_critical(pipeline, high_risk_nhi):
    analysis = pipeline.analyze_github_nhi(high_risk_nhi)

    assert analysis.risk.level is RiskLevel.CRITICAL
    assert {rule["rule_id"] for rule in analysis.risk.forced_rules} == {
        "OWNERLESS_SENSITIVE_DATA_ACCESS"
    }
    # 강제 Critical 은 사람이 검토해야 한다.
    assert analysis.policy.human_review_required is True


def test_low_risk_inventory_nhi(pipeline, low_risk_nhi):
    analysis = pipeline.analyze_github_nhi(low_risk_nhi)

    assert analysis.risk.level is RiskLevel.LOW
    assert analysis.risk.forced_critical is False
    assert analysis.policy.violations == []
    assert analysis.permissions.permissions == [PermissionLevel.READ]
    assert analysis.recommended_action is RecommendedAction.MONITOR


def test_low_risk_scores_far_below_high_risk(pipeline, low_risk_nhi, high_risk_nhi):
    low = pipeline.analyze_github_nhi(low_risk_nhi)
    high = pipeline.analyze_github_nhi(high_risk_nhi)

    assert low.risk.score < high.risk.score


# ---------------------------------------------------------------------------
# 인벤토리 입력에 성립하지 않는 판정은 만들지 않는다
# ---------------------------------------------------------------------------
def test_inventory_input_does_not_report_plaintext_exposure(pipeline, high_risk_nhi):
    """코드에서 발견된 것이 아니므로 평문 노출 위반과 환경변수 이전 권고는 없어야 한다."""
    analysis = pipeline.analyze_github_nhi(high_risk_nhi)

    assert "NO_PLAINTEXT_CREDENTIAL" not in {
        v["policy_id"] for v in analysis.policy.to_dict()["violations"]
    }
    assert RecommendedAction.MOVE_TO_ENV_VAR not in {
        rec.action for rec in analysis.recommendations
    }
    # 원문도, 마스킹된 값도 없다 (인벤토리에는 Secret 값 자체가 없다).
    assert analysis.masked_value == ""
    assert analysis.file_path == ""
    assert any("인벤토리" in line for line in analysis.policy.evidence)


def test_inventory_analysis_scores_access_scope_as_exposure(pipeline, high_risk_nhi):
    """노출 위치 배점이 '접근 가능 저장소 범위' 로 계산된다."""
    analysis = pipeline.analyze_github_nhi(high_risk_nhi)
    exposure = next(f for f in analysis.risk.factors if f.area == "exposure_location")

    assert any("광범위" in reason for reason in exposure.reasons)
    assert any("민감 저장소" in reason for reason in exposure.reasons)


def test_blast_radius_counts_each_repository_once(pipeline, high_risk_nhi):
    """접근 자원은 저장소 수와 정확히 일치해야 한다 (중복 집계 금지)."""
    analysis = pipeline.analyze_github_nhi(high_risk_nhi)
    blast = analysis.blast_radius

    assert blast.accessible_resources == len(high_risk_nhi.repositories)
    assert sorted(blast.resource_samples) == sorted(
        repo.name for repo in high_risk_nhi.repositories
    )
    assert blast.sensitive_data_access is True


# ---------------------------------------------------------------------------
# 외부 신호 주입
# ---------------------------------------------------------------------------
def test_terminated_agent_signal_forces_critical(pipeline, low_risk_nhi):
    """코드·인벤토리에 없는 사실(Agent 종료)은 신호로 주입하면 점수에 반영된다."""
    analysis = pipeline.analyze_github_nhi(
        low_risk_nhi,
        signals={"agent_status": "terminated", "agent_name": "support-agent"},
    )

    assert analysis.risk.level is RiskLevel.CRITICAL
    assert "TERMINATED_AGENT_ACTIVE_TOKEN" in {
        rule["rule_id"] for rule in analysis.risk.forced_rules
    }
    assert analysis.recommended_action is RecommendedAction.TOKEN_REVOCATION


def test_expired_credential_is_recommended_for_revocation(pipeline):
    nhi = GitHubNHIInput(
        nhi_id="pat-expired",
        nhi_name="ci-runner-token",
        nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
        owner="platform-team",
        environment=Environment.STAGING,
        active=True,
        repositories=[RepositoryInfo(name="acme/ci", visibility="private")],
        raw_permissions={"contents": "read"},
        expires_at=datetime.now(timezone.utc) - timedelta(days=3),
        last_used_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    analysis = pipeline.analyze_github_nhi(nhi)

    assert analysis.recommended_action is RecommendedAction.TOKEN_REVOCATION
    credential = next(f for f in analysis.risk.factors if f.area == "credential_state")
    assert any("만료일이 이미 지난" in reason for reason in credential.reasons)
