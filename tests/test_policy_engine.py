"""정책 엔진 테스트 — 위반 판정 / 위험 점수 / 강제 Critical / 조치 결정."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agents.context_analysis_agent import ContextAnalysisAgent
from agents.discovery_agent import DiscoveryAgent
from agents.recommendation_agent import RecommendationAgent
from agents.risk_scoring_agent import RiskScoringAgent
from agents.scope_translation_agent import ScopeTranslationAgent
from core.nhi_models import (
    AnalysisSignals,
    PermissionLevel,
    PolicyOutcome,
    RecommendedAction,
    RiskLevel,
)
from graph.blast_radius import BlastRadiusCalculator
from policy.decision_engine import DecisionEngine
from policy.rules import EvaluationContext, PolicyConfig, evaluate_forced_critical, evaluate_policies
from policy.scoring import AREA_MAX, RiskScorer, risk_level_for
from tests.test_nhi_agents import make_finding


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def build_ctx(finding=None, signals=None, config=None, **kwargs) -> EvaluationContext:
    """finding + signals 로 EvaluationContext 를 조립한다."""
    finding = finding or make_finding()
    signals = signals or AnalysisSignals()
    profile = DiscoveryAgent().analyze(finding, signals)
    context = ContextAnalysisAgent().analyze(finding, signals)
    permissions = ScopeTranslationAgent().translate_finding(finding)
    blast = BlastRadiusCalculator().compute(finding, profile, permissions, context, signals)
    return EvaluationContext(
        finding=finding,
        profile=profile,
        context=context,
        permissions=permissions,
        signals=signals,
        blast_radius=blast,
        config=config or PolicyConfig(),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# 배점 / 등급
# ---------------------------------------------------------------------------
def test_area_weights_total_100():
    assert sum(AREA_MAX.values()) == 100


def test_risk_level_thresholds():
    assert risk_level_for(100) is RiskLevel.CRITICAL
    assert risk_level_for(80) is RiskLevel.CRITICAL
    assert risk_level_for(79) is RiskLevel.HIGH
    assert risk_level_for(60) is RiskLevel.HIGH
    assert risk_level_for(59) is RiskLevel.MEDIUM
    assert risk_level_for(30) is RiskLevel.MEDIUM
    assert risk_level_for(29) is RiskLevel.LOW
    assert risk_level_for(0) is RiskLevel.LOW


def test_factor_scores_never_exceed_area_max():
    ctx = build_ctx(
        finding=make_finding(
            file_path="deploy/prod/app.env",
            raw_scopes=["repo", "delete_repo", "admin:org"],
            credential_active=True,
            occurrence_count=5,
        ),
        signals=AnalysisSignals(repository_public=True, shared_projects=["a", "b", "c"]),
    )
    assessment = RiskScorer().score(ctx, evaluate_policies(ctx))
    for factor in assessment.factors:
        assert 0 <= factor.score <= factor.max_score == AREA_MAX[factor.area]
    assert assessment.score <= 100


def test_test_fixture_scores_low():
    """테스트 픽스처의 더미 값은 낮은 위험도로 떨어져야 한다."""
    ctx = build_ctx(
        finding=make_finding(
            file_path="tests/fixtures/slack.env",
            line="SLACK_BOT_TOKEN='xoxb-example-token'",
        )
    )
    assessment = RiskScorer().score(ctx, evaluate_policies(ctx))
    assert assessment.level in (RiskLevel.LOW, RiskLevel.MEDIUM)
    assert assessment.forced_critical is False


def test_production_active_token_scores_high():
    ctx = build_ctx(
        finding=make_finding(
            file_path="deploy/production/app.env",
            raw_scopes=["channels:history", "chat:write"],
            credential_active=True,
            credential_revoked=False,
            account={"team": "Customer Support Team", "user": "customer-support-bot"},
        ),
        signals=AnalysisSignals(repository="acme/support", repository_public=True),
    )
    assessment = RiskScorer().score(ctx, evaluate_policies(ctx))
    assert assessment.score >= 60
    assert any("운영 환경" in reason for reason in assessment.reasons)


# ---------------------------------------------------------------------------
# 정책 위반
# ---------------------------------------------------------------------------
def test_owner_required_violation_is_not_auto_remediable():
    ctx = build_ctx(finding=make_finding(file_path="src/app.py"))
    violations = {v.policy_id: v for v in evaluate_policies(ctx)}
    assert "OWNER_REQUIRED" in violations
    assert violations["OWNER_REQUIRED"].remediable is False


def test_token_max_age_and_rotation_violations():
    ctx = build_ctx(
        finding=make_finding(credential_active=True),
        signals=AnalysisSignals(created_at=_days_ago(500), last_rotated_at=_days_ago(400)),
    )
    ids = {v.policy_id for v in evaluate_policies(ctx)}
    assert "TOKEN_MAX_AGE" in ids
    assert "ROTATION_PERIOD" in ids


def test_admin_scope_policy_can_be_allowlisted():
    finding = make_finding(secret_type="GITHUB_PAT", provider="github", raw_scopes=["repo"])
    ctx = build_ctx(finding=finding)
    assert "ADMIN_SCOPE_RESTRICTED" in {v.policy_id for v in evaluate_policies(ctx)}

    allowed = PolicyConfig(admin_scope_allowed_types=(DiscoveryAgent().analyze(finding).nhi_type,))
    ctx_allowed = build_ctx(finding=finding, config=allowed)
    assert "ADMIN_SCOPE_RESTRICTED" not in {v.policy_id for v in evaluate_policies(ctx_allowed)}


def test_broad_oauth_scope_violation_and_allowlist():
    """SaaS 연동 Agent 가 전사 범위(mail.read.all 등) Scope 를 승인받으면 위반이다."""
    finding = make_finding(
        secret_type="NOTION_INTEGRATION_TOKEN", provider="notion",
        raw_scopes=["mail.read.all", "channels:history"],
    )
    ctx = build_ctx(finding=finding)
    assert "BROAD_OAUTH_SCOPE" in {v.policy_id for v in evaluate_policies(ctx)}

    allowed = PolicyConfig(admin_scope_allowed_types=(DiscoveryAgent().analyze(finding).nhi_type,))
    ctx_allowed = build_ctx(finding=finding, config=allowed)
    assert "BROAD_OAUTH_SCOPE" not in {v.policy_id for v in evaluate_policies(ctx_allowed)}


def test_broad_oauth_scope_not_triggered_for_narrow_scopes():
    ctx = build_ctx(finding=make_finding(raw_scopes=["channels:history"]))
    assert "BROAD_OAUTH_SCOPE" not in {v.policy_id for v in evaluate_policies(ctx)}


def test_excessive_data_exposure_violation():
    """집계용 데이터 API 가 민감 데이터에서 대량/원본 추출 행위를 보이면 위반이다."""
    ctx = build_ctx(
        finding=make_finding(
            secret_type="STRIPE_SECRET_KEY", provider="stripe",
            file_path="src/billing/client.py", line="STRIPE_SECRET_KEY = 'sk_live_****'",
        ),
        signals=AnalysisSignals(observed_actions=["export_csv_all_customers"]),
    )
    violations = {v.policy_id: v for v in evaluate_policies(ctx)}
    assert "EXCESSIVE_DATA_EXPOSURE" in violations
    assert violations["EXCESSIVE_DATA_EXPOSURE"].severity is RiskLevel.HIGH


def test_excessive_data_exposure_not_triggered_without_bulk_action():
    ctx = build_ctx(
        finding=make_finding(
            secret_type="STRIPE_SECRET_KEY", provider="stripe",
            file_path="src/billing/client.py", line="STRIPE_SECRET_KEY = 'sk_live_****'",
        ),
        signals=AnalysisSignals(observed_actions=["get_customer_summary"]),
    )
    assert "EXCESSIVE_DATA_EXPOSURE" not in {v.policy_id for v in evaluate_policies(ctx)}


def test_exempted_policy_is_skipped():
    ctx = build_ctx(
        finding=make_finding(file_path="src/app.py"),
        signals=AnalysisSignals(exempted_policies=["OWNER_REQUIRED"]),
    )
    assert "OWNER_REQUIRED" not in {v.policy_id for v in evaluate_policies(ctx)}


# ---------------------------------------------------------------------------
# 강제 Critical 규칙 (6종)
# ---------------------------------------------------------------------------
def test_forced_critical_public_repo_active_admin_token():
    ctx = build_ctx(
        finding=make_finding(
            secret_type="GITHUB_PAT", provider="github",
            raw_scopes=["repo"], credential_active=True,
        ),
        signals=AnalysisSignals(repository_public=True),
    )
    assessment = RiskScorer().score(ctx, [])
    assert assessment.forced_critical is True
    assert assessment.level is RiskLevel.CRITICAL
    assert assessment.score >= 80
    assert "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN" in {r["rule_id"] for r in assessment.forced_rules}


def test_forced_critical_ownerless_sensitive_access():
    ctx = build_ctx(
        finding=make_finding(
            secret_type="STRIPE_SECRET_KEY", provider="stripe",
            file_path="src/billing/client.py", line="STRIPE_SECRET_KEY = 'sk_live_****'",
        )
    )
    assert ctx.profile.owner is None
    rules = {r["rule_id"] for r in evaluate_forced_critical(ctx)}
    assert "OWNERLESS_SENSITIVE_DATA_ACCESS" in rules


def test_forced_critical_terminated_agent_active_token():
    ctx = build_ctx(
        finding=make_finding(credential_active=True),
        signals=AnalysisSignals(agent_status="terminated", agent_name="support-agent"),
    )
    assert "TERMINATED_AGENT_ACTIVE_TOKEN" in {r["rule_id"] for r in evaluate_forced_critical(ctx)}


def test_forced_critical_revoked_token_still_used():
    ctx = build_ctx(
        finding=make_finding(credential_revoked=True, credential_active=False),
        signals=AnalysisSignals(token_used_after_revocation=True),
    )
    assert "REVOKED_TOKEN_STILL_USED" in {r["rule_id"] for r in evaluate_forced_critical(ctx)}


def test_runtime_token_replay_is_critical_and_recommends_revocation():
    ctx = build_ctx(
        finding=make_finding(credential_active=True),
        signals=AnalysisSignals(
            token_replay_suspected=True,
            sender_constrained=True,
            token_binding_method="DPoP",
            request_source_ip="203.0.113.77",
            request_user_agent="curl/8.0",
        ),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScorer().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)
    recommendations = RecommendationAgent().recommend(ctx, risk, decision)

    assert risk.level is RiskLevel.CRITICAL
    assert "TOKEN_REPLAY_SUSPECTED" in {item["rule_id"] for item in risk.forced_rules}
    assert recommendations[0].action is RecommendedAction.TOKEN_REVOCATION


def test_forced_critical_token_shared_across_projects():
    ctx = build_ctx(
        finding=make_finding(credential_active=True),
        signals=AnalysisSignals(shared_projects=["acme/payments", "acme/support"]),
    )
    rules = {r["rule_id"] for r in evaluate_forced_critical(ctx)}
    assert "TOKEN_SHARED_ACROSS_PROJECTS" in rules
    assert "PROJECT_TOKEN_ISOLATION" in {v.policy_id for v in evaluate_policies(ctx)}


def test_forced_critical_read_only_nhi_performs_mutation():
    ctx = build_ctx(
        finding=make_finding(raw_scopes=["channels:history"], credential_active=True),
        signals=AnalysisSignals(
            declared_permissions=["READ"], observed_actions=["chat:write", "files:write"]
        ),
        declared_permissions=[PermissionLevel.READ],
        observed_permissions=[PermissionLevel.WRITE],
    )
    assert "READ_ONLY_NHI_PERFORMS_MUTATION" in {
        r["rule_id"] for r in evaluate_forced_critical(ctx)
    }


def test_forced_critical_iam_privilege_self_escalation():
    """진단(read-only) NHI 가 같은 세션에서 IAM 정책·그룹 변경 API 를 호출하면 강제 Critical 이다."""
    ctx = build_ctx(
        finding=make_finding(raw_scopes=["iam:list"], credential_active=True),
        signals=AnalysisSignals(
            declared_permissions=["READ"],
            observed_actions=["ListPolicy", "UpdatePolicy", "AddUserToGroup"],
        ),
        declared_permissions=[PermissionLevel.READ],
    )
    assert "IAM_PRIVILEGE_SELF_ESCALATION" in {
        r["rule_id"] for r in evaluate_forced_critical(ctx)
    }


def test_forced_critical_iam_privilege_self_escalation_not_triggered_without_escalation_action():
    ctx = build_ctx(
        finding=make_finding(raw_scopes=["iam:list"], credential_active=True),
        signals=AnalysisSignals(
            declared_permissions=["READ"], observed_actions=["ListPolicy", "GetPolicy"]
        ),
        declared_permissions=[PermissionLevel.READ],
    )
    assert "IAM_PRIVILEGE_SELF_ESCALATION" not in {
        r["rule_id"] for r in evaluate_forced_critical(ctx)
    }


def test_forced_critical_skipped_for_inactive_test_values():
    """예제 값에는 강제 Critical 을 적용하지 않는다 (오탐 억제)."""
    ctx = build_ctx(
        finding=make_finding(
            secret_type="STRIPE_SECRET_KEY", provider="stripe",
            file_path="tests/fixtures/billing.env",
            line="STRIPE_SECRET_KEY='sk_test_example'",
        )
    )
    assert evaluate_forced_critical(ctx) == []


# ---------------------------------------------------------------------------
# 결정 엔진
# ---------------------------------------------------------------------------
def test_decision_requires_human_review_for_forced_critical():
    ctx = build_ctx(
        finding=make_finding(
            secret_type="GITHUB_PAT", provider="github",
            raw_scopes=["repo"], credential_active=True,
        ),
        signals=AnalysisSignals(repository_public=True),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)

    assert decision.outcome is PolicyOutcome.HUMAN_REVIEW
    assert decision.human_review_required is True
    assert decision.auto_remediable is False


def test_decision_auto_remediates_low_risk_dev_finding():
    ctx = build_ctx(
        finding=make_finding(
            file_path="dev/local.env",
            raw_scopes=["channels:history"],
            credential_active=False,
            account={"team": "Platform Team", "user": "dev-bot"},
        ),
        signals=AnalysisSignals(
            created_at=_days_ago(10), last_rotated_at=_days_ago(10), expires_at=_days_ago(-30)
        ),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)

    assert risk.level in (RiskLevel.LOW, RiskLevel.MEDIUM)
    assert decision.outcome in (PolicyOutcome.AUTO_REMEDIATION, PolicyOutcome.MONITOR)
    assert decision.human_review_required is False


def test_decision_applies_valid_exception():
    ctx = build_ctx(
        finding=make_finding(
            file_path="dev/local.env",
            raw_scopes=["channels:history"],
            credential_active=False,
            account={"team": "Platform Team", "user": "dev-bot"},
        ),
        signals=AnalysisSignals(
            exception_id="EXC-2026-014",
            exception_reason="레거시 마이그레이션 기간 한시 허용",
            exception_expires_at=_days_ago(-30),
            exempted_policies=["NO_PLAINTEXT_CREDENTIAL"],
        ),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)

    assert decision.exception_applied is not None
    assert decision.exception_applied["exception_id"] == "EXC-2026-014"
    assert decision.outcome is PolicyOutcome.EXCEPTION_APPROVED


def test_decision_ignores_expired_exception():
    ctx = build_ctx(
        finding=make_finding(credential_active=True),
        signals=AnalysisSignals(exception_id="EXC-OLD", exception_expires_at=_days_ago(5)),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)

    assert decision.exception_applied is None
    assert any("만료" in line for line in decision.evidence)


# ---------------------------------------------------------------------------
# 권고
# ---------------------------------------------------------------------------
def test_recommendation_prioritizes_revocation_for_revoked_but_used_token():
    ctx = build_ctx(
        finding=make_finding(credential_revoked=True),
        signals=AnalysisSignals(token_used_after_revocation=True),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)
    actions = [r.action for r in RecommendationAgent().recommend(ctx, risk, decision)]

    assert actions[0] is RecommendedAction.TOKEN_REVOCATION


def test_recommendation_covers_owner_and_scope_and_split():
    ctx = build_ctx(
        finding=make_finding(
            secret_type="GITHUB_PAT", provider="github",
            file_path="src/app.py", raw_scopes=["repo"], credential_active=True,
        ),
        signals=AnalysisSignals(shared_projects=["acme/a", "acme/b"]),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)
    actions = {r.action for r in RecommendationAgent().recommend(ctx, risk, decision)}

    assert RecommendedAction.ASSIGN_OWNER in actions
    assert RecommendedAction.SCOPE_REDUCTION in actions
    assert RecommendedAction.SPLIT_TOKEN_PER_PROJECT in actions
    assert RecommendedAction.MOVE_TO_ENV_VAR in actions


def test_recommendation_monitor_when_nothing_to_do():
    ctx = build_ctx(
        finding=make_finding(
            file_path="tests/fixtures/slack.env",
            line="SLACK_BOT_TOKEN='xoxb-example-token'",
            account={"team": "Platform Team"},
        )
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)
    actions = [r.action for r in RecommendationAgent().recommend(ctx, risk, decision)]

    assert actions == [RecommendedAction.MONITOR]


def test_recommendation_disables_inactive_nhi():
    ctx = build_ctx(
        finding=make_finding(credential_active=True),
        signals=AnalysisSignals(last_used_at=_days_ago(200)),
    )
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    decision = DecisionEngine().decide(ctx, risk, violations)
    actions = {r.action for r in RecommendationAgent().recommend(ctx, risk, decision)}

    assert RecommendedAction.DISABLE_INACTIVE_NHI in actions
