"""분석 Agent 단위 테스트 — Discovery / Context / Scope Translation."""

from __future__ import annotations

from core.models import CodeContext, DetectorType, SecretFinding, Severity
from core.nhi_models import (
    AnalysisSignals,
    DataSensitivity,
    Environment,
    NHIType,
    PermissionLevel,
)
from agents.context_analysis_agent import ContextAnalysisAgent
from agents.discovery_agent import DiscoveryAgent
from agents.scope_translation_agent import ScopeTranslationAgent, expand_permissions


def make_finding(
    *,
    secret_type: str = "SLACK_BOT_TOKEN",
    provider: str = "slack",
    file_path: str = "config/slack.env",
    line: str = "SLACK_BOT_TOKEN=xoxb-****-nW7pQ3d",
    before=None,
    after=None,
    raw_scopes=None,
    account=None,
    resources=None,
    credential_active=None,
    credential_revoked=None,
    occurrence_count: int = 1,
) -> SecretFinding:
    detail = None
    if account is not None or resources is not None:
        detail = {"account": account or {}, "accessible_resources": resources or []}
    return SecretFinding(
        secret_type=secret_type,
        provider=provider,
        masked_value="xoxb-****-nW7pQ3d",
        fingerprint=f"sha256:{secret_type.lower()}0011223344",
        file_path=file_path,
        line_number=12,
        detector=DetectorType.REGEX,
        severity=Severity.CRITICAL,
        context=CodeContext(before=before or [], line=line, after=after or []),
        credential_active=credential_active,
        credential_revoked=credential_revoked,
        raw_scopes=raw_scopes or [],
        credential_detail=detail,
        occurrence_count=occurrence_count,
    )


# ---------------------------------------------------------------------------
# Discovery Agent
# ---------------------------------------------------------------------------
def test_discovery_identifies_slack_bot_from_credential_account():
    finding = make_finding(
        account={"team": "Customer Support Team", "user": "customer-support-bot", "bot_id": "B01"},
        credential_active=True,
    )
    profile = DiscoveryAgent().analyze(finding)

    assert profile.nhi_type is NHIType.SLACK_BOT
    assert profile.nhi_name == "customer-support-bot"
    assert profile.owner == "Customer Support Team"
    assert profile.owner_source == "credential_account"
    assert profile.is_bot is True
    assert profile.is_service_account is True
    assert profile.identified is True
    assert profile.confidence > 0.7


def test_discovery_falls_back_to_variable_name():
    """검증 정보가 없으면 변수명에서 NHI 이름을 만든다."""
    finding = make_finding(line="CUSTOMER_SUPPORT_BOT_TOKEN=xoxb-****-nW7pQ3d")
    profile = DiscoveryAgent().analyze(finding)

    assert profile.nhi_name == "customer-support-bot"
    assert profile.credential_fingerprint == finding.fingerprint


def test_discovery_marks_unknown_nhi_for_unclassified_secret():
    finding = make_finding(
        secret_type="UNCLASSIFIED_HIGH_ENTROPY",
        provider="unknown",
        file_path="src/util.py",
        line="value = 'aZ81kdlfjW02mfPQzz19'",
    )
    profile = DiscoveryAgent().analyze(finding)

    assert profile.nhi_type is NHIType.UNKNOWN_NHI
    assert profile.identified is False
    assert profile.nhi_id.startswith("unknown-nhi:")


def test_discovery_infers_linked_ai_agent():
    finding = make_finding(
        secret_type="ANTHROPIC_API_KEY",
        provider="anthropic",
        file_path="agents/support_agent/config.py",
        line="ANTHROPIC_API_KEY = 'sk-ant-****'",
    )
    profile = DiscoveryAgent().analyze(finding)

    assert profile.nhi_type is NHIType.AI_AGENT_CREDENTIAL
    assert profile.linked_ai_agent == "support-agent"


def test_discovery_owner_from_code_comment():
    finding = make_finding(
        before=["# owner: platform-team"],
        line="SLACK_BOT_TOKEN=xoxb-****",
    )
    profile = DiscoveryAgent().analyze(finding)

    assert profile.owner == "platform-team"
    assert profile.owner_source == "code_comment"


def test_discovery_external_signal_overrides_owner():
    finding = make_finding(account={"team": "Customer Support Team"})
    profile = DiscoveryAgent().analyze(
        finding, AnalysisSignals(owner="Security Team")
    )

    assert profile.owner == "Security Team"
    assert profile.owner_source == "external_signal"


# ---------------------------------------------------------------------------
# Context Analysis Agent
# ---------------------------------------------------------------------------
def test_context_detects_production_environment():
    finding = make_finding(file_path="deploy/production/app.env", credential_active=True)
    insight = ContextAnalysisAgent().analyze(finding)

    assert insight.environment is Environment.PRODUCTION
    assert insight.in_use is True
    assert insight.is_test_or_example is False


def test_context_detects_test_fixture():
    finding = make_finding(
        file_path="tests/fixtures/slack.env",
        line="SLACK_BOT_TOKEN='xoxb-example-token'",
    )
    insight = ContextAnalysisAgent().analyze(finding)

    assert insight.is_test_or_example is True
    assert insight.environment is Environment.TEST
    assert insight.in_use is False


def test_context_flags_hardcoded_source_and_variable_name():
    finding = make_finding(
        file_path="src/payments/client.py",
        line="STRIPE_SECRET_KEY = 'sk_live_****'",
    )
    insight = ContextAnalysisAgent().analyze(finding)

    assert insight.hardcoded_in_source is True
    assert insight.variable_name == "STRIPE_SECRET_KEY"
    assert insight.data_sensitivity is DataSensitivity.RESTRICTED


def test_context_confidence_rises_with_verified_credential():
    plain = ContextAnalysisAgent().analyze(make_finding())
    verified = ContextAnalysisAgent().analyze(
        make_finding(file_path="deploy/prod/app.env", credential_active=True)
    )
    assert verified.confidence > plain.confidence


# ---------------------------------------------------------------------------
# Scope Translation Agent
# ---------------------------------------------------------------------------
def test_scope_translation_table_examples():
    """설계 문서에 명시된 변환 예시가 그대로 성립해야 한다."""
    agent = ScopeTranslationAgent()
    cases = {
        ("slack", "channels:history"): PermissionLevel.READ,
        ("slack", "chat:write"): PermissionLevel.WRITE,
        ("slack", "files:write"): PermissionLevel.WRITE,
        ("github", "contents:write"): PermissionLevel.WRITE,
        ("github", "delete_repo"): PermissionLevel.DELETE,
        ("github", "repo"): PermissionLevel.ADMIN,
    }
    for (provider, scope), expected in cases.items():
        mapping = agent.translate_scope(scope, provider=provider)
        assert mapping.permission is expected, f"{provider}:{scope}"
        assert mapping.inferred is False


def test_scope_translation_collects_distinct_permissions():
    profile = ScopeTranslationAgent().translate(
        ["channels:history", "chat:write", "files:write"], provider="slack"
    )
    assert profile.permissions == [PermissionLevel.READ, PermissionLevel.WRITE]
    assert profile.highest is PermissionLevel.WRITE
    assert profile.assumed is False
    assert profile.unknown_scopes == []


def test_scope_translation_infers_unknown_scope_by_keyword():
    profile = ScopeTranslationAgent().translate(
        ["billing.invoices.delete"], provider="acme"
    )
    assert profile.permissions == [PermissionLevel.DELETE]
    assert profile.mappings[0].inferred is True


def test_scope_translation_assumes_when_scopes_missing():
    profile = ScopeTranslationAgent().translate([], provider="github", secret_type="GITHUB_PAT")
    assert profile.assumed is True
    assert profile.highest is PermissionLevel.ADMIN


def test_expand_permissions_implies_lower_levels():
    assert expand_permissions([PermissionLevel.ADMIN]) == {
        PermissionLevel.ADMIN,
        PermissionLevel.DELETE,
        PermissionLevel.WRITE,
        PermissionLevel.READ,
    }
    assert expand_permissions([PermissionLevel.WRITE]) == {
        PermissionLevel.WRITE,
        PermissionLevel.READ,
    }
