"""Usage Analysis → Security Event → Scenario Mapping 테스트."""

from __future__ import annotations

import json

import pytest

from agents.pipeline import NHIAnalysisPipeline
from agents.usage_analysis_agent import UsageAnalysisAgent
from agents.discovery_agent import DiscoveryAgent
from agents.scope_translation_agent import ScopeTranslationAgent
from core.nhi_models import (
    AnalysisSignals,
    PermissionLevel,
    RecommendedAction,
    RiskLevel,
    SecurityEventType,
)
from tests.test_nhi_agents import make_finding


def _analyze_agent(finding, signals):
    profile = DiscoveryAgent().analyze(finding, signals)
    permissions = ScopeTranslationAgent().translate_finding(finding)
    return UsageAnalysisAgent().analyze(finding, profile, permissions, signals)


def test_read_only_identity_mutation_becomes_event():
    finding = make_finding(raw_scopes=["channels:history"], credential_active=True)
    signals = AnalysisSignals(
        declared_permissions=["READ"],
        observed_actions=["chat:write"],
        extra={"usage_data_complete": True, "usage_sources": ["slack_audit_log"]},
    )

    usage, events = _analyze_agent(finding, signals)

    assert usage.declared_permissions == [PermissionLevel.READ]
    assert usage.observed_permissions == [PermissionLevel.WRITE]
    assert usage.unexpected_permissions == [PermissionLevel.WRITE]
    assert usage.mutation_observed is True
    assert usage.usage_observed is True
    assert usage.data_complete is True
    assert events[0].event_type is SecurityEventType.UNDECLARED_PERMISSION_USE


def test_missing_usage_log_is_unknown_not_safe():
    finding = make_finding()
    usage, events = _analyze_agent(finding, AnalysisSignals())

    assert usage.usage_observed is None
    assert usage.data_complete is False
    assert usage.activity_status == "unknown"
    assert usage.unused_permissions == []
    assert usage.confidence < 0.5
    assert any("이상 없음으로 간주하지 않음" in item for item in usage.evidence)
    owner_event = next(
        event for event in events if event.event_type is SecurityEventType.OWNER_MISSING
    )
    assert owner_event.access_level is None
    assert owner_event.to_dict()["access_level"] is None


def test_unused_high_privilege_requires_complete_usage_and_verified_baseline():
    finding = make_finding(credential_active=True)
    complete, complete_events = _analyze_agent(
        finding,
        AnalysisSignals(
            owner="platform-team",
            declared_permissions=["READ", "DELETE", "ADMIN"],
            observed_actions=["READ"],
            last_used_at="2026-09-01T00:00:00Z",
            extra={
                "usage_data_complete": True,
                "analysis_reference_at": "2026-09-05T00:00:00Z",
            },
        ),
    )
    partial, partial_events = _analyze_agent(
        finding,
        AnalysisSignals(
            owner="platform-team",
            declared_permissions=["READ", "DELETE", "ADMIN"],
            observed_actions=["READ"],
            extra={"usage_data_complete": False},
        ),
    )

    assert complete.unused_permissions == [
        PermissionLevel.DELETE,
        PermissionLevel.ADMIN,
    ]
    assert complete.activity_status == "active"
    unused_event = next(
        event
        for event in complete_events
        if event.event_type is SecurityEventType.UNUSED_HIGH_PRIVILEGE
    )
    assert unused_event.access_level is PermissionLevel.ADMIN
    assert partial.unused_permissions == []
    assert not any(
        event.event_type is SecurityEventType.UNUSED_HIGH_PRIVILEGE
        for event in partial_events
    )


@pytest.mark.parametrize(
    ("last_used_at", "owner", "expected"),
    [
        ("2026-08-20T00:00:00Z", "platform-team", "active"),
        ("2026-07-01T00:00:00Z", "platform-team", "inactive_warning"),
        ("2026-01-01T00:00:00Z", "platform-team", "stale"),
        ("2026-01-01T00:00:00Z", None, "orphaned_candidate"),
    ],
)
def test_activity_status_classifies_lifecycle(last_used_at, owner, expected):
    usage, _ = _analyze_agent(
        make_finding(raw_scopes=["channels:history"]),
        AnalysisSignals(
            owner=owner,
            last_used_at=last_used_at,
            extra={"analysis_reference_at": "2026-09-05T00:00:00Z"},
        ),
    )

    assert usage.activity_status == expected


def test_partial_audit_log_does_not_drive_unused_scope_recommendation():
    analysis = NHIAnalysisPipeline().analyze_finding(
        make_finding(
            raw_scopes=["channels:history", "chat:write"],
            credential_active=True,
            account={"team": "platform-team", "user": "automation-bot"},
        ),
        signals=AnalysisSignals(
            observed_actions=["channels:history"],
            extra={"usage_data_complete": False},
        ),
    )

    assert analysis.usage_analysis.unused_permissions == []
    assert RecommendedAction.SCOPE_REDUCTION not in {
        recommendation.action for recommendation in analysis.recommendations
    }


def test_replay_event_is_deterministic_and_drives_existing_risk_rule():
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        token_replay_suspected=True,
        sender_constrained=True,
        token_binding_method="DPoP",
        request_source_ip="203.0.113.77",
        request_user_agent="curl/8.0",
    )
    pipeline = NHIAnalysisPipeline()

    first = pipeline.analyze_finding(finding, signals=signals)
    second = pipeline.analyze_finding(finding, signals=signals)

    assert first.security_events[0].event_id == second.security_events[0].event_id
    assert first.security_events[0].event_type is SecurityEventType.TOKEN_REPLAY
    assert first.scenario_matches[0].scenario_id == "TOKEN_REPLAY_SUSPECTED"
    assert first.risk.level is RiskLevel.CRITICAL
    assert "TOKEN_REPLAY_SUSPECTED" in {
        item["rule_id"] for item in first.risk.forced_rules
    }
    assert first.recommended_action is RecommendedAction.TOKEN_REVOCATION


def test_cross_project_signal_maps_to_existing_forced_rule():
    analysis = NHIAnalysisPipeline().analyze_finding(
        make_finding(credential_active=True),
        signals=AnalysisSignals(shared_projects=["acme/a", "acme/b"]),
    )

    assert {item.scenario_id for item in analysis.scenario_matches} >= {
        "TOKEN_SHARED_ACROSS_PROJECTS"
    }
    assert "TOKEN_SHARED_ACROSS_PROJECTS" in {
        item["rule_id"] for item in analysis.risk.forced_rules
    }


def test_pipeline_serializes_three_stage_usage_output_without_secret():
    raw_secret = "xoxb-should-never-be-serialized"
    finding = make_finding(credential_active=True)
    finding._raw_value = raw_secret
    result = NHIAnalysisPipeline().analyze_finding(
        finding,
        signals=AnalysisSignals(
            declared_permissions=["READ"], observed_actions=["chat:write"]
        ),
    ).to_dict()

    assert result["usage_analysis"]["unexpected_permissions"] == ["WRITE"]
    assert result["security_events"]
    assert result["scenario_matches"]
    assert raw_secret not in str(result)


def test_granted_scope_is_used_when_explicit_baseline_is_missing():
    finding = make_finding(raw_scopes=["channels:history"], credential_active=True)
    usage, events = _analyze_agent(
        finding, AnalysisSignals(observed_actions=["chat:write"])
    )

    assert usage.permission_baseline_source == "granted_scope"
    assert usage.permission_comparison_complete is True
    assert usage.declared_permissions == [PermissionLevel.READ]
    assert usage.unexpected_permissions == [PermissionLevel.WRITE]
    assert events


@pytest.mark.parametrize(
    ("declared", "observed"),
    [("ADMIN", "WRITE"), ("DELETE", "READ"), ("WRITE", "READ")],
)
def test_higher_permission_allows_normal_lower_level_action(declared, observed):
    usage, events = _analyze_agent(
        make_finding(credential_active=True),
        AnalysisSignals(
            declared_permissions=[declared], observed_actions=[observed]
        ),
    )

    assert usage.unexpected_permissions == []
    assert not any(
        event.event_type is SecurityEventType.UNDECLARED_PERMISSION_USE
        for event in events
    )


def test_revoked_credential_requires_explicit_signal_or_time_order():
    finding = make_finding(credential_active=False, credential_revoked=True)
    before, before_events = _analyze_agent(
        finding,
        AnalysisSignals(
            revoked_at="2026-08-20T00:00:00Z",
            last_used_at="2026-08-19T23:59:59Z",
        ),
    )
    after, after_events = _analyze_agent(
        finding,
        AnalysisSignals(
            revoked_at="2026-08-20T00:00:00Z",
            last_used_at="2026-08-20T00:00:01Z",
        ),
    )

    assert before.used_after_revocation is False
    assert not any(
        event.event_type is SecurityEventType.REVOKED_CREDENTIAL_USE
        for event in before_events
    )
    assert after.used_after_revocation is True
    revoked_event = next(
        event
        for event in after_events
        if event.event_type is SecurityEventType.REVOKED_CREDENTIAL_USE
    )
    assert revoked_event.origin == "derived"


def test_time_derived_revoked_use_drives_canonical_forced_rule():
    analysis = NHIAnalysisPipeline().analyze_finding(
        make_finding(credential_active=False, credential_revoked=True),
        signals=AnalysisSignals(
            revoked_at="2026-08-20T00:00:00Z",
            last_used_at="2026-08-20T00:00:01Z",
        ),
    )

    assert analysis.usage_analysis.used_after_revocation is True
    assert "REVOKED_TOKEN_STILL_USED" in {
        item.scenario_id for item in analysis.scenario_matches
    }
    assert "REVOKED_TOKEN_STILL_USED" in {
        item["rule_id"] for item in analysis.risk.forced_rules
    }


def test_usage_serialization_redacts_credentials_from_untrusted_audit_fields():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    result = NHIAnalysisPipeline().analyze_finding(
        make_finding(credential_active=True),
        signals=AnalysisSignals(
            declared_permissions=["READ"],
            observed_actions=[f"GET /v1/items?access_token={secret}"],
            token_replay_suspected=True,
            request_user_agent=f"curl Authorization: Bearer {secret}",
            extra={
                "usage_sources": [f"Authorization: Bearer {secret}"],
                "usage_source_event_id": f"token={secret}",
            },
        ),
    ).to_dict()

    serialized = json.dumps(result, ensure_ascii=False)
    assert secret not in serialized
    assert "<redacted>" in serialized


def test_pipeline_scenarios_and_forced_rules_share_canonical_ids():
    analysis = NHIAnalysisPipeline().analyze_finding(
        make_finding(
            raw_scopes=["admin"],
            credential_active=True,
            credential_revoked=True,
        ),
        signals=AnalysisSignals(
            repository_public=True,
            agent_status="terminated",
            token_used_after_revocation=True,
            token_replay_suspected=True,
            shared_projects=["acme/a", "acme/b"],
            declared_permissions=["READ"],
            observed_actions=["WRITE"],
        ),
    )

    forced_scenarios = {
        item.scenario_id for item in analysis.scenario_matches if item.forced_critical
    }
    forced_rules = {item["rule_id"] for item in analysis.risk.forced_rules}
    assert forced_scenarios == forced_rules
    assert "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN" in forced_scenarios
    assert "TOKEN_REPLAY_SUSPECTED" in forced_scenarios


def test_inactive_example_suppresses_forced_scenarios_and_risk_together():
    analysis = NHIAnalysisPipeline().analyze_finding(
        make_finding(file_path="tests/example.env", credential_active=False),
        signals=AnalysisSignals(token_replay_suspected=True),
    )

    assert [item for item in analysis.scenario_matches if item.forced_critical] == []
    assert analysis.risk.forced_rules == []
