"""회사 AI Agent 접근 기준선과 위장·범위 초과 호출 판정 테스트."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.services.agent_access_evaluator import AgentAccessEvaluator
from core.agent_access_models import (
    AgentAccessGrant,
    AgentAccessOutcome,
    AgentAccessProfile,
    AgentApiObservation,
)
from core.nhi_models import PermissionLevel


FINGERPRINT = "sha256:agentcredential1234567890abcdef"


def _profile(**overrides) -> AgentAccessProfile:
    values = {
        "agent_id": "finance-report-agent",
        "display_name": "재무 보고서 Agent",
        "owner": "finance-platform-team",
        "inventory_complete": True,
        "require_sender_constraint": True,
        "allowed_binding_methods": ["mTLS"],
        "grants": [
            AgentAccessGrant(
                grant_id="finance-graph-read",
                provider="microsoft",
                nhi_id="sp-finance-agent",
                credential_fingerprints=[FINGERPRINT],
                credential_inventory_complete=True,
                permissions=[PermissionLevel.READ],
                permission_inventory_complete=True,
                resources=["microsoft://sites/finance/*"],
                sensitive_resources=["microsoft://sites/finance/*"],
                resource_inventory_complete=True,
                source="microsoft_graph",
            )
        ],
    }
    values.update(overrides)
    return AgentAccessProfile(**values)


def _observation(**overrides) -> AgentApiObservation:
    values = {
        "event_id": "gateway-event-001",
        "claimed_agent_id": "finance-report-agent",
        "authenticated_agent_id": "finance-report-agent",
        "provider": "microsoft",
        "nhi_id": "sp-finance-agent",
        "credential_fingerprint": FINGERPRINT,
        "action": "GET /sites/finance/reports",
        "permission": PermissionLevel.READ,
        "resource": "microsoft://sites/finance/reports",
        "resource_sensitive": True,
        "sender_constrained": True,
        "binding_method": "mTLS",
        "sender_proof_valid": True,
    }
    values.update(overrides)
    return AgentApiObservation(**values)


def test_registered_agent_within_scope_is_allowed():
    decision = AgentAccessEvaluator().evaluate(_profile(), _observation())

    assert decision.outcome is AgentAccessOutcome.ALLOW
    assert decision.matched_grant_id == "finance-graph-read"
    assert decision.findings == []


def test_unregistered_agent_is_denied():
    decision = AgentAccessEvaluator().evaluate(None, _observation())

    assert decision.outcome is AgentAccessOutcome.DENY
    assert [finding.rule_id for finding in decision.findings] == [
        "UNREGISTERED_AGENT"
    ]


def test_registered_agent_token_replay_is_denied():
    decision = AgentAccessEvaluator().evaluate(
        _profile(), _observation(token_replay_suspected=True)
    )

    assert decision.outcome is AgentAccessOutcome.DENY
    assert "TOKEN_REPLAY_SUSPECTED" in {
        finding.rule_id for finding in decision.findings
    }


def test_claimed_agent_with_different_identity_and_credential_is_denied():
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(
            authenticated_agent_id="attacker-agent",
            credential_fingerprint="sha256:attackercredential1234567890",
            permission=PermissionLevel.WRITE,
            resource="microsoft://sites/hr/payroll.xlsx",
            sender_proof_valid=False,
        ),
    )

    assert decision.outcome is AgentAccessOutcome.DENY
    rule_ids = {finding.rule_id for finding in decision.findings}
    assert {
        "CLAIMED_IDENTITY_MISMATCH",
        "SENDER_PROOF_INVALID",
        "UNAPPROVED_CREDENTIAL",
        "PERMISSION_SCOPE_EXCEEDED",
        "RESOURCE_SCOPE_EXCEEDED",
    } <= rule_ids


def test_incomplete_inventory_is_review_not_false_allow_or_attack_confirmation():
    profile = _profile(grants=[], inventory_complete=False, require_sender_constraint=False)
    decision = AgentAccessEvaluator().evaluate(
        profile,
        _observation(
            authenticated_agent_id=None,
            nhi_id="unknown-sp",
            credential_fingerprint=None,
            sender_constrained=False,
            sender_proof_valid=None,
        ),
    )

    assert decision.outcome is AgentAccessOutcome.REVIEW
    assert "NHI_BASELINE_INCOMPLETE" in {
        finding.rule_id for finding in decision.findings
    }


def test_scope_summary_exposes_broad_permissions_and_coverage_gaps():
    profile = _profile(
        inventory_complete=False,
        owner=None,
        grants=[
            AgentAccessGrant(
                grant_id="broad",
                provider="github",
                nhi_id="github-app:7",
                permissions=[PermissionLevel.ADMIN],
                resources=["acme/*"],
            )
        ],
    )
    summary = AgentAccessEvaluator().summarize_scope(profile)

    assert summary["permissions"] == ["ADMIN"]
    assert summary["resource_count"] == 1
    assert summary["inventory_complete"] is False
    assert {item["type"] for item in summary["broad_access_indicators"]} == {
        "HIGH_PRIVILEGE",
        "WILDCARD_RESOURCE",
    }
    assert summary["blind_spots"]


def test_profile_rejects_raw_credential_instead_of_fingerprint():
    with pytest.raises(ValidationError, match="원문 Credential"):
        AgentAccessGrant(
            provider="github",
            nhi_id="app-1",
            credential_fingerprints=["ghp_plaintexttokenmustnotbestored123456"],
        )
