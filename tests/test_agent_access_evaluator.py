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
    NHIAccessContext,
)
from core.nhi_lifecycle_models import NHILifecycleStatus
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


# ---------------------------------------------------------------------------
# NHI 생명주기 / Credential 폐기 확인 연계 — nhi_context (하위 호환 + 신규 규칙)
# ---------------------------------------------------------------------------
def test_omitting_nhi_context_keeps_existing_behavior_identical():
    """nhi_context를 넘기지 않으면(기존 호출부) 결과가 전과 완전히 같아야 한다."""
    decision = AgentAccessEvaluator().evaluate(_profile(), _observation())

    assert decision.outcome is AgentAccessOutcome.ALLOW
    assert decision.findings == []


@pytest.mark.parametrize(
    "status", [NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.DECOMMISSIONED]
)
def test_deactivated_or_decommissioned_nhi_is_denied(status):
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(),
        nhi_context=NHIAccessContext(lifecycle_status=status),
    )

    assert decision.outcome is AgentAccessOutcome.DENY
    finding = next(f for f in decision.findings if f.rule_id == "NHI_LIFECYCLE_NOT_ACTIVE")
    assert finding.blocking is True
    assert status.value in finding.detail


def test_credential_known_revoked_is_denied_even_if_nhi_is_active():
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(),
        nhi_context=NHIAccessContext(
            lifecycle_status=NHILifecycleStatus.ACTIVE,
            credential_known_revoked=True,
        ),
    )

    assert decision.outcome is AgentAccessOutcome.DENY
    rule_ids = {f.rule_id for f in decision.findings}
    assert "CREDENTIAL_KNOWN_REVOKED" in rule_ids
    assert "NHI_LIFECYCLE_NOT_ACTIVE" not in rule_ids  # ACTIVE라 이 규칙은 안 걸림
    revoked_finding = next(f for f in decision.findings if f.rule_id == "CREDENTIAL_KNOWN_REVOKED")
    assert revoked_finding.blocking is True


def test_active_nhi_with_non_revoked_credential_has_no_lifecycle_finding():
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(),
        nhi_context=NHIAccessContext(
            lifecycle_status=NHILifecycleStatus.ACTIVE,
            credential_known_revoked=False,
        ),
    )

    assert decision.outcome is AgentAccessOutcome.ALLOW
    assert decision.findings == []


def test_registered_but_not_yet_active_nhi_is_review_not_deny():
    """등록만 되고 아직 ACTIVE로 전이되지 않은 NHI는 차단이 아니라 검토 사유다."""
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(),
        nhi_context=NHIAccessContext(lifecycle_status=NHILifecycleStatus.REGISTERED),
    )

    assert decision.outcome is AgentAccessOutcome.REVIEW
    finding = next(f for f in decision.findings if f.rule_id == "NHI_LIFECYCLE_PENDING_ACTIVATION")
    assert finding.blocking is False
    assert finding.category == "coverage"


def test_unknown_lifecycle_status_is_review_with_distinct_reason_from_registered():
    """상태 자체를 확인할 수 없는 경우는 REGISTERED와 다른 rule_id로 구분된다."""
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(),
        nhi_context=NHIAccessContext(lifecycle_status=None),
    )

    assert decision.outcome is AgentAccessOutcome.REVIEW
    rule_ids = {f.rule_id for f in decision.findings}
    assert "NHI_LIFECYCLE_UNKNOWN" in rule_ids
    assert "NHI_LIFECYCLE_PENDING_ACTIVATION" not in rule_ids
    finding = next(f for f in decision.findings if f.rule_id == "NHI_LIFECYCLE_UNKNOWN")
    assert finding.blocking is False
    assert finding.category == "coverage"


def test_explicit_empty_context_differs_from_omitted_context():
    """`nhi_context=None`(생략)과 `NHIAccessContext()`(조회했으나 빈 결과)는 다르게 처리된다."""
    omitted = AgentAccessEvaluator().evaluate(_profile(), _observation())
    explicit_empty = AgentAccessEvaluator().evaluate(
        _profile(), _observation(), nhi_context=NHIAccessContext()
    )

    assert omitted.findings == []
    assert any(f.rule_id == "NHI_LIFECYCLE_UNKNOWN" for f in explicit_empty.findings)


def test_deactivated_nhi_and_unapproved_credential_both_reported():
    """lifecycle DENY와 기존 grant 기반 DENY가 동시에 나와도 둘 다 findings에 남는다."""
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(credential_fingerprint="sha256:unexpectedcredential1234567890"),
        nhi_context=NHIAccessContext(lifecycle_status=NHILifecycleStatus.DEACTIVATED),
    )

    assert decision.outcome is AgentAccessOutcome.DENY
    rule_ids = {f.rule_id for f in decision.findings}
    assert {"NHI_LIFECYCLE_NOT_ACTIVE", "UNAPPROVED_CREDENTIAL"} <= rule_ids


def test_lifecycle_rules_appear_in_rule_catalog():
    catalog_ids = {item["rule_id"] for item in AgentAccessEvaluator.rule_catalog()}
    assert {
        "NHI_LIFECYCLE_NOT_ACTIVE",
        "CREDENTIAL_KNOWN_REVOKED",
        "NHI_LIFECYCLE_PENDING_ACTIVATION",
        "NHI_LIFECYCLE_UNKNOWN",
    } <= catalog_ids


# ---------------------------------------------------------------------------
# call_rate_ratio — 서버가 측정한 호출률(usage_rate.py)을 반영한다. 통계적
# 추정이라 항상 REVIEW(blocking=False)이고, 이 신호만으로는 DENY가 되지 않는다.
# ---------------------------------------------------------------------------
def test_omitting_call_rate_ratio_keeps_existing_behavior_identical():
    omitted = AgentAccessEvaluator().evaluate(_profile(), _observation())
    explicit_none = AgentAccessEvaluator().evaluate(
        _profile(), _observation(), call_rate_ratio=None
    )

    assert omitted.findings == explicit_none.findings == []
    assert omitted.outcome is AgentAccessOutcome.ALLOW


def test_call_rate_spike_above_threshold_is_review_not_deny():
    decision = AgentAccessEvaluator().evaluate(
        _profile(), _observation(), call_rate_ratio=8.0
    )

    assert decision.outcome is AgentAccessOutcome.REVIEW
    finding = next(f for f in decision.findings if f.rule_id == "AGENT_CALL_RATE_SPIKE")
    assert finding.blocking is False


def test_call_rate_below_threshold_produces_no_finding():
    decision = AgentAccessEvaluator().evaluate(
        _profile(), _observation(), call_rate_ratio=2.0
    )

    assert decision.outcome is AgentAccessOutcome.ALLOW
    assert decision.findings == []


def test_call_rate_spike_does_not_escalate_a_deny_outcome_to_allow_or_vice_versa():
    """다른 사유로 DENY인 상태에 호출률 급증이 겹쳐도 outcome 은 여전히 DENY다."""
    decision = AgentAccessEvaluator().evaluate(
        _profile(),
        _observation(),
        nhi_context=NHIAccessContext(lifecycle_status=NHILifecycleStatus.DEACTIVATED),
        call_rate_ratio=20.0,
    )

    assert decision.outcome is AgentAccessOutcome.DENY
    rule_ids = {f.rule_id for f in decision.findings}
    assert {"NHI_LIFECYCLE_NOT_ACTIVE", "AGENT_CALL_RATE_SPIKE"} <= rule_ids


def test_call_rate_spike_rule_appears_in_rule_catalog():
    catalog_ids = {item["rule_id"] for item in AgentAccessEvaluator.rule_catalog()}
    assert "AGENT_CALL_RATE_SPIKE" in catalog_ids
