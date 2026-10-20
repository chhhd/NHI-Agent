"""Usage → Event → Scenario 파이프라인과 사용자 고유 규칙(IAM 상승 등)의 통합 테스트."""

from __future__ import annotations

from agents.pipeline import NHIAnalysisPipeline
from normalization.usage_ingestion import signals_from_usage_events as _signals_from_usage_events
from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
from core.nhi_models import Environment, SecurityEventType

NOW = "2026-01-10T00:00:00+00:00"


def nhi(**overrides) -> GitHubNHIInput:
    values = dict(
        nhi_id="app-1",
        nhi_name="deploy-app",
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner="platform",
        environment=Environment.STAGING,
        raw_permissions={"contents": "read"},
        repositories=[RepositoryInfo(name="acme/backend", visibility="private")],
        last_used_at="2026-01-09T00:00:00+00:00",
    )
    values.update(overrides)
    return GitHubNHIInput(**values)


def analyze(signals=None, **overrides):
    return NHIAnalysisPipeline().analyze_github_nhi(nhi(**overrides), signals=signals)


def test_output_carries_usage_events_and_scenarios():
    result = analyze({"observed_actions": ["contents:write"]}).to_dict()
    assert result["usage_analysis"]["permission_comparison_complete"] is True
    assert result["usage_analysis"]["unexpected_permissions"] == ["WRITE"]
    types = {event["event_type"] for event in result["security_events"]}
    assert "UNDECLARED_PERMISSION_USE" in types
    ids = {match["scenario_id"] for match in result["scenario_matches"]}
    assert "READ_ONLY_NHI_PERFORMS_MUTATION" in ids
    # 시나리오와 강제 Critical 규칙은 같은 판정에서 나온다
    forced = {rule["rule_id"] for rule in result["risk_detail"]["forced_rules"]}
    assert "READ_ONLY_NHI_PERFORMS_MUTATION" in forced


def test_iam_escalation_rule_unique_to_this_project_still_fires_and_maps_to_a_scenario():
    result = analyze({"observed_actions": ["iam:AttachUserPolicy"]}).to_dict()
    forced = {rule["rule_id"] for rule in result["risk_detail"]["forced_rules"]}
    assert "IAM_PRIVILEGE_SELF_ESCALATION" in forced
    matches = {m["scenario_id"]: m for m in result["scenario_matches"]}
    assert matches["IAM_PRIVILEGE_SELF_ESCALATION"]["forced_critical"] is True
    assert result["risk_level"] == "CRITICAL"


def test_governance_lifecycle_timestamps_survive_the_new_pipeline():
    analysis = analyze({"observed_actions": ["contents:read"]})
    assert analysis.lifecycle_timestamps["last_used_at"] == "2026-01-09T00:00:00+00:00"


def test_unused_permissions_require_complete_usage_history():
    wide = dict(raw_permissions={"contents": "read", "administration": "write"})
    partial = analyze({"observed_actions": ["contents:read"]}, **wide).usage_analysis
    assert partial.unused_permissions == []

    complete = analyze(
        {"observed_actions": ["contents:read"], "extra": {"usage_data_complete": True}},
        **wide,
    ).usage_analysis
    assert any(p.value == "ADMIN" for p in complete.unused_permissions)


def test_no_usage_logs_is_not_treated_as_clean():
    usage = analyze().usage_analysis
    assert usage.data_complete is False
    assert any("이상 없음으로 간주하지 않음" in line or "미확인" in line for line in usage.evidence)


def test_use_after_revocation_is_a_forced_critical_scenario():
    result = analyze({"token_used_after_revocation": True})
    assert result.usage_analysis.used_after_revocation is True
    event = next(
        e for e in result.security_events
        if e.event_type is SecurityEventType.REVOKED_CREDENTIAL_USE
    )
    assert event.origin == "observed"
    assert "REVOKED_TOKEN_STILL_USED" in {m.scenario_id for m in result.scenario_matches}
    assert result.risk.level.value == "CRITICAL"


def test_inventory_path_does_not_infer_revocation_from_timestamps_alone():
    # 인벤토리 입력은 credential_revoked 를 알지 못하므로 시각 순서만으로 단정하지 않는다.
    signals = {"revoked_at": "2026-01-05T00:00:00+00:00", "last_used_at": "2026-01-08T00:00:00+00:00"}
    result = analyze(signals, active=False)
    assert result.usage_analysis.used_after_revocation is None


def test_replay_signal_forces_critical_and_recommends_revocation():
    result = analyze({"token_replay_suspected": True, "token_binding_method": "DPoP"})
    forced = {rule["rule_id"] for rule in result.risk.to_dict()["forced_rules"]}
    assert "TOKEN_REPLAY_SUSPECTED" in forced
    assert result.recommended_action.value == "TOKEN_REVOCATION"


# ------------------------------------------------------------ 감사 로그 정규화
def test_parse_failure_downgrades_requested_complete_flag():
    records = [
        {"principal_id": "app-1", "action": "contents:read", "occurred_at": NOW},
        {"principal_id": "app-1", "action": "contents:read"},  # 시각 누락 → 파싱 실패
    ]
    signals, summary = _signals_from_usage_events(
        nhi_id="app-1",
        provider="github",
        raw_signals=None,
        records=records,
        data_complete=True,
        source="audit_log",
    )
    assert summary["invalid_event_count"] == 1
    assert summary["requested_data_complete"] is True
    assert summary["effective_data_complete"] is False
    assert signals["extra"]["usage_data_complete"] is False


def test_duplicate_events_are_dropped_and_other_principals_ignored():
    record = {"event_id": "e1", "principal_id": "app-1", "action": "contents:read", "occurred_at": NOW}
    other = {"event_id": "e2", "principal_id": "someone-else", "action": "contents:write", "occurred_at": NOW}
    signals, summary = _signals_from_usage_events(
        nhi_id="app-1",
        provider="github",
        raw_signals=None,
        records=[record, dict(record), other],
        data_complete=True,
        source="audit_log",
    )
    assert summary["duplicate_event_count"] == 1
    assert summary["matched_event_count"] == 1
    assert signals["observed_actions"] == ["contents:read"]


def test_secret_in_audit_action_is_redacted_before_analysis():
    leaked = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    signals, _ = _signals_from_usage_events(
        nhi_id="app-1",
        provider="github",
        raw_signals=None,
        records=[
            {
                "principal_id": "app-1",
                "action": f"GET /repos?access_token={leaked}",
                "occurred_at": NOW,
            }
        ],
        data_complete=False,
        source="audit_log",
    )
    assert leaked not in str(signals)
