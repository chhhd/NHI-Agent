"""agents/dry_run_service.py::build_change_preview() — Change Preview 엔진 검증.

실제 Credential/권한을 바꾸지 않고, 조치가 바꾸는 입력만 가정해 같은 정책·
위험도·영향범위 엔진(policy/rules.py, RiskScoringAgent, PolicyEvidenceAgent,
BlastRadiusCalculator)을 재실행하는지 확인한다. calculated/estimated/unknown
구분과 서비스 의존성/영향받을 수 있는 작업 표시도 함께 검증한다.
"""

from __future__ import annotations

from agents.dry_run_service import ACTION_EFFECTS, build_change_preview
from agents.pipeline import NHIAnalysisPipeline
from core.nhi_models import AnalysisSignals, ImpactConfidence, RecommendedAction, RiskLevel
from tests.test_nhi_agents import make_finding


def _analyze(**signal_overrides):
    finding = make_finding(
        file_path="config/production/support_bot.env",
        raw_scopes=["channels:history", "chat:write", "admin.users:write"],
        credential_active=True,
        credential_revoked=False,
        resources=[{"name": "general"}, {"name": "incident-response"}],
    )
    signals = AnalysisSignals(repository="acme/support", repository_public=True, **signal_overrides)
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    return analysis.to_dict()


def test_all_recommended_actions_have_a_defined_effect():
    """새 조치 유형이 추가되면 이 테스트가 깨져 ACTION_EFFECTS 갱신을 강제한다."""
    for action in RecommendedAction:
        assert action in ACTION_EFFECTS, action


def test_missing_replay_snapshot_is_not_applicable():
    """이 기능 도입 이전에 저장된 분석(재현 입력 없음)은 안전하게 처리된다."""
    snapshot = _analyze()
    snapshot["replay_snapshot"] = {"signals": {}, "finding": {}}

    preview = build_change_preview("nhi:legacy", snapshot)

    assert preview.applicable is False
    assert preview.not_applicable_reason
    assert preview.unknown_notes


def test_token_revocation_recomputes_lower_risk_and_resolves_credential_violations():
    """폐기 시 신뢰 가능한 입력만으로 실제 정책/위험도 엔진을 재실행해 점수가 낮아진다."""
    snapshot = _analyze()
    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value

    preview = build_change_preview("nhi:revoke", snapshot)

    assert preview.applicable is True
    assert preview.risk_after.score < preview.risk_before.score
    assert "NO_PLAINTEXT_CREDENTIAL" in preview.resolved_violations
    # 폐기해도 과도한 ADMIN scope 자체가 사라지는 것은 아니므로 해당 위반은 유지된다.
    assert "ADMIN_SCOPE_RESTRICTED" in preview.unchanged_violations
    assert preview.risk_after.forced_critical is False


def test_token_rotation_keeps_permissions_but_resets_age():
    """회전은 동일 권한을 유지한 채 수명만 초기화한다 — Rotation 위반만 해소된다."""
    snapshot = _analyze(last_rotated_at="2020-01-01T00:00:00Z", created_at="2020-01-01T00:00:00Z")
    snapshot["recommended_action"] = RecommendedAction.TOKEN_ROTATION.value

    preview = build_change_preview("nhi:rotate", snapshot)

    assert preview.permissions_before.permissions == preview.permissions_after.permissions
    assert "ROTATION_PERIOD" in preview.resolved_violations
    # 공개 저장소 + 활성 Admin Token은 회전 후에도 그대로이므로 강제 Critical이 유지된다.
    assert preview.risk_after.forced_critical is True


def test_scope_reduction_drops_admin_and_delete_permissions():
    snapshot = _analyze()
    snapshot["recommended_action"] = RecommendedAction.SCOPE_REDUCTION.value

    preview = build_change_preview("nhi:scope", snapshot)

    from core.nhi_models import PermissionLevel

    assert PermissionLevel.ADMIN not in preview.permissions_after.permissions
    assert "ADMIN_SCOPE_RESTRICTED" in preview.resolved_violations
    assert preview.risk_after.score < preview.risk_before.score


def test_assign_owner_resolves_owner_required_but_flags_as_pending():
    snapshot = _analyze()  # owner는 선언되지 않음 -> None
    assert snapshot["owner"] is None
    snapshot["recommended_action"] = RecommendedAction.ASSIGN_OWNER.value

    preview = build_change_preview("nhi:owner", snapshot)

    assert "OWNER_REQUIRED" in preview.resolved_violations
    assert preview.risk_after.score <= preview.risk_before.score


def test_split_token_per_project_clears_shared_projects():
    snapshot = _analyze(shared_projects=["acme/support", "acme/billing"])
    snapshot["recommended_action"] = RecommendedAction.SPLIT_TOKEN_PER_PROJECT.value

    preview = build_change_preview("nhi:split", snapshot)

    assert preview.blast_radius_after.cross_project_impact is False
    assert "PROJECT_TOKEN_ISOLATION" in preview.resolved_violations


def test_monitor_action_leaves_state_unchanged():
    snapshot = _analyze()
    snapshot["recommended_action"] = RecommendedAction.MONITOR.value

    preview = build_change_preview("nhi:monitor", snapshot)

    assert preview.applicable is True
    assert preview.risk_before.score == preview.risk_after.score
    assert preview.resolved_violations == []
    assert preview.new_violations == []


def test_unrecognized_action_string_falls_back_to_monitor_without_raising():
    """`RecommendedAction`에 없는 값이 와도 예외 없이 MONITOR(관찰, 무변화)로 안전하게 처리한다."""
    snapshot = _analyze()
    snapshot["recommended_action"] = "SOME_FUTURE_ACTION"

    preview = build_change_preview("nhi:future", snapshot)

    assert preview.action == RecommendedAction.MONITOR
    assert preview.applicable is True
    assert preview.risk_before.score == preview.risk_after.score


def test_service_dependency_impact_is_calculated_when_access_not_reduced():
    snapshot = _analyze()
    snapshot["recommended_action"] = RecommendedAction.ASSIGN_OWNER.value

    preview = build_change_preview("nhi:dep-calculated", snapshot)

    assert preview.service_dependency_impact
    assert all(
        item.confidence is ImpactConfidence.CALCULATED
        for item in preview.service_dependency_impact
    )


def test_service_dependency_impact_is_unknown_when_usage_not_confirmed():
    """사용 여부(in_use)가 확인되지 않으면 영향도를 단정하지 않고 unknown으로 둔다."""
    finding = make_finding(
        file_path="scripts/misc/support_bot.env",  # 경로상 운영 사용 신호 없음
        raw_scopes=["channels:history"],
    )
    signals = AnalysisSignals(repository="acme/support")
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot = analysis.to_dict()
    assert snapshot["context_analysis"]["in_use"] is None
    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value

    preview = build_change_preview("nhi:dep-unknown", snapshot)

    assert preview.service_dependency_impact
    assert all(
        item.confidence is ImpactConfidence.UNKNOWN
        for item in preview.service_dependency_impact
    )


def test_affected_operations_flags_linked_ai_agent_as_unknown():
    finding = make_finding(credential_active=True, raw_scopes=["channels:history"])
    signals = AnalysisSignals(repository="acme/support", agent_name="support-triage-agent")
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot = analysis.to_dict()
    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value

    preview = build_change_preview("nhi:ops", snapshot)

    agent_items = [
        item for item in preview.affected_operations if "Agent" in item.name
    ]
    if snapshot["discovery"].get("linked_ai_agent"):
        assert agent_items
        assert agent_items[0].confidence is ImpactConfidence.UNKNOWN


def test_result_distinguishes_calculated_estimated_unknown_notes():
    snapshot = _analyze()
    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value

    preview = build_change_preview("nhi:notes", snapshot)

    assert preview.calculated_notes
    assert preview.estimated_notes
    assert preview.unknown_notes


def test_to_dict_never_contains_raw_secret_from_original_finding():
    """재현 입력에서 복원한 finding/signals를 직렬화해도 원문 Secret은 없다."""
    snapshot = _analyze(request_user_agent="curl Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value

    preview = build_change_preview("nhi:secret-check", snapshot)
    import json

    serialized = json.dumps(preview.to_dict(), ensure_ascii=False)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in serialized


# ---------------------------------------------------------------------------
# 회귀 — replay_snapshot 필드명 마스킹 버그 수정 후, 보안 신호가 Change
# Preview 재계산에서도 원래 분석과 동일하게 반영되는지 확인한다.
# (`token_used_after_revocation`/`token_replay_suspected`는 필드명이 20자
# 이상이라 과거엔 저장 시 키 자체가 마스킹돼 재구성에서 조용히 사라졌다.)
# ---------------------------------------------------------------------------
def test_token_replay_suspected_signal_survives_reconstruction_and_matches_original():
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        repository="acme/support",
        owner="platform-team",
        token_replay_suspected=True,
        token_binding_method="DPoP",
        request_source_ip="203.0.113.5",
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    assert analysis.risk.forced_critical is True
    assert "TOKEN_REPLAY_SUSPECTED" in {r["rule_id"] for r in analysis.risk.forced_rules}

    snapshot = analysis.to_dict()
    snapshot["recommended_action"] = RecommendedAction.MONITOR.value  # no-op — before == after

    preview = build_change_preview("nhi:replay-check", snapshot)

    assert preview.applicable is True
    for assessment in (preview.risk_before, preview.risk_after):
        assert assessment.forced_critical is True
        assert "TOKEN_REPLAY_SUSPECTED" in {r["rule_id"] for r in assessment.forced_rules}
        assert assessment.score == analysis.risk.score


def test_revoked_token_still_used_signal_survives_reconstruction_and_matches_original():
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        repository="acme/support",
        owner="platform-team",
        token_used_after_revocation=True,
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    assert analysis.risk.forced_critical is True
    assert "REVOKED_TOKEN_STILL_USED" in {r["rule_id"] for r in analysis.risk.forced_rules}

    snapshot = analysis.to_dict()
    snapshot["recommended_action"] = RecommendedAction.MONITOR.value

    preview = build_change_preview("nhi:revoked-still-used-check", snapshot)

    assert preview.applicable is True
    assert preview.risk_before.forced_critical is True
    assert "REVOKED_TOKEN_STILL_USED" in {r["rule_id"] for r in preview.risk_before.forced_rules}
    assert preview.risk_before.score == analysis.risk.score


def test_declared_permissions_signal_survives_reconstruction():
    """`declared_permissions`(20자) 필드명도 마스킹되지 않고 복원돼야 한다."""
    finding = make_finding(credential_active=True, raw_scopes=["channels:history"])
    signals = AnalysisSignals(
        repository="acme/support",
        owner="platform-team",
        declared_permissions=["READ"],
        observed_actions=["chat:write"],
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot = analysis.to_dict()
    assert snapshot["replay_snapshot"]["signals"]["declared_permissions"] == ["READ"]

    snapshot["recommended_action"] = RecommendedAction.MONITOR.value
    preview = build_change_preview("nhi:declared-permissions-check", snapshot)

    assert preview.applicable is True


def test_terminated_agent_forced_critical_is_resolved_by_token_revocation_simulation():
    """신호가 `is_active`에 의존하는 강제 Critical(TERMINATED_AGENT_ACTIVE_TOKEN)은
    TOKEN_REVOCATION 가정(credential_active=False)으로 실제로 해소돼야 한다
    — 신호가 올바르게 재현되고 있다는 것을 '해소되는 사례'로도 확인한다."""
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        repository="acme/support",
        owner="platform-team",
        agent_status="terminated",
        agent_name="demo-agent",
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    assert "TERMINATED_AGENT_ACTIVE_TOKEN" in {r["rule_id"] for r in analysis.risk.forced_rules}

    snapshot = analysis.to_dict()
    snapshot["recommended_action"] = RecommendedAction.TOKEN_REVOCATION.value
    preview = build_change_preview("nhi:terminated-agent-check", snapshot)

    assert "TERMINATED_AGENT_ACTIVE_TOKEN" in {r["rule_id"] for r in preview.risk_before.forced_rules}
    assert "TERMINATED_AGENT_ACTIVE_TOKEN" not in {r["rule_id"] for r in preview.risk_after.forced_rules}
    assert preview.risk_after.score < preview.risk_before.score


def test_legacy_snapshot_with_pre_fix_masked_key_does_not_crash():
    """이 수정 이전에 저장된 분석은 `token_used_after_revocation`이
    `"****-tion"` 같은 마스킹된 키로 남아있을 수 있다. 되살릴 수는 없지만
    (손실된 데이터), 예외 없이 안전하게 '미확인'으로 처리돼야 한다 — 기존
    데이터와의 호환성."""
    finding = make_finding(credential_active=True)
    analysis = NHIAnalysisPipeline().analyze_finding(
        finding, signals=AnalysisSignals(repository="acme/support", owner="platform-team")
    )
    snapshot = analysis.to_dict()
    # 과거 버그를 흉내낸다 — 실제 필드명 대신 마스킹된 키가 저장된 상태.
    snapshot["replay_snapshot"]["signals"].pop("token_used_after_revocation", None)
    snapshot["replay_snapshot"]["signals"]["****-tion"] = True
    snapshot["recommended_action"] = RecommendedAction.MONITOR.value

    preview = build_change_preview("nhi:legacy-masked-key", snapshot)

    assert preview.applicable is True  # 예외 없이 처리됨
    assert preview.risk_before.forced_critical is False  # 손실된 신호는 복구되지 않음(기대된 한계)
