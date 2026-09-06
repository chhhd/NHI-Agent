from core.nhi_models import (
    ContextInsight,
    NHIAnalysis,
    NHIProfile,
    PermissionLevel,
    PermissionProfile,
    PolicyEvaluation,
    RecommendedAction,
    RiskAssessment,
    RiskLevel,
    ScenarioMatch,
    SecurityEvent,
    UsageAnalysisResult,
)


def test_usage_and_event_models_serialize_reused_enums():
    usage = UsageAnalysisResult(
        granted_permissions=[PermissionLevel.READ, PermissionLevel.WRITE],
        used_permissions=[PermissionLevel.READ],
        unused_permissions=[PermissionLevel.WRITE],
        days_since_last_used=3,
        usage_status="partially_used",
        excessive_permission=True,
        evidence=["audit log"],
    )
    event = SecurityEvent(
        event_id="event-1",
        nhi_id="nhi-1",
        event_type="resource_access",
        resource_type="repository",
        access_level=PermissionLevel.WRITE,
        event_risk=RiskLevel.HIGH,
        evidence=["audit log"],
    )
    scenario = ScenarioMatch(
        scenario_id="scenario-1",
        scenario_name="excessive write access",
        severity=RiskLevel.HIGH,
        matched_events=[event.event_id],
        matched_reason="unused write permission",
        risk_addition=10,
        recommended_action=RecommendedAction.SCOPE_REDUCTION,
    )

    assert usage.to_dict()["granted_permissions"] == ["READ", "WRITE"]
    assert event.to_dict()["event_risk"] == "HIGH"
    assert scenario.to_dict()["recommended_action"] == "SCOPE_REDUCTION"


def test_nhi_analysis_new_fields_are_backward_compatible():
    analysis = NHIAnalysis(
        fingerprint="fp",
        repository="repo",
        file_path="config.env",
        line_number=1,
        masked_value="***",
        profile=NHIProfile(nhi_id="nhi-1", nhi_name="bot"),
        context=ContextInsight(),
        permissions=PermissionProfile(),
        risk=RiskAssessment(),
        policy=PolicyEvaluation(),
    )

    assert isinstance(analysis.usage_analysis, UsageAnalysisResult)
    assert analysis.events == []
    assert analysis.scenario_matches == []
    assert analysis.to_dict()["events"] == []
