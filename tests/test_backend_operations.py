"""Backend 엔티티·Finding lifecycle·Dashboard 집계 테스트."""

from __future__ import annotations

import pytest

from backend.models.entities import ConnectorRecord, FindingStatus, ProjectRecord
from backend.database import PostgresDatabase
from backend.services.demo_workspace import (
    DEMO_WORKSPACE_ID,
    clear_demo_workspace,
    seed_demo_workspace,
)
from core.models import ScanTarget
from policy.rules import FORCED_CRITICAL_RULES
from scanner.scan_service import SecretScanService
from storage.sqlite_store import SQLiteStorage

TOKEN = "xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d"


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def _scan():
    return SecretScanService().scan_targets(
        [ScanTarget(path="config/slack.env", content=f"SLACK_TOKEN={TOKEN}")],
        repository="acme/support",
    )


def test_project_connector_and_coverage(store):
    project = store.save_project(
        ProjectRecord(name="Support automation", repository="acme/support")
    )
    store.save_connector(
        ConnectorRecord(
            provider="github",
            name="GitHub production",
            project_id=project.project_id,
        )
    )
    store.save_scan_result(_scan())

    coverage = store.get_project(project.project_id)
    assert coverage is not None
    assert coverage["finding_count"] == 1
    assert coverage["last_scan_status"] == "SUCCEEDED"
    assert coverage["connector_status"] == "CONFIGURED"


def test_finding_lifecycle_and_history(store):
    store.save_project(ProjectRecord(name="Support", repository="acme/support"))
    store.save_scan_result(_scan())
    finding = store.list_finding_records()[0]

    triaged = store.update_finding_status(
        finding["finding_id"],
        FindingStatus.TRIAGED,
        actor="security@example.com",
        note="실제 운영 Token 확인",
    )
    assigned = store.update_finding_status(
        finding["finding_id"],
        FindingStatus.ASSIGNED,
        actor="security@example.com",
        assigned_to="platform-team",
    )

    assert triaged["status"] == "TRIAGED"
    assert assigned["status"] == "ASSIGNED"
    assert assigned["assigned_to"] == "platform-team"
    assert [item["to_status"] for item in assigned["status_history"]] == [
        "NEW",
        "TRIAGED",
        "ASSIGNED",
    ]

    with pytest.raises(ValueError):
        store.update_finding_status(
            finding["finding_id"],
            FindingStatus.RESOLVED,
            actor="security@example.com",
        )


def test_dashboard_summary_uses_persisted_findings(store):
    store.save_project(ProjectRecord(name="Support", repository="acme/support"))
    store.save_scan_result(_scan())
    finding = store.list_finding_records()[0]
    store.update_finding_analysis(
        repository="acme/support",
        fingerprint=finding["fingerprint"],
        analysis={
            "nhi_name": "support-bot",
            "owner": None,
            "risk_score": 86,
            "risk_level": "CRITICAL",
            "discovery": {"nhi_id": "slack:B01"},
        },
    )

    summary = store.dashboard_summary()
    assert summary["project_count"] == 1
    assert summary["credential_count"] == 1
    assert summary["critical_high_findings"] == 1
    assert summary["new_findings"] == 1


def test_demo_workspace_is_synthetic_idempotent_and_isolated(store):
    first = seed_demo_workspace(store)
    second = seed_demo_workspace(store)

    assert first["contains_real_secrets"] is False
    assert second["project_count"] == 3
    assert second["finding_count"] == 7
    assert second["nhi_count"] == 7
    assert second["action_count"] == 5

    projects = store.list_projects()
    findings = store.list_finding_records(limit=100)
    actions = store.list_actions(limit=100)
    analyses = store.list_analyses(limit=100)
    assert all(
        item["metadata"]["demo_workspace"] == DEMO_WORKSPACE_ID
        for item in projects
    )
    assert {item["risk_level"] for item in findings} == {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    }
    assert all("****" in item["masked_value"] for item in findings)
    assert all(action.demo_workspace for action in actions)
    assert store.dashboard_summary()["critical_high_findings"] == 4

    # 합성 데이터도 운영 NHIAnalysis와 같은 Decision Flow 스키마를 제공한다.
    assert len(analyses) == 7
    required = {
        "permission_detail",
        "usage_analysis",
        "security_events",
        "scenario_matches",
        "risk_detail",
        "recommendations",
    }
    assert all(required <= set(analysis) for analysis in analyses)
    assert {analysis["usage_analysis"]["data_complete"] for analysis in analyses} == {
        True,
        False,
    }
    for analysis in analyses:
        assert analysis["permission_detail"]["permissions"] == analysis["permissions"]
        assert len(analysis["risk_detail"]["factors"]) == 7
        assert sum(
            factor["score"] for factor in analysis["risk_detail"]["factors"]
        ) == analysis["risk_detail"]["base_score"]
        assert analysis["recommendations"][0]["action"] == analysis["recommended_action"]

    forced_ids = {
        rule["rule_id"]
        for analysis in analyses
        for rule in analysis["risk_detail"]["forced_rules"]
    }
    assert forced_ids == {
        "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN",
        "OWNERLESS_SENSITIVE_DATA_ACCESS",
        "TOKEN_SHARED_ACROSS_PROJECTS",
    }
    assert forced_ids <= set(FORCED_CRITICAL_RULES)

    shared = next(
        analysis
        for analysis in analyses
        if analysis["fingerprint"] == "demo-fingerprint-shared-automation-token"
    )
    assert shared["risk_level"] == "CRITICAL"
    assert shared["risk_score"] >= 80
    assert shared["scenario_matches"][0]["event_ids"] == [
        shared["security_events"][0]["event_id"]
    ]

    staging = next(
        analysis
        for analysis in analyses
        if analysis["fingerprint"] == "demo-fingerprint-staging-webhook"
    )
    assert staging["usage_analysis"]["data_complete"] is False
    assert staging["usage_analysis"]["usage_observed"] is None
    assert staging["security_events"] == []
    assert staging["scenario_matches"] == []

    cleared = clear_demo_workspace(store)
    assert cleared["deleted"]["projects"] == 3
    assert cleared["deleted"]["findings"] == 7
    assert store.list_projects() == []
    assert store.list_finding_records() == []
    assert store.list_nhi_records() == []
    assert store.list_actions() == []


def test_postgres_schema_covers_operational_entities():
    database = PostgresDatabase(
        "postgresql://nhi_agent:secret@localhost:5432/nhi_agent"
    )
    schema_path = __import__("pathlib").Path(
        "backend/database/postgres_schema.sql"
    )
    schema = schema_path.read_text(encoding="utf-8")
    for table in (
        "projects",
        "connectors",
        "scan_runs",
        "findings",
        "credentials",
        "nhi",
        "risk_assessments",
        "approval_requests",
        "remediation_actions",
        "verification_results",
        "audit_events",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in schema
    assert database.database_url.startswith("postgresql://")
