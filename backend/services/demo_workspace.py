"""실제 Credential 없이 대시보드 전체 흐름을 체험하는 합성 workspace."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List

from backend.models.entities import (
    ConnectorRecord,
    ConnectorStatus,
    FindingStatus,
    ProjectRecord,
)
from backend.services.change_control_service import ChangeControlService
from backend.services.control_service import ControlService
from backend.services.nhi_state import load_nhi, save_nhi
from core.action_models import ActionRequest, ActionStatus
from core.config import get_settings
from core.governance_models import (
    ChangeStatus,
    ChangeType,
    ControlEventType,
    LifecycleEvent,
)
from core.models import (
    CodeContext,
    DetectorType,
    ScanResult,
    ScanTrigger,
    SecretFinding,
    Severity,
)
from normalization import observation_from_finding
from storage.base import Storage

DEMO_WORKSPACE_ID = "nhi-sentinel-demo-v1"


def _iso(days_ago: int = 0, *, hours: int = 0) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours)
    ).replace(microsecond=0).isoformat()


PROJECTS = (
    {
        "project_id": "demo-project-payment-api",
        "name": "Demo · Payment API",
        "repository": "nhi-sentinel-demo/payment-api",
        "description": "합성 결제 서비스 — 공개 저장소 Admin Token 노출 사례",
    },
    {
        "project_id": "demo-project-support-automation",
        "name": "Demo · Support Automation",
        "repository": "nhi-sentinel-demo/support-automation",
        "description": "합성 고객지원 Bot — Owner 미지정과 민감 데이터 접근 사례",
    },
    {
        "project_id": "demo-project-ai-assistant",
        "name": "Demo · AI Assistant",
        "repository": "nhi-sentinel-demo/ai-assistant",
        "description": "합성 AI Agent — 장기 미회전 및 공유 Credential 사례",
    },
)


SCENARIOS: tuple[Dict[str, Any], ...] = (
    {
        "key": "public-admin-token",
        "repository": "nhi-sentinel-demo/payment-api",
        "secret_type": "GITHUB_FINE_GRAINED_PAT",
        "provider": "github",
        "masked_value": "github_pat_****7Vq1",
        "file_path": "deploy/production.env",
        "line_number": 8,
        "severity": Severity.CRITICAL,
        "nhi_id": "demo-nhi:payment-deploy-agent",
        "nhi_name": "payment-deploy-agent",
        "nhi_type": "SERVICE_ACCOUNT",
        "owner": "Platform Engineering",
        "linked_ai_agent": "release-orchestrator",
        "environment": "production",
        "permissions": ["READ", "WRITE", "DELETE", "ADMIN"],
        "raw_scopes": ["repo", "delete_repo", "workflow"],
        "risk_score": 96,
        "risk_level": "CRITICAL",
        "risk_reasons": [
            "공개 Repository에 활성 Admin Token 노출",
            "운영 배포 권한과 Repository 삭제 권한 보유",
        ],
        "recommended_action": "TOKEN_REVOCATION",
        "action_type": "TOKEN_REVOCATION",
        "action_target": "github:payment-api deployment token",
        "action_rationale": "공개 저장소에 노출된 활성 Admin Token을 즉시 폐기해야 합니다.",
        "services": ["GitHub"],
        "resources": ["payment-api", "Actions workflows", "deployment environments"],
        "policy_ids": ["ADMIN_SCOPE_RESTRICTED", "ROTATION_PERIOD"],
        "status": FindingStatus.NEEDS_REVIEW,
        "days_ago": 9,
    },
    {
        "key": "ownerless-support-bot",
        "repository": "nhi-sentinel-demo/support-automation",
        "secret_type": "SLACK_BOT_TOKEN",
        "provider": "slack",
        "masked_value": "xoxb-****91Qa",
        "file_path": "bot/settings.py",
        "line_number": 21,
        "severity": Severity.CRITICAL,
        "nhi_id": "demo-nhi:customer-support-bot",
        "nhi_name": "customer-support-bot",
        "nhi_type": "SLACK_BOT",
        "owner": None,
        "linked_ai_agent": "support-triage-agent",
        "environment": "production",
        "permissions": ["READ", "WRITE"],
        "raw_scopes": ["channels:history", "chat:write", "files:read"],
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "risk_reasons": [
            "Owner가 없는 NHI가 고객 대화와 첨부 파일에 접근",
            "운영 Workspace 메시지 작성 권한 보유",
        ],
        "recommended_action": "OWNER_ASSIGNMENT",
        "action_type": "OWNER_ASSIGNMENT",
        "action_target": "slack:customer-support-bot",
        "action_rationale": "민감 고객 데이터에 접근하는 Bot의 책임 Owner를 지정해야 합니다.",
        "services": ["Slack"],
        "resources": ["#customer-support", "#vip-escalations", "uploaded files"],
        "policy_ids": ["OWNER_REQUIRED", "OWNERLESS_SENSITIVE_DATA_ACCESS"],
        "status": FindingStatus.SLA_OVERDUE,
        "days_ago": 7,
    },
    {
        "key": "data-export-key",
        "repository": "nhi-sentinel-demo/payment-api",
        "secret_type": "AWS_ACCESS_KEY_ID",
        "provider": "aws",
        "masked_value": "AKIA****D3M0",
        "file_path": "jobs/export_config.yml",
        "line_number": 14,
        "severity": Severity.HIGH,
        "nhi_id": "demo-nhi:billing-export-service",
        "nhi_name": "billing-export-service",
        "nhi_type": "SERVICE_ACCOUNT",
        "owner": "Data Platform",
        "linked_ai_agent": None,
        "environment": "production",
        "permissions": ["READ", "WRITE"],
        "raw_scopes": ["s3:GetObject", "s3:PutObject"],
        "risk_score": 74,
        "risk_level": "HIGH",
        "risk_reasons": [
            "결제 데이터 Export Bucket 쓰기 권한",
            "만료일이 없는 장기 Credential",
        ],
        "recommended_action": "SCOPE_REDUCTION",
        "action_type": "SCOPE_REDUCTION",
        "action_target": "aws:billing-export-service",
        "action_rationale": "Export 작업에 불필요한 S3 쓰기 권한을 제거해야 합니다.",
        "services": ["AWS S3"],
        "resources": ["billing-prod-export", "customer-ledger"],
        "policy_ids": ["ROTATION_PERIOD"],
        "status": FindingStatus.ASSIGNED,
        "days_ago": 5,
    },
    {
        "key": "shared-automation-token",
        "repository": "nhi-sentinel-demo/ai-assistant",
        "secret_type": "GITHUB_TOKEN",
        "provider": "github",
        "masked_value": "ghp_****SHRD",
        "file_path": ".github/workflows/agent.yml",
        "line_number": 32,
        "severity": Severity.HIGH,
        "nhi_id": "demo-nhi:shared-ci-bot",
        "nhi_name": "shared-ci-bot",
        "nhi_type": "GITHUB_APP",
        "owner": "Developer Experience",
        "linked_ai_agent": "code-review-agent",
        "environment": "production",
        "permissions": ["READ", "WRITE"],
        "raw_scopes": ["contents:write", "pull_requests:write"],
        "risk_score": 79,
        "risk_level": "HIGH",
        "risk_reasons": [
            "하나의 Token이 여러 프로젝트에서 공유됨",
            "AI Agent가 Repository 파일 수정 권한 보유",
        ],
        "recommended_action": "TOKEN_SEPARATION",
        "action_type": "TOKEN_SEPARATION",
        "action_target": "github:shared-ci-bot",
        "action_rationale": "프로젝트별 Credential로 분리하여 Blast Radius를 줄여야 합니다.",
        "services": ["GitHub"],
        "resources": ["ai-assistant", "support-automation", "pull requests"],
        "policy_ids": ["PROJECT_TOKEN_ISOLATION"],
        "status": FindingStatus.RECURRENCE,
        "days_ago": 4,
    },
    {
        "key": "research-agent-key",
        "repository": "nhi-sentinel-demo/ai-assistant",
        "secret_type": "OPENAI_API_KEY",
        "provider": "openai",
        "masked_value": "sk-proj-****DEMO",
        "file_path": "agents/research/settings.toml",
        "line_number": 6,
        "severity": Severity.MEDIUM,
        "nhi_id": "demo-nhi:research-assistant",
        "nhi_name": "research-assistant",
        "nhi_type": "AI_AGENT",
        "owner": "AI Platform",
        "linked_ai_agent": "research-assistant",
        "environment": "development",
        "permissions": ["READ", "WRITE"],
        "raw_scopes": ["responses:write", "files:read"],
        "risk_score": 52,
        "risk_level": "MEDIUM",
        "risk_reasons": [
            "개발 환경에서 실제 사용 중인 장기 API Key",
            "업로드된 내부 문서 접근 가능",
        ],
        "recommended_action": "TOKEN_ROTATION",
        "action_type": "TOKEN_ROTATION",
        "action_target": "openai:research-assistant",
        "action_rationale": "장기 사용된 개발 Credential을 Rotation해야 합니다.",
        "services": ["OpenAI"],
        "resources": ["responses", "vector-store-documents"],
        "policy_ids": ["ROTATION_PERIOD"],
        "status": FindingStatus.TRIAGED,
        "days_ago": 3,
    },
    {
        "key": "staging-webhook",
        "repository": "nhi-sentinel-demo/support-automation",
        "secret_type": "WEBHOOK_SECRET",
        "provider": "generic",
        "masked_value": "whsec_****STG1",
        "file_path": "config/staging.env",
        "line_number": 11,
        "severity": Severity.MEDIUM,
        "nhi_id": "demo-nhi:staging-event-relay",
        "nhi_name": "staging-event-relay",
        "nhi_type": "SERVICE_ACCOUNT",
        "owner": "Customer Platform",
        "linked_ai_agent": None,
        "environment": "staging",
        "permissions": ["WRITE"],
        "raw_scopes": ["events:write"],
        "risk_score": 38,
        "risk_level": "MEDIUM",
        "risk_reasons": ["Staging 이벤트 전달 Secret이 설정 파일에 포함됨"],
        "recommended_action": "ENVIRONMENT_VARIABLE",
        "action_type": None,
        "services": ["Webhook Gateway"],
        "resources": ["staging-events"],
        "policy_ids": [],
        "status": FindingStatus.NEW,
        "days_ago": 2,
    },
    {
        "key": "test-readonly-key",
        "repository": "nhi-sentinel-demo/payment-api",
        "secret_type": "TEST_API_KEY",
        "provider": "generic",
        "masked_value": "test_****READ",
        "file_path": "tests/fixtures/example.env",
        "line_number": 4,
        "severity": Severity.LOW,
        "nhi_id": "demo-nhi:fixture-runner",
        "nhi_name": "fixture-runner",
        "nhi_type": "CI_BOT",
        "owner": "Quality Engineering",
        "linked_ai_agent": None,
        "environment": "test",
        "permissions": ["READ"],
        "raw_scopes": ["fixtures:read"],
        "risk_score": 18,
        "risk_level": "LOW",
        "risk_reasons": ["격리된 테스트 환경의 읽기 전용 예제 Credential"],
        "recommended_action": "MONITOR",
        "action_type": None,
        "services": ["Test API"],
        "resources": ["synthetic-fixtures"],
        "policy_ids": [],
        "status": FindingStatus.RESOLVED,
        "days_ago": 1,
    },
)


def _finding(scenario: Dict[str, Any]) -> SecretFinding:
    return SecretFinding(
        secret_type=scenario["secret_type"],
        provider=scenario["provider"],
        masked_value=scenario["masked_value"],
        fingerprint=f"demo-fingerprint-{scenario['key']}",
        file_path=scenario["file_path"],
        line_number=scenario["line_number"],
        detector=DetectorType.REGEX,
        severity=scenario["severity"],
        context=CodeContext(
            before=["# synthetic demonstration record"],
            line=f"{scenario['secret_type']}={scenario['masked_value']}",
            after=["# no real credential material is stored"],
        ),
        credential_active=scenario["risk_level"] in {"CRITICAL", "HIGH"},
        credential_revoked=False,
        raw_scopes=list(scenario["raw_scopes"]),
        detected_at=_iso(scenario["days_ago"]),
    )


def _advance_finding(
    storage: Storage, finding_id: str, target: FindingStatus
) -> None:
    paths = {
        FindingStatus.TRIAGED: [FindingStatus.TRIAGED],
        FindingStatus.ASSIGNED: [FindingStatus.TRIAGED, FindingStatus.ASSIGNED],
        FindingStatus.NEEDS_REVIEW: [FindingStatus.NEEDS_REVIEW],
        FindingStatus.SLA_OVERDUE: [FindingStatus.SLA_OVERDUE],
        FindingStatus.RECURRENCE: [
            FindingStatus.TRIAGED,
            FindingStatus.ASSIGNED,
            FindingStatus.REMEDIATION_IN_PROGRESS,
            FindingStatus.RESCAN_PENDING,
            FindingStatus.RECURRENCE,
        ],
        FindingStatus.RESOLVED: [
            FindingStatus.TRIAGED,
            FindingStatus.ASSIGNED,
            FindingStatus.REMEDIATION_IN_PROGRESS,
            FindingStatus.RESCAN_PENDING,
            FindingStatus.RESOLVED,
        ],
    }
    for status in paths.get(target, []):
        storage.update_finding_status(
            finding_id,
            status,
            actor="demo-generator",
            note="합성 lifecycle 예시",
            assigned_to=(
                "security-operations"
                if status is FindingStatus.ASSIGNED
                else None
            ),
        )


def _analysis(scenario: Dict[str, Any], finding: SecretFinding) -> Dict[str, Any]:
    return {
        "demo_workspace": DEMO_WORKSPACE_ID,
        "repository": scenario["repository"],
        "fingerprint": finding.fingerprint,
        "masked_value": finding.masked_value,
        "nhi_name": scenario["nhi_name"],
        "nhi_type": scenario["nhi_type"],
        "owner": scenario["owner"],
        "environment": scenario["environment"],
        "permissions": list(scenario["permissions"]),
        "risk_score": scenario["risk_score"],
        "risk_level": scenario["risk_level"],
        "risk_reasons": list(scenario["risk_reasons"]),
        "recommended_action": scenario["recommended_action"],
        "analyzed_at": _iso(scenario["days_ago"], hours=-1),
        "discovery": {
            "nhi_id": scenario["nhi_id"],
            "nhi_name": scenario["nhi_name"],
            "nhi_type": scenario["nhi_type"],
            "secret_name": scenario["secret_type"],
            "linked_ai_agent": scenario["linked_ai_agent"],
            "confidence": 0.96 if scenario["risk_level"] == "CRITICAL" else 0.86,
        },
        "policy": {
            "human_review_required": scenario["risk_level"] in {"CRITICAL", "HIGH"},
            "violations": [
                {"policy_id": policy_id, "message": reason}
                for policy_id, reason in zip(
                    scenario["policy_ids"],
                    scenario["risk_reasons"],
                )
            ],
        },
        "blast_radius": {
            "connected_services": list(scenario["services"]),
            "accessible_resource_count": len(scenario["resources"]),
            "resource_samples": list(scenario["resources"]),
            "can_exfiltrate": "READ" in scenario["permissions"],
            "can_modify": "WRITE" in scenario["permissions"],
            "can_delete": "DELETE" in scenario["permissions"],
            "sensitive_data_access": scenario["risk_level"] in {"CRITICAL", "HIGH"},
        },
    }


# ---------------------------------------------------------------------------
# 거버넌스 시나리오 — 생명주기 5단계 · 승인 대기 변경 · 실시간 통제 이벤트
# ---------------------------------------------------------------------------
#: NHI 별 생명주기 시드. 일수는 "며칠 전" 기준이며 노후화 경보가 자연스럽게 드러나도록 정했다.
LIFECYCLE_SEEDS: Dict[str, Dict[str, Any]] = {
    "demo-nhi:payment-deploy-agent": {  # 사용 — 교체 지연, 곧 노출 이벤트로 격리된다
        "stage": "ACTIVE", "first_seen": 240, "last_used": 0, "last_rotated": 150,
        "known_sources": ["10.20.0.5", "10.20.0.6"],
    },
    "demo-nhi:customer-support-bot": {  # 사용 — Owner 없음, 권한 축소 승인 대기
        "stage": "ACTIVE", "first_seen": 120, "last_used": 0, "last_rotated": 60,
    },
    "demo-nhi:billing-export-service": {  # 권한 변경 — 방금 쓰기 권한 제거(롤백 가능)
        "stage": "ACTIVE", "first_seen": 330, "last_used": 1, "last_rotated": 200,
    },
    "demo-nhi:shared-ci-bot": {  # 사용 — 교체 승인 대기
        "stage": "ACTIVE", "first_seen": 200, "last_used": 0, "last_rotated": 130,
    },
    "demo-nhi:research-assistant": {  # 생성 — 발급 직후
        "stage": "REGISTERED", "first_seen": 2, "last_used": None, "last_rotated": None,
    },
    "demo-nhi:staging-event-relay": {  # 종료 — 폐기 후 보존 기간 초과, 파기 승인 대기
        "stage": "DEACTIVATED", "first_seen": 300, "last_used": 46, "last_rotated": 200,
        "terminated": 45,
    },
    "demo-nhi:fixture-runner": {  # 파기 — Secret material 제거 완료
        "stage": "DECOMMISSIONED", "first_seen": 400, "last_used": 41, "last_rotated": 250,
        "terminated": 40, "disposed": 10,
    },
}


def _seed_lifecycle(storage: Storage) -> None:
    for nhi_id, seed in LIFECYCLE_SEEDS.items():
        nhi = load_nhi(storage, nhi_id)
        stage = seed["stage"]
        first_seen = _iso(seed["first_seen"])
        entered = {
            "REGISTERED": first_seen,
            "ACTIVE": _iso(max(seed["first_seen"] - 1, 0)),
            "DEACTIVATED": _iso(seed.get("terminated", 0)),
            "DECOMMISSIONED": _iso(seed.get("disposed", 0)),
        }[stage]
        nhi.update(
            {
                "lifecycle_stage": stage,
                "credential_state": {
                    "DEACTIVATED": "REVOKED", "DECOMMISSIONED": "DISPOSED"
                }.get(stage, "ACTIVE"),
                "control_state": "NORMAL",
                "credential_version": 1 if stage != "ACTIVE" else 3,
                "first_seen_at": first_seen,
                "created_at": first_seen,
                "stage_entered_at": entered,
                "known_sources": seed.get("known_sources", []),
            }
        )
        for key, source in (("last_used_at", "last_used"), ("last_rotated_at", "last_rotated")):
            if seed.get(source) is not None:
                nhi[key] = _iso(seed[source])
        if seed.get("terminated") is not None:
            nhi["terminated_at"] = _iso(seed["terminated"])
        if seed.get("disposed") is not None:
            nhi["disposed_at"] = _iso(seed["disposed"])
        if stage == "DECOMMISSIONED":
            nhi["permissions"], nhi["raw_scopes"] = [], []
        save_nhi(storage, nhi)

        def log(stage_name: str, event_type: str, days_ago: int, actor: str, **detail: Any):
            event = LifecycleEvent(
                nhi_id=nhi_id, stage=stage_name, event_type=event_type, actor=actor,
                detail=detail, demo_workspace=True,
            )
            event.occurred_at = _iso(days_ago)
            storage.append_lifecycle_event(event)

        log("REGISTERED", "DISCOVERED", seed["first_seen"], "scanner", owner=nhi.get("owner"))
        if stage != "REGISTERED":
            log(
                "ACTIVE", "AUTO_ACTIVATED" if nhi.get("owner") else "STAGE_ADVANCED",
                max(seed["first_seen"] - 1, 0),
                "demo-generator" if nhi.get("owner") else "security-operations",
                reason="활성화 승인",
            )
        if seed.get("last_rotated") and stage == "ACTIVE":
            log("ACTIVE", "TOKEN_ROTATED", seed["last_rotated"], "platform-admin", version=2)
        if seed.get("terminated") is not None:
            log("DEACTIVATED", "TOKEN_REVOKED", seed["terminated"], "security-operations",
                reason="사용처 제거 확인 후 폐기")
        if seed.get("disposed") is not None:
            log("DECOMMISSIONED", "TOKEN_DISPOSED", seed["disposed"], "security-operations",
                secret_material_destroyed=1)


def _seed_governance(storage: Storage) -> Dict[str, int]:
    """실제 서비스 경로(미리보기 · 승인 · 통제 판정)로 시나리오를 만든다."""
    _seed_lifecycle(storage)
    settings = replace(get_settings().governance, control_mode="enforce")
    changes = ChangeControlService(storage, settings=settings)
    control = ControlService(storage, changes=changes, settings=settings)

    # 1) 권한 변경 단계: 쓰기 권한을 제거해 읽기 전용으로 축소 — 롤백 가능
    applied = changes.propose(
        "demo-nhi:billing-export-service", ChangeType.SCOPE_CHANGE,
        requested_by="security-operations",
        reason="Export 작업에는 쓰기 권한이 필요하지 않음",
        params={"target_permissions": ["READ"], "target_scopes": ["s3:GetObject"]},
    )
    changes.approve(
        applied.change_id, actor="platform-admin",
        reason="영향도 확인 완료 — 비업무 시간 적용", acknowledge_impact=True,
    )

    # 2) 승인 대기: 권한 축소(CRITICAL) · Token 교체 · 파기(되돌릴 수 없음)
    changes.propose(
        "demo-nhi:customer-support-bot", ChangeType.SCOPE_CHANGE,
        requested_by="security-operations",
        reason="Owner 미지정 Bot 의 메시지 작성 권한 제거",
        params={
            "target_permissions": ["READ"],
            "target_scopes": ["channels:history", "files:read"],
        },
    )
    changes.propose(
        "demo-nhi:shared-ci-bot", ChangeType.TOKEN_ROTATE,
        requested_by="security-operations",
        reason="130일 미교체 공유 Token — 프로젝트별 Token 으로 분리 전 교체",
        params={"grace_period_hours": 24},
    )
    changes.propose(
        "demo-nhi:staging-event-relay", ChangeType.TOKEN_DISPOSE,
        requested_by="security-operations",
        reason="폐기 후 45일간 장애 없음 — 보존 기간 경과",
    )

    # 3) 실시간 통제: 노출 → 즉시 격리 + 폐기 승인 요청, 권한 초과 반복, 사용량 급증, 종료 Token 사용
    control.evaluate(
        "demo-nhi:payment-deploy-agent", ControlEventType.EXPOSURE_DETECTED,
        {"location": "deploy/production.env:8", "visibility": "public"},
    )
    for _ in range(2):
        control.authorize("demo-nhi:customer-support-bot", "DELETE", resource="#vip-escalations")
    control.evaluate(
        "demo-nhi:shared-ci-bot", ControlEventType.USAGE_SPIKE,
        {"requests_per_min": 310, "baseline_per_min": 52},
    )
    control.authorize("demo-nhi:staging-event-relay", "WRITE", source_ip="203.0.113.77")

    all_changes = storage.list_change_requests(limit=500)
    return {
        "change_count": sum(1 for change in all_changes if change.demo_workspace),
        "pending_change_count": sum(
            1 for change in all_changes
            if change.demo_workspace and change.status is ChangeStatus.PENDING_APPROVAL
        ),
        "control_event_count": len(
            [e for e in storage.list_control_events(limit=500) if e.get("demo_workspace")]
        ),
    }


def seed_demo_workspace(storage: Storage) -> Dict[str, Any]:
    """데모 레코드를 멱등적으로 다시 만들고 생성 결과를 반환한다."""
    storage.clear_demo_workspace(DEMO_WORKSPACE_ID)

    for project_data in PROJECTS:
        project = storage.save_project(
            ProjectRecord(
                project_id=project_data["project_id"],
                name=project_data["name"],
                repository=project_data["repository"],
                description=project_data["description"],
                policy_enabled=True,
                schedule_enabled=True,
                schedule_cron="0 2 * * *",
                metadata={
                    "demo_workspace": DEMO_WORKSPACE_ID,
                    "synthetic": True,
                },
            )
        )
        storage.save_connector(
            ConnectorRecord(
                connector_id=f"demo-connector-{project.project_id}",
                provider="github",
                name="Demo GitHub connector",
                project_id=project.project_id,
                status=ConnectorStatus.CONNECTED,
                last_checked_at=_iso(),
                metadata={
                    "demo_workspace": DEMO_WORKSPACE_ID,
                    "synthetic": True,
                },
            )
        )

    findings_by_key: Dict[str, SecretFinding] = {}
    for project_data in PROJECTS:
        scenarios = [
            item
            for item in SCENARIOS
            if item["repository"] == project_data["repository"]
        ]
        findings = [_finding(item) for item in scenarios]
        findings_by_key.update(
            {scenario["key"]: finding for scenario, finding in zip(scenarios, findings)}
        )
        storage.save_scan_result(
            ScanResult(
                repository=project_data["repository"],
                trigger=ScanTrigger.MANUAL,
                ref="demo/main",
                commit_sha=f"demo-{project_data['project_id']}",
                scanned_files=max(4, len(findings) + 2),
                findings=findings,
                started_at=_iso(1, hours=1),
                finished_at=_iso(1),
            )
        )
        for finding in findings:
            storage.save_observation(
                observation_from_finding(
                    finding,
                    repository=project_data["repository"],
                    source_type="synthetic_demo",
                    source_event_id=f"{DEMO_WORKSPACE_ID}:{finding.fingerprint}",
                )
            )

    action_count = 0
    for scenario in SCENARIOS:
        finding = findings_by_key[scenario["key"]]
        analysis = _analysis(scenario, finding)
        nhi_data = {
            "demo_workspace": DEMO_WORKSPACE_ID,
            "nhi_id": scenario["nhi_id"],
            "nhi_name": scenario["nhi_name"],
            "nhi_type": scenario["nhi_type"],
            "provider": scenario["provider"],
            "identified": True,
            "owner": scenario["owner"],
            "linked_ai_agent": scenario["linked_ai_agent"],
            "confidence": analysis["discovery"]["confidence"],
            "evidence": [
                f"변수명과 경로에서 {scenario['nhi_name']} 연결을 추론",
                "합성 데모 데이터 — 실제 Credential 아님",
            ],
            "environment": scenario["environment"],
            "data_sensitivity": (
                "sensitive"
                if scenario["risk_level"] in {"CRITICAL", "HIGH"}
                else "internal"
            ),
            "permissions": list(scenario["permissions"]),
            "raw_scopes": list(scenario["raw_scopes"]),
            "risk_score": scenario["risk_score"],
            "risk_level": scenario["risk_level"],
            "recommended_action": scenario["recommended_action"],
            "blast_radius": analysis["blast_radius"],
            "analyzed_at": analysis["analyzed_at"],
        }
        storage.upsert_nhi(scenario["nhi_id"], nhi_data)
        storage.bind_credential_to_nhi(
            finding.fingerprint,
            scenario["nhi_id"],
            confidence=analysis["discovery"]["confidence"],
            evidence=nhi_data["evidence"],
        )
        analysis_id = storage.save_analysis(
            analysis,
            repository=scenario["repository"],
            fingerprint=finding.fingerprint,
            input_revision="synthetic-demo-v1",
        )
        storage.update_finding_analysis(
            repository=scenario["repository"],
            fingerprint=finding.fingerprint,
            analysis=analysis,
        )
        finding_record = next(
            item
            for item in storage.list_finding_records(limit=500)
            if item["repository"] == scenario["repository"]
            and item["fingerprint"] == finding.fingerprint
        )
        _advance_finding(storage, finding_record["finding_id"], scenario["status"])

        if scenario["action_type"]:
            storage.create_action(
                ActionRequest(
                    action_id=f"demo-action-{scenario['key']}",
                    analysis_id=analysis_id,
                    credential_fingerprint=finding.fingerprint,
                    action_type=scenario["action_type"],
                    target=scenario["action_target"],
                    rationale=scenario["action_rationale"],
                    risk_level=scenario["risk_level"],
                    requires_approval=True,
                    idempotency_key=f"demo:{DEMO_WORKSPACE_ID}:{scenario['key']}",
                    status=ActionStatus.PENDING_APPROVAL,
                    provider=scenario["provider"],
                    demo_workspace=True,
                )
            )
            action_count += 1

    governance = _seed_governance(storage)

    storage.append_audit_event(
        "DEMO_WORKSPACE_CREATED",
        actor="demo-generator",
        target=DEMO_WORKSPACE_ID,
        detail={
            "demo_workspace": DEMO_WORKSPACE_ID,
            "synthetic": True,
            "project_count": len(PROJECTS),
            "finding_count": len(SCENARIOS),
        },
    )
    return {
        "workspace_id": DEMO_WORKSPACE_ID,
        "synthetic": True,
        "contains_real_secrets": False,
        "project_count": len(PROJECTS),
        "finding_count": len(SCENARIOS),
        "nhi_count": len(SCENARIOS),
        "action_count": action_count,
        **governance,
    }


def clear_demo_workspace(storage: Storage) -> Dict[str, Any]:
    counts = storage.clear_demo_workspace(DEMO_WORKSPACE_ID)
    return {
        "workspace_id": DEMO_WORKSPACE_ID,
        "cleared": True,
        "deleted": counts,
    }
