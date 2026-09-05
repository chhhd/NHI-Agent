"""실제 Credential 없이 대시보드 전체 흐름을 체험하는 합성 workspace."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List

from backend.models.entities import (
    ConnectorRecord,
    ConnectorStatus,
    FindingStatus,
    ProjectRecord,
)
from core.action_models import ActionRequest, ActionStatus
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


# 합성 분석도 운영 파이프라인의 직렬화 스키마를 그대로 따른다. 화면에서
# Permission -> Usage -> Event -> Scenario -> Risk/Action 흐름을 즉시 확인할 수
# 있도록 각 데모 사례에 안전한 메타데이터만 제공한다.
_DEMO_USAGE: Dict[str, Dict[str, Any]] = {
    "public-admin-token": {
        "actions": ["contents:write", "workflow:dispatch"],
        "permissions": ["WRITE"],
        "complete": True,
        "last_used_offset_days": 0,
    },
    "ownerless-support-bot": {
        "actions": ["channels:history", "chat:write"],
        "permissions": ["READ", "WRITE"],
        "complete": True,
        "last_used_offset_days": 0,
    },
    "data-export-key": {
        "actions": ["s3:GetObject"],
        "permissions": ["READ"],
        "complete": False,
        "last_used_offset_days": 1,
    },
    "shared-automation-token": {
        "actions": ["contents:write", "pull_requests:write"],
        "permissions": ["WRITE"],
        "complete": True,
        "last_used_offset_days": 0,
    },
    "research-agent-key": {
        "actions": ["responses:write", "files:read"],
        "permissions": ["READ", "WRITE"],
        "complete": False,
        "last_used_offset_days": 0,
    },
    "staging-webhook": {
        "actions": [],
        "permissions": [],
        "complete": False,
        "last_used_offset_days": None,
    },
    "test-readonly-key": {
        "actions": ["fixtures:read"],
        "permissions": ["READ"],
        "complete": True,
        "last_used_offset_days": 0,
    },
}

_FORCED_SCENARIOS: Dict[str, Dict[str, str]] = {
    "public-admin-token": {
        "scenario_id": "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN",
        "name": "공개 저장소의 활성 Admin Token",
        "reason": "공개 Repository 에 활성 Admin Token 노출",
    },
    "ownerless-support-bot": {
        "scenario_id": "OWNERLESS_SENSITIVE_DATA_ACCESS",
        "name": "Owner 없는 민감 데이터 접근",
        "reason": "Owner 가 없는 NHI 가 confidential 데이터에 접근",
    },
    "shared-automation-token": {
        "scenario_id": "TOKEN_SHARED_ACROSS_PROJECTS",
        "name": "프로젝트 간 Token 공유",
        "reason": (
            "하나의 Token 이 여러 프로젝트에서 공유됨: "
            "nhi-sentinel-demo/ai-assistant, nhi-sentinel-demo/support-automation"
        ),
    },
}

_RISK_FACTOR_MAX = {
    "exposure_location": 20,
    "api_permission": 20,
    "environment_data": 15,
    "credential_state": 15,
    "usage_anomaly": 15,
    "ownership_policy": 10,
    "connected_service_impact": 5,
}

_RISK_FACTOR_LABEL = {
    "exposure_location": "노출 위치",
    "api_permission": "API 권한 수준",
    "environment_data": "운영 환경 및 데이터 중요도",
    "credential_state": "Credential 상태",
    "usage_anomaly": "사용 및 이상행위",
    "ownership_policy": "Owner·정책 관리 상태",
    "connected_service_impact": "연결 서비스 영향 범위",
}

_DEMO_FACTOR_SCORES: Dict[str, Dict[str, int]] = {
    "public-admin-token": {
        "exposure_location": 20, "api_permission": 20,
        "environment_data": 15, "credential_state": 14,
        "usage_anomaly": 13, "ownership_policy": 9,
        "connected_service_impact": 5,
    },
    "ownerless-support-bot": {
        "exposure_location": 20, "api_permission": 12,
        "environment_data": 15, "credential_state": 13,
        "usage_anomaly": 13, "ownership_policy": 10,
        "connected_service_impact": 5,
    },
    "data-export-key": {
        "exposure_location": 16, "api_permission": 12,
        "environment_data": 15, "credential_state": 14,
        "usage_anomaly": 8, "ownership_policy": 5,
        "connected_service_impact": 4,
    },
    # TOKEN_SHARED_ACROSS_PROJECTS는 canonical forced-Critical 규칙이므로
    # 기존 79점보다 1점 높은 최소 Critical 점수로 표현한다.
    "shared-automation-token": {
        "exposure_location": 19, "api_permission": 12,
        "environment_data": 15, "credential_state": 13,
        "usage_anomaly": 11, "ownership_policy": 6,
        "connected_service_impact": 4,
    },
    "research-agent-key": {
        "exposure_location": 12, "api_permission": 12,
        "environment_data": 5, "credential_state": 10,
        "usage_anomaly": 7, "ownership_policy": 3,
        "connected_service_impact": 3,
    },
    "staging-webhook": {
        "exposure_location": 10, "api_permission": 12,
        "environment_data": 6, "credential_state": 5,
        "usage_anomaly": 2, "ownership_policy": 2,
        "connected_service_impact": 1,
    },
    "test-readonly-key": {
        "exposure_location": 4, "api_permission": 6,
        "environment_data": 1, "credential_state": 2,
        "usage_anomaly": 4, "ownership_policy": 0,
        "connected_service_impact": 1,
    },
}

_ACTION_MAP = {
    "OWNER_ASSIGNMENT": "ASSIGN_OWNER",
    "TOKEN_SEPARATION": "SPLIT_TOKEN_PER_PROJECT",
    "ENVIRONMENT_VARIABLE": "MOVE_TO_ENV_VAR",
}

_ACTION_PRIORITY = {
    "TOKEN_REVOCATION": 1,
    "TOKEN_ROTATION": 2,
    "SCOPE_REDUCTION": 3,
    "ASSIGN_OWNER": 4,
    "SPLIT_TOKEN_PER_PROJECT": 5,
    "MOVE_TO_ENV_VAR": 6,
    "MONITOR": 9,
}

_POLICY_CATALOG: Dict[str, Dict[str, Any]] = {
    "OWNER_REQUIRED": {
        "name": "Owner 필수 정책", "severity": "HIGH", "remediable": False,
    },
    "ROTATION_PERIOD": {
        "name": "Rotation 주기 정책", "severity": "MEDIUM", "remediable": True,
    },
    "ADMIN_SCOPE_RESTRICTED": {
        "name": "관리자 Scope 제한 정책", "severity": "CRITICAL", "remediable": True,
    },
    "PROJECT_TOKEN_ISOLATION": {
        "name": "프로젝트별 Token 분리 정책", "severity": "HIGH", "remediable": True,
    },
}


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


def _scope_permission(raw_scope: str) -> str:
    """합성 scope를 현재 공통 권한 4종으로 결정적으로 매핑한다."""
    lowered = raw_scope.strip().lower()
    if lowered == "repo" or "admin" in lowered:
        return "ADMIN"
    if "delete" in lowered or "remove" in lowered:
        return "DELETE"
    if any(
        token in lowered
        for token in ("write", "put", "workflow", "dispatch", "create", "update")
    ):
        return "WRITE"
    return "READ"


def _permission_detail(scenario: Dict[str, Any]) -> Dict[str, Any]:
    permissions = list(scenario["permissions"])
    rank = {"READ": 1, "WRITE": 2, "DELETE": 3, "ADMIN": 4}
    highest = max(permissions, key=lambda item: rank[item]) if permissions else None
    return {
        "raw_scopes": list(scenario["raw_scopes"]),
        "permissions": permissions,
        "highest_permission": highest,
        "mappings": [
            {
                "raw_scope": raw_scope,
                "permission": _scope_permission(raw_scope),
                "description": "합성 데모의 공급자 scope를 공통 권한으로 변환",
                "inferred": False,
            }
            for raw_scope in scenario["raw_scopes"]
        ],
        "unknown_scopes": [],
        "assumed": False,
    }


def _usage_analysis(
    scenario: Dict[str, Any], *, analyzed_at: str
) -> Dict[str, Any]:
    usage = _DEMO_USAGE[scenario["key"]]
    actions = list(usage["actions"])
    observed_permissions = list(usage["permissions"])
    complete = bool(usage["complete"])
    offset = usage["last_used_offset_days"]
    last_used_at = (
        _iso(scenario["days_ago"] + int(offset)) if offset is not None else None
    )
    if complete:
        completeness_evidence = "합성 감사 로그 범위가 완전한 예시"
    elif actions:
        completeness_evidence = "합성 감사 로그 일부만 제공됨 — 이상 없음으로 간주하지 않음"
    else:
        completeness_evidence = "사용 로그 미제공 — 사용 상태와 이상 여부 미확인"
    unused_permissions = (
        [
            permission
            for permission in scenario["permissions"]
            if permission not in observed_permissions
        ]
        if complete
        else []
    )
    activity_status = "active" if last_used_at else ("stale" if complete else "unknown")
    return {
        "declared_permissions": list(scenario["permissions"]),
        "permission_baseline_source": "granted_scope",
        "permission_comparison_complete": True,
        "observed_permissions": observed_permissions,
        "observed_actions": actions,
        "unexpected_permissions": [],
        "unused_permissions": unused_permissions,
        "activity_status": activity_status,
        "mutation_observed": any(
            item in {"WRITE", "DELETE", "ADMIN"} for item in observed_permissions
        ),
        "usage_observed": True if actions or last_used_at else (False if complete else None),
        "used_after_revocation": False if complete else None,
        "replay_suspected": False if complete else None,
        "last_used_at": last_used_at,
        "sender_constrained": None,
        "token_binding_method": None,
        "source_ip": None,
        "user_agent": None,
        "data_complete": complete,
        "confidence": 0.95 if complete else (0.72 if actions else 0.35),
        "sources": [
            "synthetic_audit_log"
            if complete
            else ("synthetic_activity_sample" if actions else "synthetic_inventory")
        ],
        "evidence": [
            "합성 데이터로 승인 권한과 관측 권한을 비교 — 실제 API 호출 아님",
            completeness_evidence,
        ],
        "analyzed_at": analyzed_at,
    }


def _security_events(
    scenario: Dict[str, Any], *, analyzed_at: str
) -> List[Dict[str, Any]]:
    """직접 관측을 꾸며내지 않고 실제 데모 조건에 해당하는 event만 만든다."""
    if scenario["key"] != "shared-automation-token":
        return []
    event_id = "demo-event:shared-automation-token:cross-project"
    projects = [
        "nhi-sentinel-demo/ai-assistant",
        "nhi-sentinel-demo/support-automation",
    ]
    return [
        {
            "event_id": event_id,
            "event_type": "CROSS_PROJECT_CREDENTIAL_USE",
            "severity": "CRITICAL",
            "title": "프로젝트 간 자격 증명 공유",
            "detail": "동일 합성 자격 증명이 2개 프로젝트에 연결됨",
            "origin": "control_gap",
            "confidence": 0.98,
            "source": "synthetic_inventory",
            "source_event_id": f"{DEMO_WORKSPACE_ID}:shared-credential-binding",
            "occurred_at": analyzed_at,
            "access_level": None,
            "evidence": [
                "합성 inventory에서 동일 fingerprint의 교차 프로젝트 연결 확인"
            ],
            "attributes": {"projects": projects, "synthetic": True},
            "observed_at": analyzed_at,
        }
    ]


def _scenario_matches(
    scenario: Dict[str, Any], events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    forced = _FORCED_SCENARIOS.get(scenario["key"])
    if forced is None:
        return []
    event_ids = [event["event_id"] for event in events]
    return [
        {
            "scenario_id": forced["scenario_id"],
            "name": forced["name"],
            "severity": "CRITICAL",
            "confidence": 0.98,
            "reason": forced["reason"],
            "event_ids": event_ids,
            "evidence": [
                event_evidence
                for event in events
                for event_evidence in event["evidence"]
            ]
            or [forced["reason"]],
            "matched": True,
            "forced_critical": True,
            "category": "forced_critical",
        }
    ]


def _risk_factors(scenario: Dict[str, Any]) -> List[Dict[str, Any]]:
    scores = _DEMO_FACTOR_SCORES[scenario["key"]]
    usage = _DEMO_USAGE[scenario["key"]]
    highest = _permission_detail(scenario)["highest_permission"] or "UNKNOWN"
    reasons = {
        "exposure_location": [
            f"합성 저장소 {scenario['repository']}의 {scenario['file_path']}에서 탐지"
        ],
        "api_permission": [f"최고 권한 {highest}"],
        "environment_data": [
            f"{scenario['environment']} 환경, 합성 데이터 민감도 반영"
        ],
        "credential_state": [
            "합성 Credential의 활성·수명·회전 상태를 반영"
        ],
        "usage_anomaly": [
            "합성 사용 로그 완전"
            if usage["complete"]
            else "사용 로그가 불완전하거나 미제공되어 보수적으로 평가"
        ],
        "ownership_policy": [
            "Owner 미지정 및 정책 위반 반영"
            if scenario["owner"] is None
            else f"Owner={scenario['owner']} 및 정책 상태 반영"
        ],
        "connected_service_impact": [
            f"서비스 {len(scenario['services'])}개, 자원 {len(scenario['resources'])}개 영향"
        ],
    }
    return [
        {
            "area": area,
            "label": _RISK_FACTOR_LABEL[area],
            "score": scores[area],
            "max_score": max_score,
            "reasons": reasons[area],
        }
        for area, max_score in _RISK_FACTOR_MAX.items()
    ]


def _policy_evaluation(
    scenario: Dict[str, Any], *, risk_level: str, analyzed_at: str
) -> Dict[str, Any]:
    violations = []
    for policy_id in scenario["policy_ids"]:
        catalog = _POLICY_CATALOG.get(policy_id)
        if catalog is None:  # forced-Critical rule는 policy violation과 중복 기록하지 않는다.
            continue
        violations.append(
            {
                "policy_id": policy_id,
                "name": catalog["name"],
                "detail": f"합성 데모에서 {catalog['name']} 위반 조건 확인",
                "severity": catalog["severity"],
                "remediable": catalog["remediable"],
            }
        )

    human_review = risk_level in {"CRITICAL", "HIGH"}
    auto = (
        not human_review
        and bool(violations)
        and all(item["remediable"] for item in violations)
    )
    outcome = "HUMAN_REVIEW" if human_review else ("AUTO_REMEDIATION" if auto else "MONITOR")
    return {
        "outcome": outcome,
        "violations": violations,
        "auto_remediable": auto,
        "human_review_required": human_review,
        "exception_applied": None,
        "evidence": [
            "합성 데모 정책 평가 — 실제 서비스 변경 없음",
            f"최종 판단={outcome}",
        ],
        "evaluated_at": analyzed_at,
    }


def _recommendations(
    scenario: Dict[str, Any], *, policy: Dict[str, Any]
) -> List[Dict[str, Any]]:
    action = _ACTION_MAP.get(
        scenario["recommended_action"], scenario["recommended_action"]
    )
    target = scenario.get("action_target") or (
        f"{scenario['provider']}:{scenario['nhi_name']}"
    )
    rationale = scenario.get("action_rationale") or scenario["risk_reasons"][0]
    return [
        {
            "action": action,
            "priority": _ACTION_PRIORITY[action],
            "rationale": rationale,
            "target": target,
            "automatable": bool(
                policy["auto_remediable"] and action == "TOKEN_ROTATION"
            ),
        }
    ]


def _analysis(scenario: Dict[str, Any], finding: SecretFinding) -> Dict[str, Any]:
    analyzed_at = _iso(scenario["days_ago"], hours=-1)
    permission_detail = _permission_detail(scenario)
    usage_analysis = _usage_analysis(scenario, analyzed_at=analyzed_at)
    security_events = _security_events(scenario, analyzed_at=analyzed_at)
    scenario_matches = _scenario_matches(scenario, security_events)
    factors = _risk_factors(scenario)
    base_score = sum(item["score"] for item in factors)
    forced_rules = [
        {
            "rule_id": match["scenario_id"],
            "reason": match["reason"],
        }
        for match in scenario_matches
        if match["forced_critical"]
    ]
    risk_level = "CRITICAL" if forced_rules else scenario["risk_level"]
    risk_score = max(base_score, 80) if forced_rules else base_score
    risk_reasons = [item["reason"] for item in forced_rules]
    risk_reasons.extend(
        reason for reason in scenario["risk_reasons"] if reason not in risk_reasons
    )
    policy = _policy_evaluation(
        scenario, risk_level=risk_level, analyzed_at=analyzed_at
    )
    recommendations = _recommendations(scenario, policy=policy)
    permissions = set(scenario["permissions"])
    cross_project = scenario["key"] == "shared-automation-token"
    affected_projects = (
        [
            "nhi-sentinel-demo/ai-assistant",
            "nhi-sentinel-demo/support-automation",
        ]
        if cross_project
        else []
    )

    return {
        "demo_workspace": DEMO_WORKSPACE_ID,
        "source": "code_scan",
        "repository": scenario["repository"],
        "fingerprint": finding.fingerprint,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "masked_value": finding.masked_value,
        "nhi_name": scenario["nhi_name"],
        "nhi_type": scenario["nhi_type"],
        "owner": scenario["owner"],
        "environment": scenario["environment"],
        "permissions": list(scenario["permissions"]),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "recommended_action": recommendations[0]["action"],
        "analyzed_at": analyzed_at,
        "discovery": {
            "nhi_id": scenario["nhi_id"],
            "nhi_name": scenario["nhi_name"],
            "nhi_type": scenario["nhi_type"],
            "provider": scenario["provider"],
            "secret_type": scenario["secret_type"],
            "secret_name": scenario["secret_type"],
            "is_bot": scenario["nhi_type"] in {"SLACK_BOT", "GITHUB_APP", "CI_BOT"},
            "is_service_account": True,
            "linked_ai_agent": scenario["linked_ai_agent"],
            "owner": scenario["owner"],
            "owner_candidates": [scenario["owner"]] if scenario["owner"] else [],
            "owner_source": "synthetic_demo" if scenario["owner"] else None,
            "account": {"synthetic": True},
            "identified": True,
            "confidence": 0.96 if scenario["risk_level"] == "CRITICAL" else 0.86,
            "evidence": [
                "합성 데모 inventory에서 NHI 식별 — 실제 계정 또는 Secret 아님"
            ],
            "credential_fingerprint": finding.fingerprint,
        },
        "context_analysis": {
            "environment": scenario["environment"],
            "is_test_or_example": scenario["environment"] == "test",
            "in_use": usage_analysis["usage_observed"],
            "data_sensitivity": (
                "confidential" if risk_level in {"CRITICAL", "HIGH"} else "internal"
            ),
            "variable_name": scenario["secret_type"],
            "hardcoded_in_source": True,
            "project_hint": scenario["repository"],
            "path_signals": [finding.file_path],
            "code_signals": ["합성 데모 Credential 위치"],
            "confidence": 0.95,
            "notes": ["합성 문맥 — 실제 Secret material 없음"],
        },
        "permission_detail": permission_detail,
        "usage_analysis": usage_analysis,
        "security_events": security_events,
        "scenario_matches": scenario_matches,
        "risk_detail": {
            "score": risk_score,
            "level": risk_level,
            "base_score": base_score,
            "factors": factors,
            "reasons": risk_reasons,
            "forced_critical": bool(forced_rules),
            "forced_rules": forced_rules,
        },
        "policy": policy,
        "recommendations": recommendations,
        "blast_radius": {
            "connected_services": list(scenario["services"]),
            "accessible_resources": len(scenario["resources"]),
            "resource_samples": list(scenario["resources"]),
            "can_read": bool(permissions),
            "can_write": bool(permissions & {"WRITE", "DELETE", "ADMIN"}),
            "can_delete": bool(permissions & {"DELETE", "ADMIN"}),
            "external_transfer_possible": (
                "READ" in permissions and risk_level in {"CRITICAL", "HIGH"}
            ),
            "cross_project_impact": cross_project,
            "affected_projects": affected_projects,
            "sensitive_data_access": risk_level in {"CRITICAL", "HIGH"},
            "impact_score": min(100, risk_score),
            "notes": ["합성 Blast Radius — 실제 외부 자원 조회 없음"],
            "connected_service_count": len(scenario["services"]),
        },
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
            "risk_score": analysis["risk_score"],
            "risk_level": analysis["risk_level"],
            "recommended_action": analysis["recommended_action"],
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
                    risk_level=analysis["risk_level"],
                    requires_approval=True,
                    idempotency_key=f"demo:{DEMO_WORKSPACE_ID}:{scenario['key']}",
                    status=ActionStatus.PENDING_APPROVAL,
                    provider=scenario["provider"],
                    demo_workspace=True,
                )
            )
            action_count += 1

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
    }


def clear_demo_workspace(storage: Storage) -> Dict[str, Any]:
    counts = storage.clear_demo_workspace(DEMO_WORKSPACE_ID)
    return {
        "workspace_id": DEMO_WORKSPACE_ID,
        "cleared": True,
        "deleted": counts,
    }
