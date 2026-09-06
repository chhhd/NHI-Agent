"""Blast Radius — Credential 1건이 손상됐을 때의 영향 범위 계산.

분석 항목
  * 연결 서비스 수
  * 접근 가능한 자원 수
  * 읽기·쓰기·삭제 권한
  * 외부 전송 가능 여부
  * 다른 프로젝트 영향 여부
  * 민감 데이터 접근 가능 여부
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from agents.scope_translation_agent import expand_permissions
from core.models import SecretFinding
from core.nhi_models import (
    AnalysisSignals,
    BlastRadiusReport,
    ContextInsight,
    DataSensitivity,
    NHIProfile,
    NHIType,
    PermissionLevel,
    PermissionProfile,
)

logger = logging.getLogger(__name__)

#: 데이터를 조직 밖으로 내보낼 수 있는 provider (쓰기 권한 결합 시)
EXTERNAL_TRANSFER_PROVIDERS = {
    "slack", "sendgrid", "notion", "huggingface", "npm", "github", "gitlab",
    "microsoft", "google_workspace",
}

#: provider → 대표 서비스 표기
SERVICE_LABEL = {
    "slack": "Slack",
    "github": "GitHub",
    "gitlab": "GitLab",
    "notion": "Notion",
    "huggingface": "Hugging Face",
    "aws": "AWS",
    "google": "Google Cloud",
    "google_workspace": "Google Workspace",
    "microsoft": "Microsoft 365",
    "anthropic": "Anthropic API",
    "openai": "OpenAI API",
    "stripe": "Stripe",
    "sendgrid": "SendGrid",
    "npm": "npm Registry",
    "generic": "Unknown Service",
    "unknown": "Unknown Service",
}

#: NHI 유형별로 함께 연결되는 것이 일반적인 서비스 (영향 범위 확장 추정)
IMPLIED_SERVICES = {
    NHIType.AI_AGENT_CREDENTIAL: ("AI Model Provider",),
    NHIType.CLOUD_SERVICE_ACCOUNT: ("Cloud Storage", "Cloud Compute"),
    NHIType.PAYMENT_SERVICE_ACCOUNT: ("Payment Ledger",),
}


def service_label(provider: str) -> str:
    return SERVICE_LABEL.get((provider or "unknown").lower(), provider or "Unknown Service")


class BlastRadiusCalculator:
    """Credential 손상 시 영향 범위를 산출한다."""

    def compute(
        self,
        finding: SecretFinding,
        profile: NHIProfile,
        permissions: PermissionProfile,
        context: ContextInsight,
        signals: Optional[AnalysisSignals] = None,
    ) -> BlastRadiusReport:
        signals = signals or AnalysisSignals()
        report = BlastRadiusReport()

        effective = expand_permissions(permissions.permissions)
        report.can_read = PermissionLevel.READ in effective
        report.can_write = PermissionLevel.WRITE in effective
        report.can_delete = PermissionLevel.DELETE in effective

        report.connected_services = self._services(profile, signals)
        resources = self._resources(finding, signals)
        report.accessible_resources = len(resources)
        report.resource_samples = [self._resource_label(r) for r in resources[:10]]
        # AWS 는 Resource 가 ARN/와일드카드라 "개수"가 의미 없다 — 대신
        # `agents/aws_policy_permission_analyzer.py` 가 이미 계산한 "광범위
        # 접근 여부"만 신호로 받는다(`agents/inventory_adapter.py::build_aws_signals`
        # 가 채운 `signals.extra["aws_broad_access"]`). 다른 provider 는 이
        # 키를 채우지 않으므로 항상 False 다.
        report.broad_access = bool(signals.extra.get("aws_broad_access")) if signals.extra else False

        report.affected_projects = list(signals.shared_projects)
        report.cross_project_impact = len(report.affected_projects) >= 2
        report.sensitive_data_access = context.data_sensitivity in (
            DataSensitivity.RESTRICTED,
            DataSensitivity.CONFIDENTIAL,
        )
        report.external_transfer_possible = self._external_transfer(profile, report)

        if permissions.assumed:
            report.notes.append("Scope 미확인 — 권한은 Secret 유형 기준 가정값")
        if not resources and profile.provider != "aws":
            # AWS 는 애초에 리소스 "개수"를 세지 않으므로(broad_access 만
            # 본다) 이 문구가 "검증 실패"처럼 오인되지 않게 AWS 는 제외한다.
            report.notes.append("접근 가능 자원 목록을 확인하지 못함 (토큰 검증 미수행 또는 권한 부족)")
        if report.broad_access:
            report.notes.append("AWS Policy 에 광범위한 Resource 접근(전체/서비스 전체 wildcard)이 포함됨")
        repository_selection = str(
            (signals.extra or {}).get("repository_selection") or ""
        ).lower()
        if repository_selection == "all":
            report.notes.append(
                "GitHub App installation은 조직의 모든 저장소 범위이나 개별 이름은 미수집"
            )
        elif repository_selection == "selected" and not resources:
            report.notes.append(
                "GitHub App installation은 선택 저장소 범위이나 개별 이름은 미수집"
            )
        if profile.linked_ai_agent:
            report.notes.append(f"AI Agent '{profile.linked_ai_agent}' 가 이 Credential 을 사용")

        report.impact_score = self._impact_score(report, permissions)
        return report

    # ------------------------------------------------------------------
    @staticmethod
    def _services(profile: NHIProfile, signals: AnalysisSignals) -> List[str]:
        services: List[str] = [service_label(profile.provider)]
        for implied in IMPLIED_SERVICES.get(profile.nhi_type, ()):
            if implied not in services:
                services.append(implied)
        extra = signals.extra.get("connected_services") if signals.extra else None
        if isinstance(extra, (list, tuple)):
            for name in extra:
                if isinstance(name, str) and name and name not in services:
                    services.append(name)
        return services

    @staticmethod
    def _resources(finding: SecretFinding, signals: AnalysisSignals) -> List[Dict[str, Any]]:
        detail = finding.credential_detail or {}
        resources = detail.get("accessible_resources") or []
        items = [r for r in resources if isinstance(r, dict)]
        extra = signals.extra.get("accessible_resources") if signals.extra else None
        if isinstance(extra, (list, tuple)):
            items.extend(r for r in extra if isinstance(r, dict))
        return items

    @staticmethod
    def _resource_label(resource: Dict[str, Any]) -> str:
        for key in ("full_name", "name", "path_with_namespace", "title", "id"):
            value = resource.get(key)
            if value:
                return str(value)
        return "unnamed-resource"

    @staticmethod
    def _external_transfer(profile: NHIProfile, report: BlastRadiusReport) -> bool:
        if profile.nhi_type is NHIType.SLACK_WEBHOOK:
            return True
        if profile.provider in EXTERNAL_TRANSFER_PROVIDERS and report.can_write:
            return True
        # 읽기만 가능해도 외부 API 로 데이터를 끌어갈 수 있는 경우
        return profile.provider in {"slack", "notion"} and report.can_read

    @staticmethod
    def _impact_score(report: BlastRadiusReport, permissions: PermissionProfile) -> int:
        score = 0
        score += min(25, len(report.connected_services) * 10)
        resources = report.accessible_resources
        if report.broad_access:
            # AWS 등 리소스 "개수"를 세지 않는 provider — 광범위 wildcard 는
            # 리소스 20개 이상(최고 구간)과 동급 위험으로 취급한다.
            score += 25
        elif resources >= 20:
            score += 25
        elif resources >= 5:
            score += 18
        elif resources >= 1:
            score += 10

        highest = permissions.highest
        score += {
            PermissionLevel.ADMIN: 25,
            PermissionLevel.DELETE: 20,
            PermissionLevel.WRITE: 14,
            PermissionLevel.READ: 7,
        }.get(highest, 10)

        if report.sensitive_data_access:
            score += 10
        if report.cross_project_impact:
            score += 10
        if report.external_transfer_possible:
            score += 5
        return min(100, score)


def summarize_blast_radius(reports: Iterable[BlastRadiusReport]) -> Dict[str, Any]:
    """여러 NHI 의 영향 범위를 합산한다 (Repository 단위 리포트용)."""
    services: List[str] = []
    projects: List[str] = []
    resources = 0
    delete_capable = 0
    external = 0

    for report in reports:
        resources += report.accessible_resources
        delete_capable += 1 if report.can_delete else 0
        external += 1 if report.external_transfer_possible else 0
        for service in report.connected_services:
            if service not in services:
                services.append(service)
        for project in report.affected_projects:
            if project not in projects:
                projects.append(project)

    return {
        "connected_services": services,
        "connected_service_count": len(services),
        "accessible_resources": resources,
        "delete_capable_credentials": delete_capable,
        "external_transfer_capable": external,
        "affected_projects": projects,
    }
