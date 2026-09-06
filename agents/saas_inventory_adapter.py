"""공급자 중립 SaaS NHI 인벤토리 입력을 공통 분석 엔진 입력으로 변환한다."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.inventory_models import SaaSNHIInput
from core.models import DetectorType, SecretFinding, Severity
from core.nhi_models import (
    AnalysisSignals,
    ContextInsight,
    DataSensitivity,
    Environment,
    NHIProfile,
    NHIType,
)


DECLARED_CONFIDENCE = 0.95


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def resource_records(nhi: SaaSNHIInput) -> List[Dict[str, Any]]:
    return [resource.model_dump(mode="json") for resource in nhi.resources]


def build_saas_signals(
    nhi: SaaSNHIInput, overrides: Optional[Dict[str, Any]] = None
) -> AnalysisSignals:
    base: Dict[str, Any] = {
        "owner": nhi.owner,
        "created_at": _iso(nhi.created_at),
        "last_used_at": _iso(nhi.last_used_at),
        "expires_at": _iso(nhi.expires_at),
        "last_rotated_at": _iso(nhi.last_rotated_at),
        "extra": {
            "environment": nhi.environment.value,
            "connected_services": list(nhi.connected_services),
        },
    }

    merged = dict(base)
    extra = dict(base["extra"])
    for key, value in (overrides or {}).items():
        if key == "extra" and isinstance(value, dict):
            extra.update(value)
        elif value is not None:
            merged[key] = value
    merged["extra"] = extra
    return AnalysisSignals.from_dict(merged)


def build_saas_credential_record(nhi: SaaSNHIInput) -> SecretFinding:
    provider = nhi.provider.strip().lower()
    return SecretFinding(
        secret_type=nhi.nhi_type.value,
        provider=provider,
        masked_value="",
        fingerprint=f"nhi:{provider}:{nhi.nhi_id}",
        file_path="",
        line_number=0,
        detector=DetectorType.REGEX,
        severity=Severity.MEDIUM,
        credential_active=nhi.active,
        credential_revoked=None,
        raw_scopes=list(dict.fromkeys(nhi.raw_scopes)),
        credential_detail={
            "account": dict(nhi.account),
            "accessible_resources": resource_records(nhi),
        },
    )


def build_saas_profile(nhi: SaaSNHIInput, signals: AnalysisSignals) -> NHIProfile:
    provider = nhi.provider.strip().lower()
    owner = (signals.owner or "").strip() or None
    evidence = [
        f"{provider} 읽기 전용 API 인벤토리에서 {nhi.nhi_type.value} 식별",
        f"원본 Scope {len(nhi.raw_scopes)}건, 접근 자원 {len(nhi.resources)}건",
    ]
    evidence.append(f"API에서 확인된 Owner: {owner}" if owner else "API 응답에 Owner 없음")

    return NHIProfile(
        nhi_id=f"{provider}:{nhi.nhi_id}",
        nhi_name=nhi.nhi_name,
        nhi_type=nhi.nhi_type,
        provider=provider,
        secret_type=nhi.nhi_type.value,
        secret_name=f"{provider} {nhi.nhi_type.value.replace('_', ' ').title()}",
        is_bot=nhi.nhi_type is NHIType.AI_AGENT_CREDENTIAL,
        is_service_account=True,
        linked_ai_agent=signals.agent_name,
        owner=owner,
        owner_candidates=[owner] if owner else [],
        owner_source="provider_api" if owner else None,
        account=dict(nhi.account),
        identified=True,
        confidence=DECLARED_CONFIDENCE,
        evidence=evidence,
        credential_fingerprint=f"nhi:{provider}:{nhi.nhi_id}",
    )


def build_saas_context(nhi: SaaSNHIInput, signals: AnalysisSignals) -> ContextInsight:
    sensitive = [resource for resource in nhi.resources if resource.is_sensitive]
    if sensitive:
        sensitivity = DataSensitivity.CONFIDENTIAL
    elif nhi.resources:
        sensitivity = DataSensitivity.INTERNAL
    else:
        sensitivity = DataSensitivity.UNKNOWN

    notes = ["SaaS API 인벤토리의 선언된 메타데이터 기준 분석"]
    if sensitive:
        notes.append(
            "민감 자원 접근: " + ", ".join(resource.name for resource in sensitive[:3])
        )
    if nhi.environment is Environment.UNKNOWN:
        notes.append("사용 환경 미지정 — 보수적으로 평가")

    return ContextInsight(
        environment=nhi.environment,
        in_use=nhi.active,
        data_sensitivity=sensitivity,
        hardcoded_in_source=False,
        path_signals=[f"접근 자원 {len(nhi.resources)}건"] if nhi.resources else [],
        confidence=DECLARED_CONFIDENCE,
        notes=notes,
    )
