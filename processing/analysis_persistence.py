"""분석 산출물·NHI 관계·조치 요청을 한 트랜잭션 경계처럼 저장한다."""

from __future__ import annotations

from typing import Dict, List

from backend.services.lifecycle_service import LifecycleService
from core.governance_models import (
    PRESERVED_ON_REANALYSIS,
    ControlEvent,
    LifecycleEvent,
    LifecycleStage,
)
from core.nhi_models import NHIAnalysis, NHIAnalysisReport
from processing.action_service import ActionService
from storage.base import Storage

SCORING_VERSION = "1.0"
POLICY_VERSION = "1.0"


def persist_analysis(
    storage: Storage,
    analysis: NHIAnalysis,
    *,
    input_revision: str = "",
) -> Dict[str, object]:
    profile = analysis.profile
    nhi_data = profile.to_dict()
    nhi_data.update(
        {
            "environment": analysis.context.environment.value,
            "data_sensitivity": analysis.context.data_sensitivity.value,
            "permissions": [
                permission.value for permission in analysis.permissions.permissions
            ],
            "raw_scopes": list(analysis.permissions.raw_scopes),
            "risk_score": analysis.risk.score,
            "risk_level": analysis.risk.level.value,
            "recommended_action": analysis.recommended_action.value,
            "blast_radius": analysis.blast_radius.to_dict(),
            "analyzed_at": analysis.analyzed_at,
        }
    )
    nhi_data.update(
        {k: v for k, v in analysis.lifecycle_timestamps.items() if v is not None}
    )
    existing = storage.get_nhi_record(profile.nhi_id)
    if existing:
        # 재분석이 생명주기·통제 상태를 초기화하지 않도록 보존한다.
        for key in PRESERVED_ON_REANALYSIS:
            if key in existing and not (
                key == "last_rotated_at" and nhi_data.get(key)
            ):
                nhi_data[key] = existing[key]
        if existing.get("demo_workspace"):
            nhi_data["demo_workspace"] = existing["demo_workspace"]
    storage.upsert_nhi(profile.nhi_id, nhi_data)
    LifecycleService(storage).ensure_tracked(profile.nhi_id)
    if existing and any(
        set(existing.get(key) or []) != set(nhi_data.get(key) or [])
        for key in ("permissions", "raw_scopes")
    ):
        LifecycleService(storage).record(
            storage.get_nhi_record(profile.nhi_id), "PERMISSION_CHANGE", "analysis-pipeline",
            {
                "source": "observed_analysis",
                "before": {key: existing.get(key, []) for key in ("permissions", "raw_scopes")},
                "after": {key: nhi_data.get(key, []) for key in ("permissions", "raw_scopes")},
            },
        )
    if existing and existing.get("lifecycle_stage") in (
        LifecycleStage.DEACTIVATED.value,
        LifecycleStage.DECOMMISSIONED.value,
    ):
        _report_redetection(storage, profile.nhi_id, existing, analysis)
    storage.bind_credential_to_nhi(
        analysis.fingerprint,
        profile.nhi_id,
        confidence=profile.confidence,
        evidence=profile.evidence,
    )
    analysis_id = storage.save_analysis(
        analysis.to_dict(),
        repository=analysis.repository,
        fingerprint=analysis.fingerprint,
        input_revision=input_revision,
        scoring_version=SCORING_VERSION,
        policy_version=POLICY_VERSION,
    )
    storage.update_finding_analysis(
        repository=analysis.repository,
        fingerprint=analysis.fingerprint,
        analysis=analysis.to_dict(),
    )
    actions = ActionService(storage).create_from_analysis(
        analysis_id, analysis, policy_version=POLICY_VERSION
    )
    return {
        "analysis_id": analysis_id,
        "action_ids": [action.action_id for action in actions],
    }


def persist_report(
    storage: Storage,
    report: NHIAnalysisReport,
    *,
    input_revision: str = "",
) -> List[Dict[str, object]]:
    return [
        persist_analysis(storage, analysis, input_revision=input_revision)
        for analysis in report.analyses
    ]


def _report_redetection(
    storage: Storage,
    nhi_id: str,
    existing: Dict[str, object],
    analysis: NHIAnalysis,
) -> None:
    """종료·파기된 NHI 의 Credential 이 다시 탐지되면 잔존 사용처 신호로 기록한다."""
    detail = {
        "stage": existing.get("lifecycle_stage"),
        "location": f"{analysis.file_path}:{analysis.line_number}",
        "repository": analysis.repository,
    }
    storage.append_lifecycle_event(
        LifecycleEvent(
            nhi_id=nhi_id,
            stage=str(existing.get("lifecycle_stage")),
            event_type="REDETECTED_AFTER_TERMINATION",
            actor="scanner",
            detail=detail,
            demo_workspace=bool(existing.get("demo_workspace")),
        )
    )
    storage.append_control_event(
        ControlEvent(
            nhi_id=nhi_id,
            event_type="EXPOSURE_DETECTED",
            verdict="ALERT",
            severity="HIGH",
            rules=[
                {
                    "rule_id": "R8_REDETECTED_AFTER_TERMINATION",
                    "verdict": "ALERT",
                    "severity": "HIGH",
                    "message": "종료·파기된 NHI 의 Credential 이 저장소에서 다시 탐지되었습니다 "
                    "— 잔존 사용처 또는 재발급 누락을 확인하세요.",
                }
            ],
            attributes=detail,
            demo_workspace=bool(existing.get("demo_workspace")),
        )
    )
