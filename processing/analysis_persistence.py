"""분석 산출물·NHI 관계·조치 요청을 한 트랜잭션 경계처럼 저장한다."""

from __future__ import annotations

from typing import Dict, List

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
    storage.upsert_nhi(profile.nhi_id, nhi_data)
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
