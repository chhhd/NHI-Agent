"""Dry-run 조치 흐름 — 기본 구조.

`NHIAnalysis.recommended_action` 을 기준으로 "실제로 이 조치를 적용하면
무엇이 바뀔지"를 실제 실행 없이 미리 계산해서 보여주는 것뿐이다.

명시적으로 이번 단계에서 하지 않는 것:
  * 실제 Credential 폐기/회전/권한 축소 등 조치 실행 — 별도 실행 엔진에서
    다룬다(`processing/action_service.py::ActionService` 가 그 승인/실행
    라이프사이클을 관리하지만, 이 함수는 그것을 호출하지 않는다).
  * 승인 처리 — dry-run 은 승인 여부와 무관하게 항상 계산 가능하다.
  * `risk_after_estimate` 를 위한 정책 엔진 재실행 — 실제로 조치를 적용한
    뒤 파이프라인을 다시 돌려 얻은 값이 아니라, 조치 유형별 고정 감소율을
    곱한 대략적인 추정값이다(휴리스틱). 실제 재평가 값과 다를 수 있다.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.nhi_models import RecommendedAction

#: 조치 유형별 예상 변경 사항 설명 — 실제로 실행하지 않고 미리 보여주는 문구다.
_EXPECTED_CHANGES: Dict[str, List[str]] = {
    RecommendedAction.TOKEN_REVOCATION.value: [
        "Credential을 즉시 폐기 처리합니다.",
    ],
    RecommendedAction.TOKEN_ROTATION.value: [
        "새 Credential을 발급하고 기존 Credential을 폐기합니다.",
    ],
    RecommendedAction.SCOPE_REDUCTION.value: [
        "과도하게 부여된 권한(ADMIN/DELETE 등)을 필요한 최소 범위로 축소합니다.",
    ],
    RecommendedAction.ASSIGN_OWNER.value: [
        "책임 Owner를 지정합니다.",
    ],
    RecommendedAction.SPLIT_TOKEN_PER_PROJECT.value: [
        "프로젝트별로 별도 Credential을 분리 발급합니다.",
    ],
    RecommendedAction.MOVE_TO_ENV_VAR.value: [
        "하드코딩된 값을 환경변수/시크릿 매니저로 이전합니다.",
    ],
    RecommendedAction.DISABLE_INACTIVE_NHI.value: [
        "미사용 NHI 계정을 비활성화합니다.",
    ],
    RecommendedAction.REQUEST_REAPPROVAL.value: [
        "책임자에게 재승인을 요청합니다.",
    ],
    RecommendedAction.MONITOR.value: [
        "추가 조치 없이 관찰만 유지합니다.",
    ],
}

#: 조치 유형별 예상 위험도 감소율(휴리스틱, 0.0~1.0) — 실제 정책 재평가
#: 결과가 아니라 조치 성격에 따른 대략적인 추정 비율이다.
_ESTIMATED_RISK_REDUCTION_RATIO: Dict[str, float] = {
    RecommendedAction.TOKEN_REVOCATION.value: 1.0,
    RecommendedAction.TOKEN_ROTATION.value: 0.5,
    RecommendedAction.DISABLE_INACTIVE_NHI.value: 0.6,
    RecommendedAction.SCOPE_REDUCTION.value: 0.3,
    RecommendedAction.SPLIT_TOKEN_PER_PROJECT.value: 0.2,
    RecommendedAction.MOVE_TO_ENV_VAR.value: 0.15,
    RecommendedAction.ASSIGN_OWNER.value: 0.1,
    RecommendedAction.REQUEST_REAPPROVAL.value: 0.05,
    RecommendedAction.MONITOR.value: 0.0,
}


def build_dry_run_result(nhi_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """저장된 NHI 레코드(`storage.get_nhi_record()` 결과)를 기준으로 dry-run 결과를 만든다.

    실제 조치는 수행하지 않는다 — `record` 를 읽기만 하고 아무 것도 쓰지 않는다.
    정의되지 않은(향후 추가될) 조치 유형이 와도 예외를 던지지 않고 안전한
    기본값(변경 사항 없음 문구, 감소율 0)으로 처리한다.
    """
    action = record.get("recommended_action") or RecommendedAction.MONITOR.value
    risk_before = record.get("risk_score") or 0

    expected_changes = _EXPECTED_CHANGES.get(
        action, ["정의된 예상 변경 사항이 없습니다."]
    )
    reduction_ratio = _ESTIMATED_RISK_REDUCTION_RATIO.get(action, 0.0)
    risk_after_estimate = max(0, round(risk_before * (1 - reduction_ratio)))

    return {
        "target_nhi_id": nhi_id,
        "recommended_action": action,
        "expected_changes": expected_changes,
        "risk_before": risk_before,
        "risk_after_estimate": risk_after_estimate,
    }
