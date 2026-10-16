"""Change Preview — 조치 적용 전·후 비교 (실제 변경 없음).

`build_dry_run_result()` 는 기존 API 하위 호환을 위해 그대로 유지한다(고정
감소율 기반 단순 추정). 이 파일의 핵심은 그 아래에 새로 추가된
`build_change_preview()` 다 — 조치가 바꾸는 입력(권한/Owner/Agent 상태 등)만
가정으로 바꾼 뒤, **같은** `policy/rules.py::evaluate_policies()`,
`RiskScoringAgent`, `PolicyEvidenceAgent`, `BlastRadiusCalculator` 를 재실행해서
"조치를 적용하면 무엇이 바뀔지"를 계산한다.

실제로 조치를 적용해 검증한 값이 아니므로 모든 결과 항목은 다음 셋 중 하나로
구분한다(`core.nhi_models.ImpactConfidence` 참고).

  * ``calculated`` — 가정 상태를 입력으로 같은 규칙 기반 엔진을 재실행해 얻은 값.
  * ``estimated``  — 재검증 없이는 알 수 없어 과거 값·휴리스틱을 그대로 쓴 값.
  * ``unknown``    — 판단할 근거 자체가 없는 값(서비스 의존성 등).

명시적으로 하지 않는 것:
  * 실제 Credential 폐기/회전/권한 축소 등 조치 실행 — 이 함수는 입력을 읽고
    계산만 한다. 저장소에도 쓰지 않는다.
  * Usage/보안 이벤트 분석(`usage_analysis`/`security_events`) 재현 — 재현
    입력(`NHIAnalysis.replay_snapshot`)에 포함되지 않으므로 before/after 모두
    이 분석 없이 재계산한다. 그래서 여기서 나오는 `risk_before` 는 원래 저장된
    분석의 `risk_score` 와 다를 수 있다(계산 대상에서 빠진 부분은
    `calculated_notes` 에 명시한다) — before/after 를 **같은 축소 입력**으로
    계산해야 둘의 차이가 오직 조치 효과만을 반영하기 때문이다.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from agents.policy_evidence_agent import PolicyEvidenceAgent
from agents.risk_scoring_agent import RiskScoringAgent
from core.models import ResolutionStatus, SecretFinding
from core.nhi_models import (
    PERMISSION_RANK,
    AnalysisSignals,
    AnalysisSource,
    BlastRadiusReport,
    ChangePreviewResult,
    ContextInsight,
    DataSensitivity,
    Environment,
    ImpactConfidence,
    ImpactItem,
    NHIProfile,
    NHIType,
    PermissionLevel,
    PermissionProfile,
    PolicyViolation,
    RecommendedAction,
    RiskAssessment,
    ScopeMapping,
)
from graph.blast_radius import BlastRadiusCalculator
from policy.decision_engine import DecisionEngine
from policy.rules import EvaluationContext, PolicyConfig, evaluate_policies
from storage.base import Storage


def get_latest_analysis_snapshot(storage: Storage, nhi_id: str) -> Optional[Dict[str, Any]]:
    """NHI의 가장 최근 분석 snapshot(`NHIAnalysis.to_dict()`)을 조회한다.

    새 저장소 코드를 추가하지 않고 기존 `Storage.list_nhi_analyses()`
    (최신순 정렬, `backend/services/analysis_history.py`가 이미 쓰는 조회)를
    그대로 재사용한다. 분석 이력이 없으면 `None`을 반환한다 — NHI 자체가
    없거나(`storage.get_nhi_record()`로 별도 확인), 데모 workspace처럼
    파이프라인을 거치지 않고 합성 데이터만 저장된 경우에도 안전하게 `None`을
    준다(이 경우 분석 자체는 있을 수 있지만 `replay_snapshot`이 없을 뿐이며,
    그 처리는 `build_change_preview()`가 담당한다).
    """
    analyses = storage.list_nhi_analyses(nhi_id, limit=1)
    return analyses[0] if analyses else None

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

    기존 API 하위 호환을 위해 유지하는 단순 버전이다 — 고정 감소율 추정만
    한다. 정책/위험도 엔진을 실제로 재실행하는 버전은 `build_change_preview()`
    를 쓴다. 실제 조치는 수행하지 않는다 — `record` 를 읽기만 하고 아무 것도
    쓰지 않는다. 정의되지 않은(향후 추가될) 조치 유형이 와도 예외를 던지지
    않고 안전한 기본값(변경 사항 없음 문구, 감소율 0)으로 처리한다.
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


# ---------------------------------------------------------------------------
# Change Preview — 정책/위험도/영향범위 엔진을 재사용하는 본 구현
# ---------------------------------------------------------------------------

#: 조치 1건이 가정 상태(before를 복제한 EvaluationContext)에 적용하는 효과.
#: 실제 Credential/권한을 바꾸지 않는다 — 메모리 내 복제본만 변형한다.
ActionEffect = Callable[[EvaluationContext], None]


def _effect_token_revocation(ctx: EvaluationContext) -> None:
    """폐기 — Credential이 더 이상 유효하지 않다고 가정한다."""
    ctx.finding.credential_active = False
    ctx.finding.credential_revoked = True


def _effect_token_rotation(ctx: EvaluationContext) -> None:
    """회전 — 같은 권한 범위로 새 Credential을 발급했다고 가정한다(수명만 초기화됨)."""
    now = datetime.now(timezone.utc).isoformat()
    ctx.signals.created_at = now
    ctx.signals.last_rotated_at = now
    ctx.finding.credential_active = True
    ctx.finding.credential_revoked = False


def _effect_scope_reduction(ctx: EvaluationContext) -> None:
    """권한 축소 — ADMIN/DELETE 를 제거하고 필요한 최소 권한만 남긴다고 가정한다."""
    excessive = {PermissionLevel.ADMIN, PermissionLevel.DELETE}
    permissions = ctx.permissions
    reduced = [p for p in permissions.permissions if p not in excessive]
    if not reduced and permissions.permissions:
        # 전부 과도한 권한이었다면 "완전 차단"이 아니라 "최소 권한(READ)"으로 축소한다.
        reduced = [PermissionLevel.READ]
    permissions.permissions = sorted(set(reduced), key=lambda p: PERMISSION_RANK[p])
    permissions.mappings = [m for m in permissions.mappings if m.permission not in excessive]


def _effect_assign_owner(ctx: EvaluationContext) -> None:
    """Owner 지정 — 아직 확정되지 않은 가정값이므로 "공식 확인 필요" 상태로 둔다."""
    if ctx.profile.owner:
        return
    ctx.profile.owner = "(조치 적용 시 지정될 Owner — 아직 미확정)"
    ctx.profile.owner_source = "pending_assignment"


def _effect_split_token_per_project(ctx: EvaluationContext) -> None:
    """프로젝트별 분리 — 이 Credential이 더 이상 다른 프로젝트와 공유되지 않는다고 가정한다."""
    ctx.signals.shared_projects = []
    ctx.finding.duplicate_locations = []


def _effect_move_to_env_var(ctx: EvaluationContext) -> None:
    """환경변수 이전 — 소스에 하드코딩된 상태가 해소된다고 가정한다."""
    ctx.context.hardcoded_in_source = False


def _effect_disable_inactive_nhi(ctx: EvaluationContext) -> None:
    """비활성화 — Agent를 정지시키고 Credential도 함께 비활성화한다고 가정한다."""
    ctx.signals.agent_status = "stopped"
    ctx.finding.credential_active = False
    ctx.finding.credential_revoked = True


def _effect_noop(ctx: EvaluationContext) -> None:
    """이 조치는 기술적 상태를 바꾸지 않는다(조직 프로세스 조치 또는 관찰 유지)."""
    return None


#: 조치 → 가정 상태 변형 함수. 여기 없는 조치는 `build_change_preview()`가
#: `applicable=False`로 표시하고 after를 before와 동일하게 둔다(안전한 기본값).
ACTION_EFFECTS: Dict[RecommendedAction, ActionEffect] = {
    RecommendedAction.TOKEN_REVOCATION: _effect_token_revocation,
    RecommendedAction.TOKEN_ROTATION: _effect_token_rotation,
    RecommendedAction.SCOPE_REDUCTION: _effect_scope_reduction,
    RecommendedAction.ASSIGN_OWNER: _effect_assign_owner,
    RecommendedAction.SPLIT_TOKEN_PER_PROJECT: _effect_split_token_per_project,
    RecommendedAction.MOVE_TO_ENV_VAR: _effect_move_to_env_var,
    RecommendedAction.DISABLE_INACTIVE_NHI: _effect_disable_inactive_nhi,
    RecommendedAction.REQUEST_REAPPROVAL: _effect_noop,
    RecommendedAction.MONITOR: _effect_noop,
}

#: 접근 권한 자체를 줄이거나 없애는 조치 — service_dependency_impact 판단에 쓴다.
_ACCESS_REDUCING_ACTIONS = {
    RecommendedAction.TOKEN_REVOCATION,
    RecommendedAction.DISABLE_INACTIVE_NHI,
    RecommendedAction.SCOPE_REDUCTION,
}


# ---------------------------------------------------------------------------
# 저장된 분석 snapshot(`NHIAnalysis.to_dict()`) → EvaluationContext 재구성
# ---------------------------------------------------------------------------
def _enum_or_default(enum_cls, value, default):
    try:
        return enum_cls(value)
    except ValueError:
        return default


def _profile_from_dict(data: Dict[str, Any]) -> NHIProfile:
    data = dict(data or {})
    return NHIProfile(
        nhi_id=str(data.get("nhi_id", "")),
        nhi_name=str(data.get("nhi_name", "")),
        nhi_type=_enum_or_default(NHIType, data.get("nhi_type"), NHIType.UNKNOWN_NHI),
        provider=str(data.get("provider", "unknown")),
        secret_type=str(data.get("secret_type", "")),
        secret_name=str(data.get("secret_name", "")),
        is_bot=bool(data.get("is_bot", False)),
        is_service_account=bool(data.get("is_service_account", False)),
        linked_ai_agent=data.get("linked_ai_agent"),
        owner=data.get("owner"),
        owner_candidates=list(data.get("owner_candidates", [])),
        owner_source=data.get("owner_source"),
        account=dict(data.get("account", {})),
        identified=bool(data.get("identified", False)),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        evidence=list(data.get("evidence", [])),
        credential_fingerprint=str(data.get("credential_fingerprint", "")),
    )


def _context_from_dict(data: Dict[str, Any]) -> ContextInsight:
    data = dict(data or {})
    return ContextInsight(
        environment=_enum_or_default(Environment, data.get("environment"), Environment.UNKNOWN),
        is_test_or_example=bool(data.get("is_test_or_example", False)),
        in_use=data.get("in_use"),
        data_sensitivity=_enum_or_default(
            DataSensitivity, data.get("data_sensitivity"), DataSensitivity.UNKNOWN
        ),
        variable_name=data.get("variable_name"),
        hardcoded_in_source=bool(data.get("hardcoded_in_source", False)),
        project_hint=data.get("project_hint"),
        path_signals=list(data.get("path_signals", [])),
        code_signals=list(data.get("code_signals", [])),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        notes=list(data.get("notes", [])),
    )


def _mapping_from_dict(data: Dict[str, Any]) -> ScopeMapping:
    permission = data.get("permission")
    return ScopeMapping(
        raw_scope=str(data.get("raw_scope", "")),
        permission=PermissionLevel(permission) if permission else None,
        description=str(data.get("description", "")),
        inferred=bool(data.get("inferred", False)),
    )


def _permissions_from_dict(data: Dict[str, Any]) -> PermissionProfile:
    data = dict(data or {})
    permissions = [
        _enum_or_default(PermissionLevel, value, None)
        for value in data.get("permissions", [])
    ]
    return PermissionProfile(
        raw_scopes=list(data.get("raw_scopes", [])),
        permissions=[p for p in permissions if p is not None],
        mappings=[_mapping_from_dict(m) for m in data.get("mappings", [])],
        unknown_scopes=list(data.get("unknown_scopes", [])),
        assumed=bool(data.get("assumed", False)),
    )


def _blast_radius_from_dict(data: Dict[str, Any]) -> BlastRadiusReport:
    data = dict(data or {})
    fields = set(BlastRadiusReport.__dataclass_fields__)
    return BlastRadiusReport(**{k: v for k, v in data.items() if k in fields})


#: `ChangePreviewSnapshot.finding`에 보존된 필드 → `SecretFinding` 재구성.
def _finding_from_snapshot(
    analysis_dict: Dict[str, Any], finding_snapshot: Dict[str, Any]
) -> SecretFinding:
    discovery = analysis_dict.get("discovery") or {}
    return SecretFinding(
        secret_type=str(finding_snapshot.get("secret_type", "")),
        provider=str(finding_snapshot.get("provider") or discovery.get("provider") or "unknown"),
        masked_value=str(analysis_dict.get("masked_value", "")),
        fingerprint=str(analysis_dict.get("fingerprint", "")),
        file_path=str(analysis_dict.get("file_path", "")),
        line_number=int(analysis_dict.get("line_number", 0) or 0),
        credential_active=finding_snapshot.get("credential_active"),
        credential_revoked=finding_snapshot.get("credential_revoked"),
        raw_scopes=list(finding_snapshot.get("raw_scopes", [])),
        credential_detail=finding_snapshot.get("credential_detail"),
        occurrence_count=int(finding_snapshot.get("occurrence_count", 1) or 1),
        duplicate_locations=list(finding_snapshot.get("duplicate_locations", [])),
        status=_enum_or_default(
            ResolutionStatus, finding_snapshot.get("status"), ResolutionStatus.NEW
        ),
        detected_at=str(finding_snapshot.get("detected_at") or ""),
    )


def _reconstruct_context(
    analysis_dict: Dict[str, Any], *, config: Optional[PolicyConfig] = None
) -> Optional[EvaluationContext]:
    """저장된 `NHIAnalysis.to_dict()` → 재현용 `EvaluationContext`.

    `replay_snapshot`이 비어 있으면(이 기능 도입 이전 분석 등) `None`을
    반환한다 — 재현할 입력이 없다는 뜻이고, 호출부가 `applicable=False`로
    처리해야 한다. `usage_analysis`/`security_events`/`scenario_matches`는
    재현 입력에 없으므로 항상 비워 둔다(상단 모듈 docstring 참고) — before와
    after를 같은 축소 입력으로 계산해야 둘의 차이가 조치 효과만 반영한다.
    """
    replay = analysis_dict.get("replay_snapshot") or {}
    signals_data = replay.get("signals")
    finding_data = replay.get("finding")
    if not signals_data and not finding_data:
        return None

    profile = _profile_from_dict(analysis_dict.get("discovery") or {})
    context = _context_from_dict(analysis_dict.get("context_analysis") or {})
    permissions = _permissions_from_dict(analysis_dict.get("permission_detail") or {})
    signals = AnalysisSignals.from_dict(signals_data)
    finding = _finding_from_snapshot(analysis_dict, finding_data or {})
    blast_radius = _blast_radius_from_dict(analysis_dict.get("blast_radius") or {})
    source = _enum_or_default(
        AnalysisSource, analysis_dict.get("source"), AnalysisSource.CODE_SCAN
    )

    return EvaluationContext(
        finding=finding,
        profile=profile,
        context=context,
        permissions=permissions,
        signals=signals,
        blast_radius=blast_radius,
        config=config or PolicyConfig(),
        declared_permissions=list(permissions.permissions),
        observed_permissions=[],
        source=source,
        usage_analysis=None,
        security_events=[],
        scenario_matches=None,
    )


def _evaluate(
    ctx: EvaluationContext,
) -> tuple[List[PolicyViolation], RiskAssessment, Any, BlastRadiusReport]:
    """같은 ctx로 정책 위반 → 위험 점수 → 정책 결정 → Blast Radius를 재계산한다.

    `agents/pipeline.py::_assess()`가 실제 분석에서 쓰는 것과 동일한
    `RiskScoringAgent`/`PolicyEvidenceAgent`/`BlastRadiusCalculator`를
    그대로 재사용한다 — Change Preview 전용 점수·정책 로직은 없다.
    """
    violations = evaluate_policies(ctx)
    risk = RiskScoringAgent().score(ctx, violations)
    policy = PolicyEvidenceAgent(engine=DecisionEngine()).decide(ctx, risk, violations)
    blast = BlastRadiusCalculator().compute(
        ctx.finding, ctx.profile, ctx.permissions, ctx.context, ctx.signals
    )
    return violations, risk, policy, blast


# ---------------------------------------------------------------------------
# 서비스 의존성 / 영향받을 수 있는 작업 — 확인되지 않으면 unknown으로 둔다
# ---------------------------------------------------------------------------
def _service_dependency_impact(
    action: RecommendedAction,
    effect: Optional[ActionEffect],
    before_ctx: EvaluationContext,
    before_blast: BlastRadiusReport,
) -> List[ImpactItem]:
    items: List[ImpactItem] = []
    reduces_access = effect is not None and action in _ACCESS_REDUCING_ACTIONS

    for service in before_blast.connected_services:
        if not reduces_access:
            items.append(
                ImpactItem(
                    name=service,
                    confidence=ImpactConfidence.CALCULATED,
                    detail="이 조치는 접근 권한 범위를 줄이지 않아 이 서비스와의 연결에는 영향이 없습니다.",
                )
            )
            continue

        in_use = before_ctx.context.in_use
        if in_use is True:
            items.append(
                ImpactItem(
                    name=service,
                    confidence=ImpactConfidence.ESTIMATED,
                    detail="현재 사용 중으로 표시된 서비스입니다 — 접근이 줄어들면 연동이 끊길 수 있으나 "
                    "실제 중단 여부는 재검증이 필요합니다.",
                )
            )
        elif in_use is False:
            items.append(
                ImpactItem(
                    name=service,
                    confidence=ImpactConfidence.ESTIMATED,
                    detail="최근 미사용으로 표시된 서비스입니다 — 다른 시스템의 의존 여부까지는 "
                    "재검증 전에는 단정할 수 없습니다.",
                )
            )
        else:
            items.append(
                ImpactItem(
                    name=service,
                    confidence=ImpactConfidence.UNKNOWN,
                    detail="사용 여부 자체가 확인되지 않아 이 서비스에 대한 영향을 판단할 수 없습니다.",
                )
            )
    return items


def _affected_operations(
    action: RecommendedAction,
    effect: Optional[ActionEffect],
    before_ctx: EvaluationContext,
    before_blast: BlastRadiusReport,
) -> List[ImpactItem]:
    items: List[ImpactItem] = []
    reduces_access = effect is not None and action in _ACCESS_REDUCING_ACTIONS

    if before_ctx.profile.linked_ai_agent:
        items.append(
            ImpactItem(
                name=f"AI Agent '{before_ctx.profile.linked_ai_agent}' 연계 작업",
                confidence=ImpactConfidence.UNKNOWN,
                detail="이 Credential을 사용하는 자동화 작업이 있는지 확인되지 않습니다 — "
                "적용 전 Agent 책임자 확인이 필요합니다.",
            )
        )

    if reduces_access and before_blast.accessible_resources > 0:
        items.append(
            ImpactItem(
                name="이 Credential로 접근 가능한 자원을 사용하는 작업",
                confidence=ImpactConfidence.UNKNOWN,
                detail=(
                    f"접근 가능 자원 {before_blast.accessible_resources}건에 대해 이 Credential에 "
                    "의존하는 작업(CI 파이프라인, 외부 연동 등)이 있는지는 확인되지 않습니다."
                ),
            )
        )
    return items


# ---------------------------------------------------------------------------
# 공개 API
# ---------------------------------------------------------------------------
def build_change_preview(
    nhi_id: str,
    analysis_snapshot: Dict[str, Any],
    *,
    config: Optional[PolicyConfig] = None,
) -> ChangePreviewResult:
    """저장된 분석 snapshot(`NHIAnalysis.to_dict()`)으로 조치 적용 전·후를 비교한다.

    실제 Credential/권한은 전혀 바꾸지 않는다 — `analysis_snapshot`을 읽고
    메모리에서 가정 상태를 만든 뒤 계산만 한다. `applicable=False`면
    (재현 입력이 없거나 이 조치에 대한 효과가 정의되지 않음) after 값은
    before와 동일하게 채워지고, 그 이유가 `not_applicable_reason`에 남는다.
    """
    action = _enum_or_default(
        RecommendedAction,
        analysis_snapshot.get("recommended_action"),
        RecommendedAction.MONITOR,
    )
    result = ChangePreviewResult(target_nhi_id=nhi_id, action=action)

    before_ctx = _reconstruct_context(analysis_snapshot, config=config)
    if before_ctx is None:
        result.applicable = False
        result.not_applicable_reason = (
            "이 분석에는 Change Preview 재현에 필요한 입력 스냅샷이 없습니다 "
            "(이 기능 도입 이전에 저장된 분석이거나 입력이 비어 있음). 재분석 후 다시 시도하세요."
        )
        result.unknown_notes.append(
            "가정 상태를 계산할 입력이 없어 before/after 값을 확인할 수 없습니다."
        )
        return result

    before_violations, before_risk, before_policy, before_blast = _evaluate(before_ctx)

    effect = ACTION_EFFECTS.get(action)
    after_ctx = copy.deepcopy(before_ctx)
    if effect is None:
        result.applicable = False
        result.not_applicable_reason = (
            f"'{action.value}' 조치에 대한 Change Preview 효과가 아직 정의되지 않았습니다 — "
            "after 값은 before와 동일합니다."
        )
    else:
        effect(after_ctx)

    after_violations, after_risk, after_policy, after_blast = _evaluate(after_ctx)

    result.permissions_before = before_ctx.permissions
    result.permissions_after = after_ctx.permissions
    result.risk_before = before_risk
    result.risk_after = after_risk
    result.policy_before = before_policy
    result.policy_after = after_policy
    result.blast_radius_before = before_blast
    result.blast_radius_after = after_blast

    before_ids = {v.policy_id for v in before_violations}
    after_ids = {v.policy_id for v in after_violations}
    result.resolved_violations = sorted(before_ids - after_ids)
    result.new_violations = sorted(after_ids - before_ids)
    result.unchanged_violations = sorted(before_ids & after_ids)

    result.calculated_notes.append(
        "risk/policy/blast_radius의 before·after는 실제로 조치를 적용하지 않고, "
        "같은 정책·위험도·영향범위 엔진을 가정 상태로 재실행해 계산한 값입니다."
    )
    result.estimated_notes.append(
        "usage_analysis/보안 이벤트 분석은 재현 입력에 포함되지 않아 이번 계산에서 제외되었습니다 — "
        "원래 저장된 분석의 risk_score와 다를 수 있습니다."
    )
    result.unknown_notes.append(
        "이 Credential을 사용하는 다른 시스템(CI 파이프라인, 외부 연동 등)에 대한 실시간 의존성 "
        "데이터가 없어 service_dependency_impact/affected_operations의 unknown 항목은 최소 추정치입니다."
    )

    result.service_dependency_impact = _service_dependency_impact(
        action, effect, before_ctx, before_blast
    )
    result.affected_operations = _affected_operations(action, effect, before_ctx, before_blast)

    return result


def build_dry_run_response(
    nhi_id: str,
    record: Dict[str, Any],
    analysis_snapshot: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """`POST /nhi/{nhi_id}/dry-run` 응답 조립 — 기존 API 하위 호환 지점.

    기존 5개 필드(`target_nhi_id`/`recommended_action`/`expected_changes`/
    `risk_before`/`risk_after_estimate`)는 `build_dry_run_result()`가 만들던
    그대로 항상 채운다 — 값과 의미를 바꾸지 않는다. `analysis_snapshot`
    (`get_latest_analysis_snapshot()` 결과)이 있을 때만 `change_preview` 키를
    추가로 담아 calculated/estimated/unknown 구분과 서비스 영향 분석을
    제공한다. snapshot이 없으면(분석 이력 없음) 기존 응답과 완전히 동일하다.
    snapshot이 있어도 `replay_snapshot`이 없는 과거 분석이면
    `change_preview.applicable=False`로 안전하게 표시될 뿐, 이 함수가 예외를
    던지지는 않는다.
    """
    response = build_dry_run_result(nhi_id, record)
    if analysis_snapshot is not None:
        response["change_preview"] = build_change_preview(nhi_id, analysis_snapshot).to_dict()
    return response
