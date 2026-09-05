"""정책 규칙 정의 — 정책 위반 판정 + 강제 Critical 규칙.

여기서는 "판정"만 하고 "조치 결정"은 `policy/decision_engine.py` 가 맡는다.
초기 구현은 순수 Python 규칙이며, 규칙 표현식을 외부화해야 하면
`POLICIES` / `FORCED_CRITICAL_RULES` 를 OPA(Rego) 또는 Cerbos 정책으로
옮기고 이 모듈은 어댑터만 남기면 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from core.models import SecretFinding
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    BlastRadiusReport,
    ContextInsight,
    DataSensitivity,
    Environment,
    NHIProfile,
    NHIType,
    PermissionLevel,
    PermissionProfile,
    PolicyViolation,
    RiskLevel,
    ScenarioMatch,
    SecurityEvent,
    SecurityEventType,
    UsageAnalysisResult,
    days_since,
)


@dataclass
class PolicyConfig:
    """조직 정책 파라미터. 환경에 맞게 조정한다."""

    require_owner: bool = True
    #: Token 최대 수명 (일)
    max_token_age_days: int = 365
    #: Rotation 주기 (일)
    rotation_period_days: int = 90
    #: 관리자 Scope 를 허용할 NHI 유형
    admin_scope_allowed_types: Sequence[NHIType] = ()
    #: 프로젝트별 Token 분리 강제
    require_project_isolation: bool = True
    #: 미사용으로 간주할 기간 (일)
    inactive_days: int = 90
    #: 이 개수 이상의 저장소에 접근하면 "광범위 접근" 으로 본다 (인벤토리 입력 기준)
    broad_repository_access_threshold: int = 5
    #: 자동 조치를 허용할 최대 위험 점수 (초과 시 사람 검토)
    auto_remediation_max_score: int = 79
    #: 사람 검토가 필요한 최소 위험 점수
    human_review_min_score: int = 60


@dataclass
class EvaluationContext:
    """정책·점수 계산에 필요한 모든 입력을 한 곳에 모은 번들."""

    finding: SecretFinding
    profile: NHIProfile
    context: ContextInsight
    permissions: PermissionProfile
    signals: AnalysisSignals = field(default_factory=AnalysisSignals)
    blast_radius: BlastRadiusReport = field(default_factory=BlastRadiusReport)
    config: PolicyConfig = field(default_factory=PolicyConfig)
    #: NHI 에 승인된 권한 (Scope Translation 으로 정규화된 값)
    declared_permissions: List[PermissionLevel] = field(default_factory=list)
    #: 감사 로그에서 관측된 실제 행위 권한
    observed_permissions: List[PermissionLevel] = field(default_factory=list)
    #: 분석 대상이 코드 스캔 결과인가, NHI 인벤토리 입력인가
    source: AnalysisSource = AnalysisSource.CODE_SCAN
    #: 독립된 Usage → Event → Scenario 분석 산출물. None은 해당 단계 미실행.
    usage_analysis: Optional[UsageAnalysisResult] = None
    security_events: List[SecurityEvent] = field(default_factory=list)
    scenario_matches: Optional[List[ScenarioMatch]] = None

    # -- 파생 값 --------------------------------------------------------
    @property
    def from_code_scan(self) -> bool:
        """저장소 코드에서 실제로 Secret 이 발견된 건인가."""
        return self.source is AnalysisSource.CODE_SCAN

    @property
    def accessible_repositories(self) -> List[Dict[str, object]]:
        """NHI 가 접근할 수 있는 저장소 목록 (인벤토리 입력에서만 채워진다)."""
        items = self.signals.extra.get("repositories") if self.signals.extra else None
        if not isinstance(items, (list, tuple)):
            return []
        return [item for item in items if isinstance(item, dict)]

    @property
    def accessible_resources(self) -> List[Dict[str, object]]:
        """공급자 중립 인벤토리에서 확인한 접근 자원 목록."""
        items = self.signals.extra.get("accessible_resources") if self.signals.extra else None
        if not isinstance(items, (list, tuple)):
            detail = self.finding.credential_detail or {}
            items = detail.get("accessible_resources")
        if not isinstance(items, (list, tuple)):
            return []
        return [item for item in items if isinstance(item, dict)]

    @property
    def shared_projects(self) -> List[str]:
        return derive_shared_projects(self.finding, self.signals)

    @property
    def token_age_days(self) -> Optional[int]:
        return days_since(self.signals.created_at)

    @property
    def days_since_rotation(self) -> Optional[int]:
        return days_since(self.signals.last_rotated_at or self.signals.created_at)

    @property
    def days_since_use(self) -> Optional[int]:
        return days_since(self.signals.last_used_at)

    @property
    def has_admin(self) -> bool:
        return self.permissions.has(PermissionLevel.ADMIN)

    @property
    def is_active(self) -> Optional[bool]:
        """자격 증명이 살아있는가. 외부 검증 결과 우선, 없으면 문맥 판단."""
        if self.finding.credential_active is not None:
            return self.finding.credential_active
        return self.context.in_use

    def scenario(self, scenario_id: str) -> Optional[ScenarioMatch]:
        if self.scenario_matches is None:
            return None
        return next(
            (
                match
                for match in self.scenario_matches
                if match.matched and match.scenario_id == scenario_id
            ),
            None,
        )


def derive_shared_projects(finding: SecretFinding, signals: AnalysisSignals) -> List[str]:
    """동일 Credential 이 걸쳐 있는 프로젝트 목록.

    같은 Repository 안의 중복 노출은 "프로젝트 공유"가 아니므로 세지 않는다.
    외부 신호(`shared_projects`) 또는 중복 위치에 명시된 `repository` 만 근거로 삼는다.
    """
    projects: List[str] = []

    def _add(name: object) -> None:
        if isinstance(name, str) and name.strip() and name.strip() not in projects:
            projects.append(name.strip())

    for name in signals.shared_projects:
        _add(name)

    if not projects:
        _add(signals.repository or signals.project)
        for location in finding.duplicate_locations:
            _add(location.get("repository"))
        if len(projects) < 2:
            return projects
    return projects


# ---------------------------------------------------------------------------
# 정책 위반 판정
# ---------------------------------------------------------------------------
def _owner_required(ctx: EvaluationContext) -> Optional[PolicyViolation]:
    if not ctx.config.require_owner or ctx.profile.owner:
        return None
    return PolicyViolation(
        policy_id="OWNER_REQUIRED",
        name="Owner 필수 정책",
        detail=(
            "NHI 에 책임자가 지정되어 있지 않다. "
            f"후보: {', '.join(ctx.profile.owner_candidates[:3]) or '없음'}"
        ),
        severity=RiskLevel.HIGH,
        remediable=False,  # 사람이 지정해야 한다
    )


def _max_token_age(ctx: EvaluationContext) -> Optional[PolicyViolation]:
    age = ctx.token_age_days
    if age is None or age <= ctx.config.max_token_age_days:
        return None
    return PolicyViolation(
        policy_id="TOKEN_MAX_AGE",
        name="Token 최대 수명 정책",
        detail=f"발급 후 {age}일 경과 (허용 {ctx.config.max_token_age_days}일)",
        severity=RiskLevel.HIGH,
    )


def _rotation_period(ctx: EvaluationContext) -> Optional[PolicyViolation]:
    days = ctx.days_since_rotation
    if days is None:
        # 회전 이력 자체가 없고 만료일도 없으면 위반으로 본다.
        if ctx.signals.expires_at or ctx.finding.credential_active is not True:
            return None
        return PolicyViolation(
            policy_id="ROTATION_PERIOD",
            name="Rotation 주기 정책",
            detail="회전 이력과 만료일이 모두 없다 (무기한 유효 Token)",
            severity=RiskLevel.MEDIUM,
        )
    if days <= ctx.config.rotation_period_days:
        return None
    return PolicyViolation(
        policy_id="ROTATION_PERIOD",
        name="Rotation 주기 정책",
        detail=f"마지막 회전 후 {days}일 경과 (주기 {ctx.config.rotation_period_days}일)",
        severity=RiskLevel.MEDIUM,
    )


def _admin_scope_restricted(ctx: EvaluationContext) -> Optional[PolicyViolation]:
    if not ctx.has_admin:
        return None
    if ctx.profile.nhi_type in tuple(ctx.config.admin_scope_allowed_types):
        return None
    return PolicyViolation(
        policy_id="ADMIN_SCOPE_RESTRICTED",
        name="관리자 Scope 제한 정책",
        detail=(
            f"{ctx.profile.nhi_type.value} 에 관리자 권한이 부여되어 있다. "
            f"원본 scope: {', '.join(ctx.permissions.raw_scopes[:5]) or '미확인(유형 기준 가정)'}"
        ),
        severity=RiskLevel.CRITICAL,
    )


def _project_isolation(ctx: EvaluationContext) -> Optional[PolicyViolation]:
    if not ctx.config.require_project_isolation:
        return None
    projects = ctx.shared_projects
    if len(projects) < 2:
        return None
    return PolicyViolation(
        policy_id="PROJECT_TOKEN_ISOLATION",
        name="프로젝트별 Token 분리 정책",
        detail=f"하나의 Credential 이 {len(projects)}개 프로젝트에서 공유됨: {', '.join(projects[:5])}",
        severity=RiskLevel.HIGH,
    )


def _no_active_credential_in_repository(ctx: EvaluationContext) -> Optional[PolicyViolation]:
    """저장소에 활성 자격 증명이 평문으로 존재하면 안 된다.

    인벤토리 입력은 "코드에 노출됐다" 는 사실 자체가 없으므로 평가하지 않는다.
    근거 없는 위반을 만들지 않는 것이 이 계층의 원칙이다.
    """
    if not ctx.from_code_scan:
        return None
    if ctx.context.is_test_or_example and ctx.finding.credential_active is not True:
        return None
    if ctx.is_active is False:
        return None
    return PolicyViolation(
        policy_id="NO_PLAINTEXT_CREDENTIAL",
        name="평문 자격 증명 금지 정책",
        detail=f"{ctx.finding.file_path}:{ctx.finding.line_number} 에 자격 증명이 평문으로 존재",
        severity=RiskLevel.HIGH if ctx.is_active else RiskLevel.MEDIUM,
    )


#: 정책 ID → 판정 함수
POLICIES: Dict[str, Callable[[EvaluationContext], Optional[PolicyViolation]]] = {
    "OWNER_REQUIRED": _owner_required,
    "TOKEN_MAX_AGE": _max_token_age,
    "ROTATION_PERIOD": _rotation_period,
    "ADMIN_SCOPE_RESTRICTED": _admin_scope_restricted,
    "PROJECT_TOKEN_ISOLATION": _project_isolation,
    "NO_PLAINTEXT_CREDENTIAL": _no_active_credential_in_repository,
}


def evaluate_policies(ctx: EvaluationContext) -> List[PolicyViolation]:
    """전체 정책을 평가해 위반 목록을 만든다 (예외 정책은 제외)."""
    exempted = set(ctx.signals.exempted_policies or [])
    violations: List[PolicyViolation] = []
    for policy_id, rule in POLICIES.items():
        if policy_id in exempted:
            continue
        violation = rule(ctx)
        if violation is not None:
            violations.append(violation)
    return violations


# ---------------------------------------------------------------------------
# 강제 Critical 규칙 — 점수와 무관하게 Critical 로 승격한다
# ---------------------------------------------------------------------------
def _public_repo_active_admin(ctx: EvaluationContext) -> Optional[str]:
    if ctx.signals.repository_public is True and ctx.is_active is True and ctx.has_admin:
        return "공개 Repository 에 활성 Admin Token 노출"
    return None


def _ownerless_sensitive_access(ctx: EvaluationContext) -> Optional[str]:
    sensitive = ctx.context.data_sensitivity in (
        DataSensitivity.RESTRICTED,
        DataSensitivity.CONFIDENTIAL,
    )
    if ctx.profile.owner is None and sensitive:
        return f"Owner 가 없는 NHI 가 {ctx.context.data_sensitivity.value} 데이터에 접근"
    return None


def _terminated_agent_active_token(ctx: EvaluationContext) -> Optional[str]:
    matched = ctx.scenario("TERMINATED_AGENT_ACTIVE_TOKEN")
    if matched is not None:
        return matched.reason
    status = (ctx.signals.agent_status or "").lower()
    if status in ("terminated", "deleted", "decommissioned", "stopped") and ctx.is_active is True:
        return f"종료된 AI Agent({ctx.signals.agent_name or ctx.profile.linked_ai_agent or '이름 미상'})에 활성 Token 존재"
    return None


def _revoked_token_still_used(ctx: EvaluationContext) -> Optional[str]:
    matched = ctx.scenario("REVOKED_TOKEN_STILL_USED")
    if matched is not None:
        return matched.reason
    if ctx.signals.token_used_after_revocation is True:
        return "폐기 처리된 Token 이 계속 사용되고 있음"
    if ctx.usage_analysis is not None and ctx.usage_analysis.used_after_revocation is True:
        return "폐기 시각 이후의 사용 기록이 확인됨"
    return None


def _token_replay_suspected(ctx: EvaluationContext) -> Optional[str]:
    matched = ctx.scenario("TOKEN_REPLAY_SUSPECTED")
    if matched is not None:
        return matched.reason
    if ctx.signals.token_replay_suspected is True:
        binding = ctx.signals.token_binding_method or "미적용/미상"
        source = ctx.signals.request_source_ip or "출처 미상"
        return f"탈취 token 또는 proof 재사용 의심 요청 탐지 (binding={binding}, source={source})"
    return None


def _shared_across_projects(ctx: EvaluationContext) -> Optional[str]:
    matched = ctx.scenario("TOKEN_SHARED_ACROSS_PROJECTS")
    if matched is not None:
        return matched.reason
    projects = ctx.shared_projects
    if len(projects) >= 2:
        return f"하나의 Token 이 여러 프로젝트에서 공유됨: {', '.join(projects[:5])}"
    return None


def _read_only_nhi_mutates(ctx: EvaluationContext) -> Optional[str]:
    matched = ctx.scenario("READ_ONLY_NHI_PERFORMS_MUTATION")
    if matched is not None:
        return matched.reason
    declared = set(ctx.declared_permissions)
    if declared and declared <= {PermissionLevel.READ}:
        mutating = {PermissionLevel.WRITE, PermissionLevel.DELETE, PermissionLevel.ADMIN}
        observed = set(ctx.observed_permissions) & mutating
        if observed:
            names = ", ".join(sorted(p.value for p in observed))
            return f"조회 전용 NHI 가 {names} 행위를 수행함"
    return None


#: 규칙 ID → 판정 함수 (반환값은 사람이 읽는 근거 문장)
FORCED_CRITICAL_RULES: Dict[str, Callable[[EvaluationContext], Optional[str]]] = {
    "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN": _public_repo_active_admin,
    "OWNERLESS_SENSITIVE_DATA_ACCESS": _ownerless_sensitive_access,
    "TERMINATED_AGENT_ACTIVE_TOKEN": _terminated_agent_active_token,
    "REVOKED_TOKEN_STILL_USED": _revoked_token_still_used,
    "TOKEN_REPLAY_SUSPECTED": _token_replay_suspected,
    "TOKEN_SHARED_ACROSS_PROJECTS": _shared_across_projects,
    "READ_ONLY_NHI_PERFORMS_MUTATION": _read_only_nhi_mutates,
}


def evaluate_forced_critical(ctx: EvaluationContext) -> List[Dict[str, str]]:
    """강제 Critical 규칙 평가.

    예제/테스트 값이면서 자격 증명이 활성이 아닌 경우는 오탐이므로 평가하지 않는다.
    """
    if ctx.context.is_test_or_example and ctx.finding.credential_active is not True:
        return []

    hits: List[Dict[str, str]] = []
    for rule_id, rule in FORCED_CRITICAL_RULES.items():
        reason = rule(ctx)
        if reason:
            hits.append({"rule_id": rule_id, "reason": reason})
    return hits


_SCENARIO_NAMES: Dict[str, str] = {
    "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN": "공개 저장소의 활성 Admin Token",
    "OWNERLESS_SENSITIVE_DATA_ACCESS": "Owner 없는 민감 데이터 접근",
    "TERMINATED_AGENT_ACTIVE_TOKEN": "종료 Agent 자격 증명 잔존",
    "REVOKED_TOKEN_STILL_USED": "폐기 Token 지속 사용",
    "TOKEN_REPLAY_SUSPECTED": "탈취 Token/Proof 재사용",
    "TOKEN_SHARED_ACROSS_PROJECTS": "프로젝트 간 Token 공유",
    "READ_ONLY_NHI_PERFORMS_MUTATION": "조회 전용 NHI의 변경 행위",
}

_SCENARIO_EVENT_TYPES: Dict[str, SecurityEventType] = {
    "PUBLIC_REPO_ACTIVE_ADMIN_TOKEN": SecurityEventType.HIGH_RISK_SCOPE_GRANTED,
    "OWNERLESS_SENSITIVE_DATA_ACCESS": SecurityEventType.OWNER_MISSING,
    "TERMINATED_AGENT_ACTIVE_TOKEN": SecurityEventType.TERMINATED_AGENT_CREDENTIAL_USE,
    "REVOKED_TOKEN_STILL_USED": SecurityEventType.REVOKED_CREDENTIAL_USE,
    "TOKEN_REPLAY_SUSPECTED": SecurityEventType.TOKEN_REPLAY,
    "TOKEN_SHARED_ACROSS_PROJECTS": SecurityEventType.CROSS_PROJECT_CREDENTIAL_USE,
    "READ_ONLY_NHI_PERFORMS_MUTATION": SecurityEventType.UNDECLARED_PERMISSION_USE,
}


def evaluate_security_scenarios(ctx: EvaluationContext) -> List[ScenarioMatch]:
    """강제 Critical 규칙과 동일한 판정에서 ScenarioMatch를 구성한다.

    Usage Agent의 event 기반 임시 매핑을 다시 신뢰하지 않고 canonical rule을 한 번
    평가하므로 ``scenario_matches``와 ``risk.forced_rules``가 어긋나지 않는다.
    """
    previous = ctx.scenario_matches
    ctx.scenario_matches = []
    try:
        hits = evaluate_forced_critical(ctx)
    finally:
        ctx.scenario_matches = previous

    scenarios: List[ScenarioMatch] = []
    hit_ids = {item["rule_id"] for item in hits}
    for hit in hits:
        rule_id = hit["rule_id"]
        event_type = _SCENARIO_EVENT_TYPES.get(rule_id)
        related = [
            event
            for event in ctx.security_events
            if event_type is not None and event.event_type is event_type
        ]
        scenarios.append(
            ScenarioMatch(
                scenario_id=rule_id,
                name=_SCENARIO_NAMES[rule_id],
                severity=RiskLevel.CRITICAL,
                confidence=max((event.confidence for event in related), default=1.0),
                reason=hit["reason"],
                event_ids=[event.event_id for event in related],
                evidence=[
                    evidence for event in related for evidence in event.evidence
                ]
                or [hit["reason"]],
                forced_critical=True,
                category="forced_critical",
            )
        )

    # 일반 Scope 초과는 이벤트로 남기되 강제 Critical 시나리오와 구분한다.
    if "READ_ONLY_NHI_PERFORMS_MUTATION" not in hit_ids:
        for event in ctx.security_events:
            if event.event_type is not SecurityEventType.UNDECLARED_PERMISSION_USE:
                continue
            scenarios.append(
                ScenarioMatch(
                    scenario_id="OBSERVED_ACTION_EXCEEDS_DECLARED_SCOPE",
                    name="승인 Scope 초과 행위",
                    severity=event.severity,
                    confidence=event.confidence,
                    reason=event.detail,
                    event_ids=[event.event_id],
                    evidence=list(event.evidence),
                    forced_critical=False,
                    category="usage_anomaly",
                )
            )

    # 점수를 다시 더하지 않는 설명용 시나리오다. 기존 Risk factor와 강제 규칙이
    # 점수의 단일 진실 공급원이며, 아래 결과는 변화 추적과 대응 근거에만 사용한다.
    used_event_ids = {
        event_id for scenario in scenarios for event_id in scenario.event_ids
    }
    descriptive = {
        SecurityEventType.HIGH_RISK_SCOPE_GRANTED: (
            "HIGH_RISK_SCOPE_GRANTED",
            "고위험 Scope 부여",
            "permission_governance",
        ),
        SecurityEventType.UNUSED_HIGH_PRIVILEGE: (
            "UNUSED_HIGH_PRIVILEGE",
            "실제 사용보다 과도한 고권한",
            "least_privilege",
        ),
        SecurityEventType.STALE_PERMISSION: (
            "STALE_PERMISSION",
            "장기 미사용 권한 잔존",
            "lifecycle",
        ),
        SecurityEventType.OWNER_MISSING: (
            "OWNER_MISSING",
            "책임자 없는 NHI",
            "ownership",
        ),
    }
    for event in ctx.security_events:
        if event.event_id in used_event_ids or event.event_type not in descriptive:
            continue
        scenario_id, name, category = descriptive[event.event_type]
        scenarios.append(
            ScenarioMatch(
                scenario_id=scenario_id,
                name=name,
                severity=event.severity,
                confidence=event.confidence,
                reason=event.detail,
                event_ids=[event.event_id],
                evidence=list(event.evidence),
                forced_critical=False,
                category=category,
            )
        )
    return scenarios


def is_inactive_nhi(ctx: EvaluationContext) -> bool:
    """장기간 사용되지 않은 NHI 인가."""
    status = (ctx.signals.agent_status or "").lower()
    if status in ("terminated", "deleted", "decommissioned", "stopped"):
        return True
    days = ctx.days_since_use
    return days is not None and days > ctx.config.inactive_days


def is_production(ctx: EvaluationContext) -> bool:
    return ctx.context.environment is Environment.PRODUCTION
