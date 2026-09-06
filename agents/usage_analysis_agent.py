"""사용 행위 분석 → 보안 이벤트 추출.

원시 감사 로그 전체를 보관하거나 LLM으로 분류하지 않는다. ``AnalysisSignals``에
들어온 관측 사실을 공통 권한으로 변환하고 결정적인 규칙으로 이벤트를 만든다.
ScenarioMatch는 ``policy.rules.evaluate_security_scenarios``가 강제 Critical 규칙과
같은 canonical 판정 결과에서 한 번만 구성한다.

이 파일에는 클래스가 두 개 있다:
  * ``UsageAnalysisAgent`` (canonical) — 위 설명대로 `EvaluationContext`/
    강제 Critical 규칙과 깊게 연결된 종합 Usage → SecurityEvent 분석기다.
  * ``PermissionUsageAgent`` — `agents/event_extraction_agent.py`/
    `agents/scenario_mapping_agent.py`가 쓰는, 승인 권한과 관측 행위를 단순
    비교하는 별도 분석기다. 원래 이름이 `UsageAnalysisAgent`로 동일해
    병합 시 충돌했던 것을 여기서만 이름을 바꿔 분리했다 — 산출물 타입도
    `core.nhi_models.PermissionUsageResult`로 별도다
    (`core.nhi_models.UsageAnalysisResult`와는 다른 클래스).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

from agents.scope_translation_agent import ScopeTranslationAgent, expand_permissions
from core.models import SecretFinding
from core.nhi_models import (
    AnalysisSignals,
    NHIProfile,
    PERMISSION_RANK,
    PermissionLevel,
    PermissionProfile,
    PermissionUsageResult,
    RiskLevel,
    SecurityEvent,
    SecurityEventType,
    UsageAnalysisResult,
    days_since,
    parse_dt,
)
from security.redaction import sanitize_security_text, sanitize_security_value


_TERMINATED_STATUSES = {"terminated", "deleted", "decommissioned", "stopped"}
_MUTATING_PERMISSIONS = {
    PermissionLevel.WRITE,
    PermissionLevel.DELETE,
    PermissionLevel.ADMIN,
}
_HIGH_PRIVILEGE_PERMISSIONS = {PermissionLevel.DELETE, PermissionLevel.ADMIN}
_ACTIVE_MAX_DAYS = 30
_WARNING_MAX_DAYS = 90


class UsageAnalysisAgent:
    """승인 권한과 실제 행위를 비교하고 보안 이벤트를 식별한다."""

    def __init__(self, translator: Optional[ScopeTranslationAgent] = None) -> None:
        self.translator = translator or ScopeTranslationAgent()

    def analyze(
        self,
        finding: SecretFinding,
        profile: NHIProfile,
        permissions: PermissionProfile,
        signals: AnalysisSignals,
    ) -> Tuple[UsageAnalysisResult, List[SecurityEvent]]:
        signal_declared = self._normalize_permissions(
            signals.declared_permissions, provider=finding.provider
        )
        observed = self._normalize_permissions(
            signals.observed_actions, provider=finding.provider
        )

        # 조직이 직접 제공한 승인 baseline이 최우선이다. 없으면 실제 Scope 번역
        # 결과를 사용하되, 유형 기반 가정 Scope는 초과 판정 근거로 쓰지 않는다.
        if signal_declared:
            declared = signal_declared
            baseline_source = "approved_signal"
            comparison_complete = True
        elif permissions.permissions and not permissions.assumed:
            declared = list(permissions.permissions)
            baseline_source = "granted_scope"
            comparison_complete = True
        elif permissions.permissions:
            declared = list(permissions.permissions)
            baseline_source = "assumed_scope"
            comparison_complete = False
        else:
            declared = []
            baseline_source = "unavailable"
            comparison_complete = False

        allowed = expand_permissions(declared)
        unexpected = [
            item for item in observed if comparison_complete and item not in allowed
        ]
        data_complete = signals.extra.get("usage_data_complete") is True
        # 일부 로그만 보고 권한이 "미사용"이라고 단정하면 최소 권한 권고가 오판된다.
        # 승인 기준과 분석 기간의 사용 이력이 모두 완전한 경우에만 계산한다.
        unused = [
            item
            for item in declared
            if comparison_complete and data_complete and item not in observed
        ]
        activity_status = self._activity_status(profile, signals, data_complete)
        raw_sources = signals.extra.get("usage_sources")
        sources = (
            [
                sanitize_security_text(item)
                for item in raw_sources
                if isinstance(item, str) and item.strip()
            ]
            if isinstance(raw_sources, (list, tuple))
            else []
        )
        if not sources and signals.observed_actions:
            sources = ["analysis_signals.observed_actions"]

        evidence = [
            f"권한 기준 {len(declared)}종({baseline_source}), 관측 권한 {len(observed)}종"
        ]
        if not signals.observed_actions:
            if signals.last_used_at:
                evidence.append("최근 사용 시각만 제공됨 — 구체 행위·권한은 미확인")
            else:
                evidence.append("관측 행위 로그 미제공 — 이상 없음으로 간주하지 않음")
        elif not comparison_complete:
            evidence.append("신뢰할 수 있는 승인 권한 기준이 없어 초과 여부 판단 불가")
        elif unexpected:
            evidence.append(
                "승인 범위 밖 권한: " + ", ".join(item.value for item in unexpected)
            )
        else:
            evidence.append("제공된 관측 행위에서 승인 권한 초과를 확인하지 못함")

        if unused:
            evidence.append(
                "완전한 사용 이력에서 미사용 권한 확인: "
                + ", ".join(item.value for item in unused)
            )
        elif not data_complete:
            evidence.append("사용 이력이 불완전하여 미사용 권한은 판정하지 않음")
        evidence.append(f"활동 상태: {activity_status}")

        if signals.sender_constrained is None:
            evidence.append("Sender constraint 적용 여부 미확인")
        else:
            method = sanitize_security_text(signals.token_binding_method or "방식 미상")
            evidence.append(
                f"Sender constraint: {'적용' if signals.sender_constrained else '미적용'} ({method})"
            )

        used_after_revocation = self._used_after_revocation(finding, signals)
        sanitized_actions = [
            sanitize_security_text(item)
            for item in signals.observed_actions
            if isinstance(item, str) and item.strip()
        ]
        usage = UsageAnalysisResult(
            declared_permissions=declared,
            permission_baseline_source=baseline_source,
            permission_comparison_complete=comparison_complete,
            observed_permissions=observed,
            observed_actions=sanitized_actions,
            unexpected_permissions=unexpected,
            unused_permissions=unused,
            activity_status=activity_status,
            mutation_observed=bool(set(observed) & _MUTATING_PERMISSIONS),
            usage_observed=(
                True
                if signals.observed_actions or signals.last_used_at
                else (False if data_complete else None)
            ),
            used_after_revocation=used_after_revocation,
            replay_suspected=signals.token_replay_suspected,
            last_used_at=(
                sanitize_security_text(signals.last_used_at)
                if signals.last_used_at
                else None
            ),
            sender_constrained=signals.sender_constrained,
            token_binding_method=(
                sanitize_security_text(signals.token_binding_method)
                if signals.token_binding_method
                else None
            ),
            source_ip=(
                sanitize_security_text(signals.request_source_ip)
                if signals.request_source_ip
                else None
            ),
            user_agent=(
                sanitize_security_text(signals.request_user_agent)
                if signals.request_user_agent
                else None
            ),
            data_complete=data_complete,
            confidence=(
                0.95
                if data_complete
                else (
                    0.75
                    if signals.observed_actions
                    else (0.6 if signals.last_used_at else 0.35)
                )
            ),
            sources=sources,
            evidence=evidence,
        )
        events = self._extract_events(finding, profile, signals, usage)
        return usage, events

    def _extract_events(
        self,
        finding: SecretFinding,
        profile: NHIProfile,
        signals: AnalysisSignals,
        usage: UsageAnalysisResult,
    ) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []

        if signals.token_replay_suspected is True:
            binding = sanitize_security_text(
                signals.token_binding_method or "미적용/미상"
            )
            source = sanitize_security_text(signals.request_source_ip or "출처 미상")
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.TOKEN_REPLAY,
                    RiskLevel.CRITICAL,
                    "Token 또는 proof 재사용 의심",
                    f"동일 자격 증명의 재사용 의심 요청 탐지 (binding={binding}, source={source})",
                    evidence=["runtime gateway의 token_replay_suspected=true"],
                    attributes={
                        "binding_method": signals.token_binding_method,
                        "source_ip": signals.request_source_ip,
                        "user_agent": signals.request_user_agent,
                    },
                )
            )

        if usage.used_after_revocation is True:
            explicit = signals.token_used_after_revocation is True
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.REVOKED_CREDENTIAL_USE,
                    RiskLevel.CRITICAL,
                    "폐기된 자격 증명 사용",
                    "폐기 처리 이후의 API 사용 기록이 관측됨",
                    evidence=[
                        "token_used_after_revocation=true"
                        if explicit
                        else (
                            f"revoked_at={signals.revoked_at}, "
                            f"last_used_at={signals.last_used_at}"
                        )
                    ],
                    origin="observed" if explicit else "derived",
                )
            )

        agent_status = (signals.agent_status or "").strip().lower()
        if agent_status in _TERMINATED_STATUSES and finding.credential_active is True:
            agent_name = sanitize_security_text(
                signals.agent_name or profile.linked_ai_agent or profile.nhi_name
            )
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.TERMINATED_AGENT_CREDENTIAL_USE,
                    RiskLevel.CRITICAL,
                    "종료된 Agent의 활성 자격 증명",
                    f"종료 상태 Agent({agent_name})에 활성 자격 증명이 남아 있음",
                    evidence=[f"agent_status={agent_status}", "credential_active=true"],
                    attributes={"agent_name": agent_name, "agent_status": agent_status},
                    origin="control_gap",
                    access_level=self._highest_permission(usage.declared_permissions),
                )
            )

        if usage.unexpected_permissions:
            read_only_mutation = (
                bool(usage.declared_permissions)
                and set(usage.declared_permissions) <= {PermissionLevel.READ}
                and bool(set(usage.observed_permissions) & _MUTATING_PERMISSIONS)
            )
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.UNDECLARED_PERMISSION_USE,
                    RiskLevel.CRITICAL if read_only_mutation else RiskLevel.HIGH,
                    "승인 Scope를 벗어난 행위",
                    "관측 권한이 승인 권한을 초과함: "
                    + ", ".join(item.value for item in usage.unexpected_permissions),
                    evidence=[
                        "declared="
                        + ",".join(item.value for item in usage.declared_permissions),
                        "observed="
                        + ",".join(item.value for item in usage.observed_permissions),
                    ],
                    attributes={"read_only_mutation": read_only_mutation},
                    access_level=self._highest_permission(
                        usage.unexpected_permissions
                    ),
                )
            )

        projects = self._shared_projects(finding, signals)
        if len(projects) >= 2:
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.CROSS_PROJECT_CREDENTIAL_USE,
                    RiskLevel.CRITICAL,
                    "프로젝트 간 자격 증명 공유",
                    f"동일 자격 증명이 {len(projects)}개 프로젝트에 연결됨",
                    evidence=[", ".join(projects[:5])],
                    attributes={"projects": projects},
                    origin="control_gap",
                )
            )

        trusted_high_privilege = [
            item
            for item in usage.declared_permissions
            if item in _HIGH_PRIVILEGE_PERMISSIONS
            and usage.permission_baseline_source in {"approved_signal", "granted_scope"}
        ]
        if trusted_high_privilege:
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.HIGH_RISK_SCOPE_GRANTED,
                    RiskLevel.HIGH,
                    "고위험 Scope 부여",
                    "검증 가능한 권한 기준에 고위험 Scope가 포함됨: "
                    + ", ".join(item.value for item in trusted_high_privilege),
                    evidence=[
                        f"permission_baseline_source={usage.permission_baseline_source}"
                    ],
                    origin="control_gap",
                    access_level=self._highest_permission(trusted_high_privilege),
                )
            )

        unused_high_privilege = [
            item
            for item in usage.unused_permissions
            if item in _HIGH_PRIVILEGE_PERMISSIONS
        ]
        if unused_high_privilege:
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.UNUSED_HIGH_PRIVILEGE,
                    RiskLevel.HIGH,
                    "사용되지 않은 고권한",
                    "완전한 사용 이력에서 사용되지 않은 고권한: "
                    + ", ".join(item.value for item in unused_high_privilege),
                    evidence=["usage_data_complete=true", "permission baseline verified"],
                    origin="derived",
                    access_level=self._highest_permission(unused_high_privilege),
                )
            )

        if usage.activity_status in {"stale", "orphaned_candidate"} and usage.declared_permissions:
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.STALE_PERMISSION,
                    RiskLevel.HIGH
                    if usage.activity_status == "orphaned_candidate"
                    else RiskLevel.MEDIUM,
                    "장기 미사용 권한",
                    f"NHI 활동 상태가 {usage.activity_status}이며 권한이 계속 부여되어 있음",
                    evidence=[f"last_used_at={usage.last_used_at or '관측 없음'}"],
                    origin="derived",
                    access_level=self._highest_permission(usage.declared_permissions),
                )
            )

        if profile.owner is None:
            events.append(
                self._event(
                    finding,
                    signals,
                    SecurityEventType.OWNER_MISSING,
                    RiskLevel.HIGH,
                    "NHI 책임자 미지정",
                    "조직 내 책임자(Owner)가 지정되지 않은 NHI",
                    evidence=["profile.owner=null"],
                    origin="control_gap",
                    access_level=None,
                )
            )

        return events

    def _normalize_permissions(
        self, values: Iterable[str], *, provider: str
    ) -> List[PermissionLevel]:
        result: List[PermissionLevel] = []
        for raw in values or []:
            if not isinstance(raw, str) or not raw.strip():
                continue
            try:
                permission = PermissionLevel(raw.strip().upper())
            except ValueError:
                permission = self.translator.translate_scope(
                    raw, provider=provider
                ).permission
            if permission is not None and permission not in result:
                result.append(permission)
        return result

    @staticmethod
    def _event(
        finding: SecretFinding,
        signals: AnalysisSignals,
        event_type: SecurityEventType,
        severity: RiskLevel,
        title: str,
        detail: str,
        *,
        evidence: Optional[List[str]] = None,
        attributes: Optional[Dict[str, object]] = None,
        origin: str = "observed",
        access_level: Optional[PermissionLevel] = None,
    ) -> SecurityEvent:
        source_event_id = signals.extra.get("usage_source_event_id")
        occurred_at = signals.extra.get("usage_occurred_at")
        source = signals.extra.get("usage_source")
        if not source:
            raw_sources = signals.extra.get("usage_sources")
            if isinstance(raw_sources, (list, tuple)) and raw_sources:
                source = raw_sources[0]

        safe_detail = sanitize_security_text(detail)
        safe_source_event_id = (
            sanitize_security_text(source_event_id) if source_event_id else None
        )
        safe_occurred_at = sanitize_security_text(occurred_at) if occurred_at else None
        material = "|".join(
            (
                finding.fingerprint,
                event_type.value,
                safe_detail,
                safe_source_event_id or safe_occurred_at or "aggregate",
            )
        )
        event_id = "event:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        safe_attributes = sanitize_security_value(dict(attributes or {}))
        return SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            severity=severity,
            title=sanitize_security_text(title),
            detail=safe_detail,
            origin=origin,
            confidence=1.0 if origin == "observed" else 0.9,
            source=sanitize_security_text(source) if source else None,
            source_event_id=safe_source_event_id,
            occurred_at=safe_occurred_at,
            access_level=access_level,
            evidence=[sanitize_security_text(item) for item in (evidence or [])],
            attributes=safe_attributes if isinstance(safe_attributes, dict) else {},
        )

    @staticmethod
    def _used_after_revocation(
        finding: SecretFinding, signals: AnalysisSignals
    ) -> Optional[bool]:
        """명시 신호 또는 검증 가능한 시간 순서가 있을 때만 폐기 후 사용으로 본다."""
        if signals.token_used_after_revocation is not None:
            return signals.token_used_after_revocation
        if finding.credential_revoked is not True:
            return None
        revoked_at = parse_dt(signals.revoked_at)
        last_used_at = parse_dt(signals.last_used_at)
        if revoked_at is None or last_used_at is None:
            return None
        return last_used_at > revoked_at

    @staticmethod
    def _activity_status(
        profile: NHIProfile, signals: AnalysisSignals, data_complete: bool
    ) -> str:
        """최근 사용 시각과 로그 완전성을 이용해 활동 상태를 보수적으로 분류한다."""
        last_used_at = parse_dt(signals.last_used_at)
        reference_at = parse_dt(signals.extra.get("analysis_reference_at"))
        if last_used_at is not None:
            now = reference_at or datetime.now(timezone.utc)
            days = max(0, (now - last_used_at).days)
            if days <= _ACTIVE_MAX_DAYS:
                return "active"
            if days <= _WARNING_MAX_DAYS:
                return "inactive_warning"
            return "orphaned_candidate" if profile.owner is None else "stale"
        if data_complete:
            if signals.observed_actions:
                return "active"
            return "orphaned_candidate" if profile.owner is None else "stale"
        return "unknown"

    @staticmethod
    def _highest_permission(
        permissions: Iterable[PermissionLevel],
    ) -> Optional[PermissionLevel]:
        rank = {
            PermissionLevel.READ: 1,
            PermissionLevel.WRITE: 2,
            PermissionLevel.DELETE: 3,
            PermissionLevel.ADMIN: 4,
        }
        return max(permissions, key=lambda item: rank[item], default=None)

    @staticmethod
    def _shared_projects(
        finding: SecretFinding, signals: AnalysisSignals
    ) -> List[str]:
        projects: List[str] = []

        def add(value: object) -> None:
            if isinstance(value, str) and value.strip():
                sanitized = sanitize_security_text(value.strip())
                if sanitized and sanitized not in projects:
                    projects.append(sanitized)

        for project in signals.shared_projects:
            add(project)
        if not projects:
            add(signals.repository or signals.project)
            for location in finding.duplicate_locations:
                add(location.get("repository"))
        return projects


class PermissionUsageAgent:
    """Build a simple granted-vs-observed permission usage comparison.

    `UsageAnalysisAgent`(canonical, 위)와는 독립적인 별도 분석기다 —
    `agents/event_extraction_agent.py::EventExtractionAgent`/
    `agents/scenario_mapping_agent.py::ScenarioMappingAgent`/
    `agents/recommendation_agent.py` 의 시나리오 기반 권고가 이 결과에
    의존한다(`agents/pipeline.py::_assess()` 참고).
    """

    def __init__(self, *, scope_translator: Optional[ScopeTranslationAgent] = None) -> None:
        self.scope_translator = scope_translator or ScopeTranslationAgent()

    def analyze(
        self,
        permissions: PermissionProfile,
        signals: Optional[AnalysisSignals] = None,
    ) -> PermissionUsageResult:
        """Compare a permission profile with ``AnalysisSignals.observed_actions``."""
        signals = signals or AnalysisSignals()
        granted = self._sorted_permissions(permissions.permissions)
        used = self._sorted_permissions(self._permissions_from_actions(signals.observed_actions))
        granted_set = set(granted)
        used_set = set(used)
        unused = self._sorted_permissions(granted_set - used_set)
        elapsed = days_since(signals.last_used_at)

        return PermissionUsageResult(
            granted_permissions=granted,
            used_permissions=self._sorted_permissions(used_set),
            unused_permissions=unused,
            days_since_last_used=elapsed,
            usage_status=self._usage_status(elapsed),
            excessive_permission=bool(
                set(unused) & {PermissionLevel.DELETE, PermissionLevel.ADMIN}
            ),
            evidence=self._evidence(granted, used_set, unused, elapsed),
        )

    def _permissions_from_actions(self, actions: Iterable[object]) -> Set[PermissionLevel]:
        permissions: Set[PermissionLevel] = set()
        for action in actions or []:
            if isinstance(action, PermissionLevel):
                permissions.add(action)
                continue
            if not isinstance(action, str) or not action.strip():
                continue
            try:
                permissions.add(PermissionLevel(action.strip().upper()))
                continue
            except ValueError:
                pass
            mapping = self.scope_translator.translate_scope(action)
            if mapping.permission is not None:
                permissions.add(mapping.permission)
        return permissions

    @staticmethod
    def _sorted_permissions(
        permissions: Iterable[PermissionLevel],
    ) -> List[PermissionLevel]:
        return sorted(set(permissions), key=lambda permission: PERMISSION_RANK[permission])

    @staticmethod
    def _usage_status(days: Optional[int]) -> str:
        if days is None:
            return "unknown"
        if days <= 30:
            return "active"
        if days <= 90:
            return "inactive_warning"
        if days <= 180:
            return "stale"
        return "orphaned_candidate"

    @staticmethod
    def _evidence(
        granted: List[PermissionLevel],
        used: Set[PermissionLevel],
        unused: List[PermissionLevel],
        days: Optional[int],
    ) -> List[str]:
        granted_text = ", ".join(permission.value for permission in granted) or "none"
        used_text = ", ".join(permission.value for permission in sorted(used, key=lambda p: PERMISSION_RANK[p])) or "none"
        evidence = [f"Granted permissions: {granted_text}.", f"Observed used permissions: {used_text}."]
        if unused:
            unused_text = ", ".join(permission.value for permission in unused)
            evidence.append(f"Granted permissions not observed in use: {unused_text}.")
        if days is None:
            evidence.append("Last usage time is unknown.")
        else:
            evidence.append(f"Last usage was {days} day(s) ago.")
        if set(unused) & {PermissionLevel.DELETE, PermissionLevel.ADMIN}:
            evidence.append("High-privilege permission is granted but has no observed use.")
        return evidence


__all__ = ["UsageAnalysisAgent", "PermissionUsageAgent"]
