"""실시간 통제 서비스 (Policy Decision Point).

NHI 의 사용 이벤트를 받아 즉시 판정한다.

    ALLOW       허용
    ALERT       허용하되 경고
    REVIEW      추가 검토(운영 모드에 따라 차단·관찰·승인 대기)
    DENY        모든 운영 모드에서 이번 요청 차단

판정은 결정적인 규칙(R1~R7)으로 이루어지며 어떤 규칙이 왜 발동했는지 이벤트에 남는다.
신규 접근 판정은 자동 격리를 생성하지 않는다. 기존 수동 격리 데이터는 계속 차단한다.

`monitor` 모드도 DENY는 차단한다. ALERT는 모든 모드에서 허용하고 경고를 기록한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from backend.services.agent_access_evaluator import (
    AgentAccessEvaluator,
    NHIRuntimeContext,
)
from backend.services.change_control_service import (
    PERMISSION_RANK,
    ChangeControlService,
    ChangeError,
)
from backend.services.control_approval import (
    CONTAINMENT_RULES,
    ApprovalError,
    ControlApprovalService,
    binding_of,
)
from backend.services.usage_rate import DEFAULT_TRACKER, UsageRateTracker
from backend.services.nhi_state import (
    GOVERNANCE_LOCK,
    days_between,
    is_demo,
    load_nhi,
    snapshot,
)
from core.agent_access_models import AgentAccessProfile, AgentApiObservation
from core.config import GovernanceSettings, get_settings
from core.governance_models import (
    VERDICT_ORDER,
    ChangeStatus,
    ChangeType,
    ControlEvent,
    ControlEventType,
    ControlState,
    CredentialState,
    Verdict,
)
from core.nhi_models import PermissionLevel
from storage.base import Storage

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _rule(rule_id: str, verdict: Verdict, severity: str, message: str) -> Dict[str, str]:
    return {
        "rule_id": rule_id,
        "verdict": verdict.value,
        "severity": severity,
        "message": message,
    }


class ControlService:
    def __init__(
        self,
        storage: Storage,
        *,
        changes: Optional[ChangeControlService] = None,
        settings: Optional[GovernanceSettings] = None,
        evaluator: Optional[AgentAccessEvaluator] = None,
        approvals: Optional[ControlApprovalService] = None,
        tracker: Optional[UsageRateTracker] = None,
    ) -> None:
        self.storage = storage
        self.evaluator = evaluator or AgentAccessEvaluator()
        self.settings = settings or get_settings().governance
        self.changes = changes or ChangeControlService(storage, settings=self.settings)
        self.approvals = approvals or ControlApprovalService(
            storage,
            approval_ttl_seconds=self.settings.approval_ttl_seconds,
            grant_ttl_seconds=self.settings.grant_ttl_seconds,
        )
        self.tracker = tracker or DEFAULT_TRACKER

    @property
    def mode(self) -> str:
        """REVIEW 집행 정책을 고르는 모드. DENY 차단은 모드와 무관하다."""
        return "monitor" if self.settings.control_mode.lower() == "monitor" else "enforce"

    @property
    def hold_reviews(self) -> bool:
        """true 면 Agent 호출의 REVIEW(확정 불가) 판정을 통과시키지 않고 승인 대기로 보류한다."""
        return self.settings.control_mode.lower() == "human_in_the_loop"

    # ------------------------------------------------------------------
    # 진입점
    # ------------------------------------------------------------------
    def authorize(
        self,
        nhi_id: str,
        permission: str,
        *,
        resource: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """집행 지점(게이트웨이/프록시)이 요청을 통과시키기 전에 호출하는 동기 질의."""
        return self.evaluate(
            nhi_id,
            ControlEventType.CREDENTIAL_USE,
            {"permission": permission, "resource": resource, "source_ip": source_ip},
        )

    def evaluate(
        self,
        nhi_id: str,
        event_type: ControlEventType,
        attributes: Optional[Dict[str, Any]] = None,
        *,
        actor: str = "control-plane",
    ) -> Dict[str, Any]:
        attrs = {k: v for k, v in (attributes or {}).items() if v is not None}
        with GOVERNANCE_LOCK:
            nhi = load_nhi(self.storage, nhi_id)
            state = snapshot(nhi)
            rules = self._rules(nhi, state, event_type, attrs)
            if event_type is ControlEventType.CREDENTIAL_USE:
                self._measured_spike(nhi_id, nhi, rules)
            verdict, severity = self._summarize(rules)
            allowed, directive = self._enforcement(verdict)
            enforce = not allowed

            change_id: Optional[str] = None
            follow_ups: List[str] = []
            if verdict is Verdict.DENY and event_type is ControlEventType.EXPOSURE_DETECTED:
                follow_ups = self._propose_revoke(nhi, rules, enforce)

            event = None
            approval_view = None
            decision_id = str(uuid4())
            if verdict is not Verdict.ALLOW:  # ALLOW 는 양이 많아 기록하지 않는다
                event = self.storage.append_control_event(
                    ControlEvent(
                        nhi_id=nhi_id,
                        event_type=event_type.value,
                        verdict=verdict.value,
                        severity=severity,
                        rules=rules,
                        attributes={**attrs, "decision_id": decision_id},
                        enforced=enforce,
                        allowed=allowed,
                        change_id=change_id,
                        follow_up_change_ids=follow_ups,
                        demo_workspace=is_demo(nhi),
                    )
                )
                if directive == "REQUIRE_APPROVAL":
                    approval_view = self.approvals.open_hold(
                        decision_id=decision_id,
                        observation={"provider": nhi.get("provider"), "nhi_id": nhi_id, **attrs},
                        rule_ids=[rule["rule_id"] for rule in rules], event_seq=event.seq,
                    )
            return {
                "decision_id": decision_id,
                "approval": approval_view,
                "nhi_id": nhi_id,
                "nhi_name": nhi.get("nhi_name"),
                "event_type": event_type.value,
                "verdict": verdict.value,
                "allowed": allowed,
                "enforced": enforce,
                "mode": self.settings.control_mode.lower(),
                "access_outcome": verdict.value,
                "directive": directive,
                "severity": severity,
                "rules": rules,
                "quarantine_change_id": change_id,
                "follow_up_change_ids": follow_ups,
                "event_seq": event.seq if event else None,
            }

    def authorize_call(
        self,
        observation: AgentApiObservation,
        *,
        actor: str = "control-plane",
        grant_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Agent 가 NHI 로 한 호출을 승인 기준선과 비교해 판정한다.

        `authorize`/`evaluate` 는 NHI 단위(누가 호출했는지 모름)지만, 이 경로는 주장 Agent ·
        인증 Agent · Credential · 권한 · 자원을 함께 본다. 기존 규칙과의 대응:

            R1 종료·폐기 사용      → NHI_LIFECYCLE_ENDED      (DENY)
            R2 격리 중 사용        → NHI_QUARANTINED          (DENY)
            R3 권한 초과           → PERMISSION_SCOPE_EXCEEDED (DENY, 반복 시 QUARANTINE)
            R4 사용량 급증         → USAGE_SPIKE (서버가 측정한 호출률 기준)
            R5 미등록 출처         → UNREGISTERED_SOURCE      (ALERT — IP 는 인증 근거가 아님)
            R7 휴면 재사용         → DORMANT_CREDENTIAL_REACTIVATED (ALERT)

        지시(directive): PASS · ALERT_ONLY · REQUIRE_APPROVAL · BLOCK.
        기준선·관측이 불완전해 확정할 수 없는 경우(REVIEW)는 DENY 가 아니라 ALERT 이며,
        `human_in_the_loop` 모드에서는 통과시키지 않고 승인 대기(REQUIRE_APPROVAL)로 보류한다.
        관리자가 승인하면 1회용 허가가 발급되고, 같은 요청을 `grant_token` 과 함께 재시도하면 통과한다.
        """
        raw_profile = self.storage.get_agent_access_profile(observation.claimed_agent_id)
        profile = AgentAccessProfile.model_validate(raw_profile) if raw_profile else None
        safe_observation = self.evaluator.sanitize_observation(observation)
        observed = safe_observation.model_dump(mode="json")

        with GOVERNANCE_LOCK:
            grant_rejected: Optional[str] = None
            nhi: Optional[Dict[str, Any]] = None
            context = NHIRuntimeContext()
            if self.storage.get_nhi_record(observation.nhi_id) is not None:
                nhi = load_nhi(self.storage, observation.nhi_id)
                context = self._context(nhi, snapshot(nhi))

            decision = self.evaluator.evaluate(profile, observation, context=context)
            rules = self._findings_to_rules(decision.findings)
            previous = self._find_replay(observation)
            if previous is None:
                self._measured_spike(observation.nhi_id, nhi, rules)
            else:
                rules.extend(r for r in previous["rules"] if r["rule_id"] == "AGENT_CALL_RATE_SPIKE")
                self._correlate_spike(rules)
            verdict, severity = self._summarize(rules)
            allowed, directive = self._enforcement(verdict)
            hold = directive == "REQUIRE_APPROVAL"
            enforce = not allowed
            if grant_token:
                if verdict is not Verdict.REVIEW or not self.hold_reviews:
                    grant_rejected = "Approval grant cannot override the current decision."
                else:
                    try:
                        approval = self.approvals.redeem(grant_token, observed, event_id=observation.event_id)
                    except ApprovalError as exc:
                        grant_rejected = str(exc)
                    else:
                        return self._result(
                            observation, decision_id=approval["decision_id"], outcome="REVIEW",
                            verdict=Verdict.ALLOW, directive="PASS", allowed=True, enforce=False,
                            severity="LOW", rules=rules, approval=approval, grant_redeemed=True,
                        )
            if (
                previous is not None
                and previous["verdict"] == verdict.value
                and previous["mode"] == self.settings.control_mode.lower()
                and previous["directive"] == directive
                and {r["rule_id"] for r in previous["rules"]} == {r["rule_id"] for r in rules}
            ):
                previous.update(allowed=allowed, directive=directive, enforced=enforce)
                if grant_rejected:
                    previous["grant_rejected_reason"] = grant_rejected
                return previous

            change_id: Optional[str] = None
            follow_ups: List[str] = []
            if verdict is Verdict.DENY and nhi is not None:
                follow_ups = self._propose_rotation(nhi, rules)

            event_seq = None
            approval_view = None
            if verdict is not Verdict.ALLOW:
                event = self.storage.append_control_event(
                    ControlEvent(
                        nhi_id=observation.nhi_id,
                        event_type="AGENT_API_CALL",
                        verdict=verdict.value,
                        severity=severity,
                        rules=rules,
                        attributes={
                            "observation_event_id": observation.event_id,
                            "claimed_agent_id": observation.claimed_agent_id,
                            "decision_id": decision.decision_id,
                            "access_outcome": verdict.value,
                            "directive": directive,
                            "mode": self.settings.control_mode.lower(),
                            "observation": observed,
                        },
                        enforced=enforce,
                        allowed=allowed,
                        change_id=change_id,
                        follow_up_change_ids=follow_ups,
                        demo_workspace=is_demo(nhi) if nhi else False,
                    )
                )
                event_seq = event.seq
                if hold:
                    approval_view = self.approvals.open_hold(
                        decision_id=decision.decision_id,
                        observation=observed,
                        rule_ids=[rule["rule_id"] for rule in rules],
                        event_seq=event_seq,
                    )
            return self._result(
                observation,
                decision_id=decision.decision_id,
                outcome=verdict.value,
                verdict=verdict,
                directive=directive,
                allowed=allowed,
                enforce=enforce,
                severity=severity,
                rules=rules,
                matched_grant_id=decision.matched_grant_id,
                change_id=change_id,
                follow_ups=follow_ups,
                event_seq=event_seq,
                approval=approval_view,
                grant_rejected=grant_rejected,
            )

    def _result(
        self,
        observation: AgentApiObservation,
        *,
        decision_id: str,
        outcome: str,
        verdict: Verdict,
        directive: str,
        allowed: bool,
        enforce: bool,
        severity: str,
        rules: List[Dict[str, str]],
        matched_grant_id: Optional[str] = None,
        change_id: Optional[str] = None,
        follow_ups: Optional[List[str]] = None,
        event_seq: Optional[int] = None,
        approval: Optional[Dict[str, Any]] = None,
        grant_rejected: Optional[str] = None,
        grant_redeemed: bool = False,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "decision_id": decision_id,
            "agent_id": observation.claimed_agent_id,
            "nhi_id": observation.nhi_id,
            "access_outcome": outcome,
            "verdict": verdict.value,
            "directive": directive,
            "allowed": allowed,
            "enforced": enforce,
            "mode": self.settings.control_mode.lower(),
            "severity": severity,
            "rules": rules,
            "matched_grant_id": matched_grant_id,
            "quarantine_change_id": change_id,
            "follow_up_change_ids": follow_ups or [],
            "event_seq": event_seq,
            "approval": approval,
            "grant_redeemed": grant_redeemed,
            "replayed": False,
        }
        if grant_rejected:
            result["grant_rejected_reason"] = grant_rejected
        return result

    def _measured_spike(
        self, nhi_id: str, nhi: Optional[Dict[str, Any]], rules: List[Dict[str, str]]
    ) -> None:
        """급증 단독은 REVIEW, 독립 이상행위와 동시 확인되면 DENY."""
        sample = self.tracker.observe(nhi_id)
        ratio = sample.ratio
        if ratio is None or ratio < 5:
            return
        detail = (
            f"서버 측정 호출률 {sample.current_per_min:.0f}회/분 "
            f"(평소 {sample.baseline_per_min:.1f}회/분의 {self._ratio(ratio)}배)"
        )
        rules.append(_rule("AGENT_CALL_RATE_SPIKE", Verdict.REVIEW, "MEDIUM", detail))
        self._correlate_spike(rules)

    @staticmethod
    def _correlate_spike(rules: List[Dict[str, str]]) -> None:
        ids = {rule["rule_id"] for rule in rules}
        abnormal = ids & {
            "UNREGISTERED_SOURCE", "DORMANT_CREDENTIAL_REACTIVATED",
            "TOKEN_REPLAY_SUSPECTED", "SENDER_PROOF_INVALID",
            "UNAPPROVED_CREDENTIAL", "PERMISSION_SCOPE_EXCEEDED", "RESOURCE_SCOPE_EXCEEDED",
        }
        if "AGENT_CALL_RATE_SPIKE" in ids and abnormal:
            rules.append(_rule(
                "AGENT_CALL_RATE_SPIKE_CORRELATED", Verdict.DENY, "HIGH",
                "호출률 급증과 이상행위 동시 확인: " + ", ".join(sorted(abnormal)),
            ))

    def _enforcement(self, verdict: Verdict) -> Tuple[bool, str]:
        if verdict in (Verdict.DENY, Verdict.QUARANTINE):
            return False, "BLOCK"
        if verdict is Verdict.REVIEW:
            if self.hold_reviews:
                return False, "REQUIRE_APPROVAL"
            if self.mode == "enforce":
                return False, "BLOCK"
            return True, "ALERT_ONLY"
        if verdict is Verdict.ALERT:
            return True, "ALERT_ONLY"
        return True, "PASS"

    def _propose_rotation(
        self, nhi: Dict[str, Any], rules: List[Dict[str, str]]
    ) -> List[str]:
        """Credential 탈취·위장이 의심되는 차단이면 교체(TOKEN_ROTATE) 승인 요청을 만든다.

        차단만으로는 탈취된 Credential 이 계속 유효하다. 실행은 사람의 승인 이후다.
        """
        hit = sorted({rule["rule_id"] for rule in rules} & CONTAINMENT_RULES)
        if not hit:
            return []
        try:
            change = self.changes.propose(
                nhi["nhi_id"], ChangeType.TOKEN_ROTATE,
                requested_by="control-plane",
                reason="Credential 탈취·위장 의심으로 호출을 차단했습니다: " + ", ".join(hit),
                source="control-plane",
            )
        except ChangeError:
            return []  # 이미 교체 요청이 대기 중이거나 종료된 NHI
        return [change.change_id]

    def _find_replay(self, observation: AgentApiObservation) -> Optional[Dict[str, Any]]:
        """같은 호출 이벤트의 재전송은 새 위반으로 세지 않는다(재시도가 격리를 부르지 않도록)."""
        for event in self.storage.list_control_events(nhi_id=observation.nhi_id, limit=500):
            attrs = event.get("attributes") or {}
            if (
                attrs.get("observation_event_id") == observation.event_id
                and attrs.get("claimed_agent_id") == observation.claimed_agent_id
                and binding_of(attrs.get("observation") or {}) == binding_of(
                    self.evaluator.sanitize_observation(observation).model_dump(mode="json")
                )
            ):
                result = self._result(
                    observation,
                    decision_id=attrs.get("decision_id"),
                    outcome=attrs.get("access_outcome"),
                    verdict=Verdict(event["verdict"]),
                    directive=attrs.get("directive") or "ALERT_ONLY",
                    allowed=event["allowed"],
                    enforce=event["enforced"],
                    severity=event["severity"],
                    rules=event["rules"],
                    change_id=event.get("change_id"),
                    follow_ups=event.get("follow_up_change_ids"),
                    event_seq=event["seq"],
                    approval=self.approvals.get(attrs.get("decision_id") or ""),
                )
                result["replayed"] = True
                result["mode"] = attrs.get("mode", "enforce")
                return result
        return None

    def _context(self, nhi: Dict[str, Any], state: Dict[str, Any]) -> NHIRuntimeContext:
        """NHI 인벤토리 상태를 평가기 입력으로 옮긴다."""
        return NHIRuntimeContext(
            lifecycle_stage=state["lifecycle_stage"],
            credential_state=state["credential_state"],
            quarantined=state["control_state"] == ControlState.QUARANTINED.value,
            known_sources=[str(item) for item in nhi.get("known_sources") or []],
            idle_days=days_between(nhi.get("last_used_at"), datetime.now(timezone.utc)),
        )

    @staticmethod
    def _findings_to_rules(findings: List[Any]) -> List[Dict[str, str]]:
        """평가기 finding → 통제 규칙. 확정 위반(blocking)은 DENY, 확정 불가는 ALERT."""
        return [
            _rule(
                finding.rule_id,
                Verdict.DENY if finding.blocking else (
                    Verdict.ALERT if finding.rule_id in {"UNREGISTERED_SOURCE", "DORMANT_CREDENTIAL_REACTIVATED"}
                    else Verdict.REVIEW
                ),
                finding.severity.value,
                finding.detail,
            )
            for finding in findings
        ]

    def _summarize(self, rules: List[Dict[str, str]]) -> Tuple[Verdict, str]:
        verdict = self._strongest(rules)
        severity = max(
            (rule["severity"] for rule in rules),
            key=lambda value: _SEVERITY_ORDER[value],
            default="LOW",
        )
        return verdict, severity

    def _rules(
        self,
        nhi: Dict[str, Any],
        state: Dict[str, Any],
        event_type: ControlEventType,
        attrs: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """NHI 단위 질의·이벤트를 판정한다.

        호출 판정(R1·R2·R3·R5·R7)은 Agent 경로와 같은 평가기 규칙을 쓴다. 호출이 아닌
        이벤트(사용량 급증 R4 · 노출 R6)만 여기서 직접 판정한다.
        """
        rules: List[Dict[str, str]] = []
        held = state["permissions"]
        top = max((PERMISSION_RANK.get(p, 1) for p in held), default=0)

        if event_type is ControlEventType.CREDENTIAL_USE:
            requested = str(attrs.get("permission") or "").upper()
            try:
                level: Optional[PermissionLevel] = PermissionLevel(requested)
            except ValueError:
                level = None
            findings = self.evaluator.nhi_context_findings(
                nhi_id=nhi["nhi_id"],
                source_ip=attrs.get("source_ip"),
                permission=level,
                context=self._context(nhi, state),
            )
            findings += self.evaluator.nhi_permission_findings(requested, held)
            rules += self._findings_to_rules(findings)

        if event_type is ControlEventType.USAGE_SPIKE:
            rate = float(attrs.get("requests_per_min") or 0)
            baseline = float(attrs.get("baseline_per_min") or 0)
            if baseline > 0 and rate / baseline >= 5:
                rules.append(_rule(
                    "USAGE_SPIKE", Verdict.REVIEW, "MEDIUM",
                    f"사용량이 평소의 {self._ratio(rate / baseline)}배로 급증했습니다 (호출자 보고값).",
                ))

        if event_type is ControlEventType.EXPOSURE_DETECTED:
            if state["credential_state"] == CredentialState.ACTIVE.value and top > 0:
                verdict = Verdict.DENY if top >= PERMISSION_RANK["WRITE"] or not (
                    str(nhi.get("environment") or "").lower()
                    in {"development", "test"}
                ) else Verdict.ALERT
                rules.append(_rule(
                    "CREDENTIAL_EXPOSED", verdict, "CRITICAL",
                    "활성 Credential 이 외부에 노출되었습니다 — 즉시 격리하고 폐기 승인을 요청합니다."
                    if verdict is Verdict.DENY
                    else "비운영 읽기 전용 Credential 노출 — 경고 후 교체를 권고합니다.",
                ))
        return rules

    @staticmethod
    def _ratio(value: float) -> str:
        return "무한대" if value == float("inf") else f"{value:.0f}"

    @staticmethod
    def _strongest(rules: List[Dict[str, str]]) -> Verdict:
        if not rules:
            return Verdict.ALLOW
        return max(
            (Verdict(rule["verdict"]) for rule in rules), key=lambda v: VERDICT_ORDER[v]
        )

    # ------------------------------------------------------------------
    # 집행
    # ------------------------------------------------------------------
    def _propose_revoke(
        self, nhi: Dict[str, Any], rules: List[Dict[str, str]], enforce: bool
    ) -> List[str]:
        if not enforce:
            return []
        try:
            change = self.changes.propose(
                nhi["nhi_id"], ChangeType.TOKEN_REVOKE,
                requested_by="control-plane",
                reason="Credential 노출 감지 — "
                + "; ".join(rule["message"] for rule in rules),
                source="control-plane",
            )
        except ChangeError:
            return []  # 이미 대기 중이거나 폐기됨
        return [change.change_id]

    # ------------------------------------------------------------------
    # 조회
    # ------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        recent = self.storage.list_control_events(since=since, limit=500)
        counts = {verdict.value: 0 for verdict in Verdict if verdict is not Verdict.ALLOW}
        for event in recent:
            counts[event["verdict"]] = counts.get(event["verdict"], 0) + 1
        quarantined = [
            {
                "nhi_id": nhi["nhi_id"],
                "nhi_name": nhi.get("nhi_name"),
                "risk_level": nhi.get("risk_level"),
            }
            for nhi in self.storage.list_nhi_records(limit=500)
            if nhi.get("control_state") == ControlState.QUARANTINED.value
        ]
        pending = self.storage.list_change_requests(
            status=ChangeStatus.PENDING_APPROVAL, limit=200
        )
        return {
            "mode": self.settings.control_mode.lower(),
            "last_hour": counts,
            "quarantined": quarantined,
            "pending_control_changes": sum(
                1 for change in pending if change.source == "control-plane"
            ),
            "thresholds": {
                "deny_quarantine_threshold": self.settings.deny_quarantine_threshold,
                "deny_window_seconds": self.settings.deny_window_seconds,
            },
        }
