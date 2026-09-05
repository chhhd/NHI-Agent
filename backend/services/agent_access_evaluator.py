"""회사 AI Agent의 승인 기준선과 API 관측 이벤트를 비교한다.

규칙 ID와 설명을 한 곳에 모아, 이후 실제 정보유출 사례·권한 범용 사례가
추가되더라도 Connector나 위험 점수 엔진을 직접 수정하지 않고 규칙을 확장할 수 있다.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional
from uuid import NAMESPACE_URL, uuid5

from core.agent_access_models import (
    AgentAccessDecision,
    AgentAccessGrant,
    AgentAccessOutcome,
    AgentAccessProfile,
    AgentApiObservation,
    AgentLifecycleStatus,
    AgentThreatFinding,
)
from core.nhi_models import PERMISSION_RANK, PermissionLevel, RiskLevel
from security.redaction import sanitize_security_text


AGENT_ACCESS_RULE_CATALOG: Dict[str, Dict[str, Any]] = {
    "UNREGISTERED_AGENT": {
        "category": "identity",
        "severity": RiskLevel.CRITICAL,
        "title": "등록되지 않은 Agent",
        "description": "회사 기준선에 없는 Agent가 사내 API 주체를 주장함",
    },
    "CLAIMED_IDENTITY_MISMATCH": {
        "category": "impersonation",
        "severity": RiskLevel.CRITICAL,
        "title": "Agent 신원 불일치",
        "description": "요청이 주장한 Agent와 인증 계층이 확인한 Agent가 다름",
    },
    "IDENTITY_EVIDENCE_INCOMPLETE": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "Agent 신원 증명 불완전",
        "description": "Agent ID 또는 sender proof를 통해 호출 주체를 확정할 수 없음",
    },
    "AGENT_NOT_ACTIVE": {
        "category": "lifecycle",
        "severity": RiskLevel.CRITICAL,
        "title": "비활성 Agent의 API 호출",
        "description": "중지·퇴역 상태 Agent 명의의 호출이 관측됨",
    },
    "TOKEN_REPLAY_SUSPECTED": {
        "category": "impersonation",
        "severity": RiskLevel.CRITICAL,
        "title": "Token 또는 proof 재사용",
        "description": "탈취된 자격 증명 또는 sender proof의 재사용이 의심됨",
    },
    "SENDER_PROOF_INVALID": {
        "category": "impersonation",
        "severity": RiskLevel.CRITICAL,
        "title": "Sender proof 검증 실패",
        "description": "요청자가 승인된 private key 또는 인증서를 보유했음을 증명하지 못함",
    },
    "SENDER_CONSTRAINT_REQUIRED": {
        "category": "token_binding",
        "severity": RiskLevel.HIGH,
        "title": "Sender-constrained token 필수",
        "description": "해당 Agent 정책은 DPoP/mTLS 등 발신자 바인딩을 요구함",
    },
    "UNAPPROVED_NHI": {
        "category": "identity",
        "severity": RiskLevel.CRITICAL,
        "title": "승인되지 않은 NHI 사용",
        "description": "Agent에 연결되지 않은 API 계정 또는 서비스 주체로 호출함",
    },
    "UNAPPROVED_CREDENTIAL": {
        "category": "impersonation",
        "severity": RiskLevel.CRITICAL,
        "title": "승인되지 않은 Credential",
        "description": "등록된 NHI와 다른 Credential fingerprint가 관측됨",
    },
    "PERMISSION_SCOPE_EXCEEDED": {
        "category": "permission",
        "severity": RiskLevel.HIGH,
        "title": "승인 권한 초과",
        "description": "Agent가 승인된 공통 권한보다 강한 행위를 수행함",
    },
    "RESOURCE_SCOPE_EXCEEDED": {
        "category": "resource",
        "severity": RiskLevel.HIGH,
        "title": "승인 자원 범위 초과",
        "description": "Agent가 승인 목록 밖의 저장소·채널·파일·메일함 등에 접근함",
    },
    "NHI_BASELINE_INCOMPLETE": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "Agent–NHI 기준선 불완전",
        "description": "전체 NHI 연결 수집이 끝나지 않아 승인 여부를 확정할 수 없음",
    },
    "CREDENTIAL_BASELINE_INCOMPLETE": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "Credential 기준선 불완전",
        "description": "NHI의 승인 Credential fingerprint 수집이 불완전함",
    },
    "PERMISSION_BASELINE_INCOMPLETE": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "권한 기준선 불완전",
        "description": "Agent/NHI의 전체 승인 권한을 아직 수집하지 못함",
    },
    "RESOURCE_BASELINE_INCOMPLETE": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "자원 기준선 불완전",
        "description": "Agent/NHI의 전체 접근 자원을 아직 수집하지 못함",
    },
    "OBSERVATION_INCOMPLETE": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "API 관측 정보 불완전",
        "description": "권한 또는 대상 자원이 없어 승인 범위와 비교할 수 없음",
    },
    "SENSITIVE_ACCESS_WITHOUT_BINDING": {
        "category": "data_access",
        "severity": RiskLevel.HIGH,
        "title": "민감 자원 접근의 발신자 바인딩 부재",
        "description": "민감 자료 접근에 sender-constrained token 증거가 없음",
    },
}


_SEVERITY_RANK = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


class AgentAccessEvaluator:
    """승인된 Agent 접근 범위와 한 번의 API 호출을 결정적으로 비교한다."""

    def evaluate(
        self,
        profile: Optional[AgentAccessProfile],
        observation: AgentApiObservation,
    ) -> AgentAccessDecision:
        safe_observation = self._sanitize_observation(observation)
        findings: List[AgentThreatFinding] = []
        matched_grant: Optional[AgentAccessGrant] = None

        if profile is None:
            findings.append(
                self._finding(
                    "UNREGISTERED_AGENT",
                    detail=(
                        f"회사 Agent 기준선에 {observation.claimed_agent_id}가 없음"
                    ),
                    evidence=[f"claimed_agent_id={observation.claimed_agent_id}"],
                    blocking=True,
                )
            )
            return self._decision(safe_observation, findings, None)

        if (
            observation.authenticated_agent_id
            and observation.authenticated_agent_id != profile.agent_id
        ):
            findings.append(
                self._finding(
                    "CLAIMED_IDENTITY_MISMATCH",
                    detail=(
                        f"주장 Agent={profile.agent_id}, 인증 Agent="
                        f"{observation.authenticated_agent_id}"
                    ),
                    evidence=[
                        f"claimed_agent_id={profile.agent_id}",
                        f"authenticated_agent_id={observation.authenticated_agent_id}",
                    ],
                    blocking=True,
                )
            )

        if profile.status is not AgentLifecycleStatus.ACTIVE:
            findings.append(
                self._finding(
                    "AGENT_NOT_ACTIVE",
                    detail=f"Agent 상태가 {profile.status.value}임",
                    evidence=[f"agent_status={profile.status.value}"],
                    blocking=True,
                )
            )

        if observation.token_replay_suspected:
            findings.append(
                self._finding(
                    "TOKEN_REPLAY_SUSPECTED",
                    detail="Gateway 또는 감사 로그에서 Token/proof 재사용 신호가 확인됨",
                    evidence=["token_replay_suspected=true"],
                    blocking=True,
                )
            )

        if observation.sender_proof_valid is False:
            findings.append(
                self._finding(
                    "SENDER_PROOF_INVALID",
                    detail="DPoP proof 또는 mTLS client 인증 검증이 실패함",
                    evidence=[
                        f"binding_method={observation.binding_method or 'unknown'}",
                        "sender_proof_valid=false",
                    ],
                    blocking=True,
                )
            )

        grants = [
            grant
            for grant in profile.grants
            if grant.provider.lower() == observation.provider.lower()
            and grant.nhi_id == observation.nhi_id
        ]
        if grants:
            matched_grant = self._select_grant(grants, observation)
            self._evaluate_grant(matched_grant, observation, findings)
        elif profile.inventory_complete:
            findings.append(
                self._finding(
                    "UNAPPROVED_NHI",
                    detail=(
                        f"{profile.agent_id}에 승인되지 않은 "
                        f"{observation.provider}:{observation.nhi_id} 사용"
                    ),
                    evidence=[
                        f"provider={observation.provider}",
                        f"nhi_id={observation.nhi_id}",
                        "agent_inventory_complete=true",
                    ],
                    blocking=True,
                )
            )
        else:
            findings.append(
                self._finding(
                    "NHI_BASELINE_INCOMPLETE",
                    detail=(
                        f"{observation.provider}:{observation.nhi_id}가 현재 기준선에는 없으나 "
                        "Agent 인벤토리가 불완전해 공격으로 확정하지 않음"
                    ),
                    evidence=["agent_inventory_complete=false"],
                    blocking=False,
                )
            )

        binding_method = (observation.binding_method or "").lower()
        allowed_methods = {
            method.lower() for method in profile.allowed_binding_methods if method
        }
        sender_verified = (
            observation.sender_constrained is True
            and observation.sender_proof_valid is True
            and (not allowed_methods or binding_method in allowed_methods)
        )
        if (
            profile.require_sender_constraint
            and not sender_verified
            and observation.sender_proof_valid is not False
        ):
            findings.append(
                self._finding(
                    "SENDER_CONSTRAINT_REQUIRED",
                    detail=(
                        "Agent 정책이 sender constraint를 요구하지만 승인된 방식의 "
                        "유효한 증명이 확인되지 않음"
                    ),
                    evidence=[
                        f"sender_constrained={observation.sender_constrained}",
                        f"sender_proof_valid={observation.sender_proof_valid}",
                        f"binding_method={observation.binding_method or 'unknown'}",
                    ],
                    blocking=True,
                )
            )

        identity_proven = (
            observation.authenticated_agent_id == profile.agent_id
            or (matched_grant is not None and sender_verified)
        )
        if not identity_proven and not any(
            finding.rule_id == "CLAIMED_IDENTITY_MISMATCH" for finding in findings
        ):
            findings.append(
                self._finding(
                    "IDENTITY_EVIDENCE_INCOMPLETE",
                    detail="주장한 Agent를 인증된 Agent ID 또는 승인된 sender proof로 확정하지 못함",
                    evidence=[
                        f"authenticated_agent_id={observation.authenticated_agent_id or 'missing'}",
                        f"matched_grant={matched_grant.grant_id if matched_grant else 'none'}",
                    ],
                    blocking=False,
                )
            )

        if (
            self._is_sensitive(matched_grant, observation)
            and not sender_verified
            and not profile.require_sender_constraint
        ):
            findings.append(
                self._finding(
                    "SENSITIVE_ACCESS_WITHOUT_BINDING",
                    detail=f"민감 자원 {observation.resource or '미상'} 접근에 sender proof가 없음",
                    evidence=["require_sender_constraint=false"],
                    blocking=False,
                )
            )

        return self._decision(safe_observation, findings, matched_grant)

    def summarize_scope(self, profile: AgentAccessProfile) -> Dict[str, Any]:
        providers = sorted({grant.provider for grant in profile.grants})
        nhi_ids = sorted({grant.nhi_id for grant in profile.grants})
        permissions = sorted(
            {permission for grant in profile.grants for permission in grant.permissions},
            key=lambda item: PERMISSION_RANK[item],
        )
        resources = sorted({item for grant in profile.grants for item in grant.resources})
        sensitive = sorted(
            {item for grant in profile.grants for item in grant.sensitive_resources}
        )
        blind_spots: List[str] = []
        indicators: List[Dict[str, str]] = []

        if not profile.inventory_complete:
            blind_spots.append("Agent에 연결된 전체 NHI 인벤토리가 불완전함")
        if not profile.owner:
            blind_spots.append("Agent 보안 책임자(Owner)가 지정되지 않음")
        if not profile.require_sender_constraint:
            blind_spots.append("Agent API 호출에 sender constraint가 필수가 아님")

        for grant in profile.grants:
            if not grant.credential_inventory_complete:
                blind_spots.append(f"{grant.grant_id}: Credential 목록 불완전")
            if not grant.permission_inventory_complete:
                blind_spots.append(f"{grant.grant_id}: 권한 목록 불완전")
            if not grant.resource_inventory_complete:
                blind_spots.append(f"{grant.grant_id}: 자원 목록 불완전")
            high = [
                item.value
                for item in grant.permissions
                if item in {PermissionLevel.DELETE, PermissionLevel.ADMIN}
            ]
            if high:
                indicators.append(
                    {
                        "type": "HIGH_PRIVILEGE",
                        "grant_id": grant.grant_id,
                        "detail": ", ".join(high),
                    }
                )
            broad = [item for item in grant.resources if item == "*" or item.endswith("/*")]
            if broad:
                indicators.append(
                    {
                        "type": "WILDCARD_RESOURCE",
                        "grant_id": grant.grant_id,
                        "detail": ", ".join(broad[:5]),
                    }
                )

        return {
            "agent_id": profile.agent_id,
            "display_name": profile.display_name,
            "owner": profile.owner,
            "status": profile.status.value,
            "environment": profile.environment,
            "provider_count": len(providers),
            "providers": providers,
            "nhi_count": len(nhi_ids),
            "nhi_ids": nhi_ids,
            "credential_count": len(
                {
                    fingerprint
                    for grant in profile.grants
                    for fingerprint in grant.credential_fingerprints
                }
            ),
            "permissions": [item.value for item in permissions],
            "resource_count": len(resources),
            "resources": resources,
            "sensitive_resource_count": len(sensitive),
            "sensitive_resources": sensitive,
            "inventory_complete": profile.inventory_complete
            and all(
                grant.credential_inventory_complete
                and grant.permission_inventory_complete
                and grant.resource_inventory_complete
                for grant in profile.grants
            ),
            "broad_access_indicators": indicators,
            "blind_spots": list(dict.fromkeys(blind_spots)),
            "grants": [grant.model_dump(mode="json") for grant in profile.grants],
        }

    @staticmethod
    def rule_catalog() -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": rule_id,
                **{
                    key: (value.value if isinstance(value, RiskLevel) else value)
                    for key, value in definition.items()
                },
            }
            for rule_id, definition in AGENT_ACCESS_RULE_CATALOG.items()
        ]

    def _evaluate_grant(
        self,
        grant: AgentAccessGrant,
        observation: AgentApiObservation,
        findings: List[AgentThreatFinding],
    ) -> None:
        fingerprint = observation.credential_fingerprint
        if fingerprint:
            if fingerprint in grant.credential_fingerprints:
                pass
            elif grant.credential_inventory_complete:
                findings.append(
                    self._finding(
                        "UNAPPROVED_CREDENTIAL",
                        detail=f"NHI {grant.nhi_id}에 등록되지 않은 Credential fingerprint 사용",
                        evidence=[f"credential_fingerprint={fingerprint}"],
                        blocking=True,
                    )
                )
            else:
                findings.append(
                    self._finding(
                        "CREDENTIAL_BASELINE_INCOMPLETE",
                        detail="Credential fingerprint 기준선이 불완전해 일치 여부를 확정하지 않음",
                        evidence=["credential_inventory_complete=false"],
                        blocking=False,
                    )
                )
        else:
            findings.append(
                self._finding(
                    "OBSERVATION_INCOMPLETE",
                    detail="API 관측 이벤트에 Credential fingerprint가 없음",
                    evidence=["credential_fingerprint=missing"],
                    blocking=False,
                )
            )

        permission = observation.permission
        if permission is None:
            findings.append(
                self._finding(
                    "OBSERVATION_INCOMPLETE",
                    detail="API action을 공통 권한으로 변환한 값이 없음",
                    evidence=[f"action={sanitize_security_text(observation.action)}"],
                    blocking=False,
                )
            )
        elif not self._permission_allowed(permission, grant.permissions):
            if grant.permission_inventory_complete:
                findings.append(
                    self._finding(
                        "PERMISSION_SCOPE_EXCEEDED",
                        detail=(
                            f"관측 권한 {permission.value}가 승인 권한 "
                            f"{[item.value for item in grant.permissions]}을 초과함"
                        ),
                        evidence=[f"permission={permission.value}"],
                        blocking=True,
                        severity=(
                            RiskLevel.CRITICAL
                            if observation.resource_sensitive
                            else None
                        ),
                    )
                )
            else:
                findings.append(
                    self._finding(
                        "PERMISSION_BASELINE_INCOMPLETE",
                        detail=f"관측 권한 {permission.value}의 승인 여부를 불완전한 기준선으로 확정하지 않음",
                        evidence=["permission_inventory_complete=false"],
                        blocking=False,
                    )
                )

        resource = observation.resource
        if not resource:
            findings.append(
                self._finding(
                    "OBSERVATION_INCOMPLETE",
                    detail="API 관측 이벤트에 접근 대상 자원이 없음",
                    evidence=["resource=missing"],
                    blocking=False,
                )
            )
        elif not self._resource_allowed(resource, grant.resources):
            if grant.resource_inventory_complete:
                findings.append(
                    self._finding(
                        "RESOURCE_SCOPE_EXCEEDED",
                        detail=f"자원 {sanitize_security_text(resource)}이 승인 범위 밖임",
                        evidence=[f"resource={sanitize_security_text(resource)}"],
                        blocking=True,
                        severity=(
                            RiskLevel.CRITICAL
                            if observation.resource_sensitive
                            else None
                        ),
                    )
                )
            else:
                findings.append(
                    self._finding(
                        "RESOURCE_BASELINE_INCOMPLETE",
                        detail=f"자원 {sanitize_security_text(resource)}의 승인 여부를 불완전한 기준선으로 확정하지 않음",
                        evidence=["resource_inventory_complete=false"],
                        blocking=False,
                    )
                )

    @staticmethod
    def _select_grant(
        grants: List[AgentAccessGrant], observation: AgentApiObservation
    ) -> AgentAccessGrant:
        if observation.credential_fingerprint:
            for grant in grants:
                if observation.credential_fingerprint in grant.credential_fingerprints:
                    return grant
        return grants[0]

    @staticmethod
    def _sanitize_observation(observation: AgentApiObservation) -> AgentApiObservation:
        """Gateway 입력의 제어문자·Secret 형태를 감사 저장 전에 제거한다."""
        values: Dict[str, Any] = {}
        for field_name in (
            "action",
            "resource",
            "binding_method",
            "user_agent",
        ):
            value = getattr(observation, field_name)
            if isinstance(value, str):
                values[field_name] = sanitize_security_text(value)
        return observation.model_copy(update=values)

    @staticmethod
    def _permission_allowed(
        observed: PermissionLevel, allowed: Iterable[PermissionLevel]
    ) -> bool:
        return any(
            PERMISSION_RANK[item] >= PERMISSION_RANK[observed] for item in allowed
        )

    @classmethod
    def _resource_allowed(cls, resource: str, patterns: Iterable[str]) -> bool:
        return any(cls._resource_matches(resource, pattern) for pattern in patterns)

    @staticmethod
    def _resource_matches(resource: str, pattern: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith("/*"):
            prefix = pattern[:-2].rstrip("/")
            return resource == prefix or resource.startswith(prefix + "/")
        return resource == pattern

    @classmethod
    def _is_sensitive(
        cls,
        grant: Optional[AgentAccessGrant],
        observation: AgentApiObservation,
    ) -> bool:
        if observation.resource_sensitive:
            return True
        if grant is None or not observation.resource:
            return False
        return cls._resource_allowed(
            observation.resource, grant.sensitive_resources
        )

    @staticmethod
    def _finding(
        rule_id: str,
        *,
        detail: str,
        evidence: List[str],
        blocking: bool,
        severity: Optional[RiskLevel] = None,
    ) -> AgentThreatFinding:
        definition = AGENT_ACCESS_RULE_CATALOG[rule_id]
        return AgentThreatFinding(
            rule_id=rule_id,
            category=str(definition["category"]),
            severity=severity or definition["severity"],
            title=str(definition["title"]),
            detail=sanitize_security_text(detail),
            evidence=[sanitize_security_text(item) for item in evidence],
            blocking=blocking,
        )

    @staticmethod
    def _decision(
        observation: AgentApiObservation,
        findings: List[AgentThreatFinding],
        matched_grant: Optional[AgentAccessGrant],
    ) -> AgentAccessDecision:
        findings = AgentAccessEvaluator._dedupe_findings(findings)
        if any(item.blocking for item in findings):
            outcome = AgentAccessOutcome.DENY
        elif findings:
            outcome = AgentAccessOutcome.REVIEW
        else:
            outcome = AgentAccessOutcome.ALLOW
        overall = (
            max(findings, key=lambda item: _SEVERITY_RANK[item.severity]).severity
            if findings
            else None
        )
        decision_id = str(
            uuid5(
                NAMESPACE_URL,
                f"nhi-agent-access:{observation.claimed_agent_id}:{observation.event_id}",
            )
        )
        return AgentAccessDecision(
            decision_id=decision_id,
            event_id=observation.event_id,
            agent_id=observation.claimed_agent_id,
            outcome=outcome,
            overall_severity=overall,
            matched_grant_id=matched_grant.grant_id if matched_grant else None,
            findings=findings,
            observation=observation,
        )

    @staticmethod
    def _dedupe_findings(
        findings: List[AgentThreatFinding],
    ) -> List[AgentThreatFinding]:
        """한 호출에서 같은 규칙을 한 번만 표시하고 근거만 합친다."""
        unique: Dict[str, AgentThreatFinding] = {}
        for finding in findings:
            previous = unique.get(finding.rule_id)
            if previous is None:
                unique[finding.rule_id] = finding
                continue
            previous.evidence = list(
                dict.fromkeys([*previous.evidence, finding.detail, *finding.evidence])
            )
            previous.blocking = previous.blocking or finding.blocking
            if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[previous.severity]:
                previous.severity = finding.severity
        return list(unique.values())


__all__ = ["AGENT_ACCESS_RULE_CATALOG", "AgentAccessEvaluator"]
