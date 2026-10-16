"""회사 AI Agent의 승인 기준선과 API 관측 이벤트를 비교한다.

규칙 ID와 설명을 한 곳에 모아, 이후 실제 정보유출 사례·권한 범용 사례가
추가되더라도 Connector나 위험 점수 엔진을 직접 수정하지 않고 규칙을 확장할 수 있다.

실시간 Gateway 집행 설계 노트 (이 모듈은 판정만 하고 집행은 하지 않음):
`AgentAccessOutcome.REVIEW`를 실제 요청에 어떻게 적용할지는 Gateway/집행
계층의 책임이지만, 이 모듈의 설계는 그 기본 원칙(REVIEW는 기본적으로
차단하고, `category == "coverage"`뿐인 완화 가능한 경우만 예외적으로
허용)을 전제로 한다 — `category == "lifecycle"`인 finding(이번에 추가한
`NHI_LIFECYCLE_NOT_ACTIVE`/`CREDENTIAL_KNOWN_REVOKED` 포함)은 항상
`blocking=True`로 둬서 이 원칙과 충돌하지 않게 한다. 집행 정책을 실제로
계산하는 코드는 이후 단계에서 추가한다.
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
    NHIAccessContext,
)
from core.nhi_lifecycle_models import NHILifecycleStatus
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
    "NHI_LIFECYCLE_NOT_ACTIVE": {
        "category": "lifecycle",
        "severity": RiskLevel.CRITICAL,
        "title": "비활성/파기된 NHI 사용",
        "description": "종료(DEACTIVATED) 또는 파기(DECOMMISSIONED) 처리된 NHI로 호출이 들어옴",
    },
    "CREDENTIAL_KNOWN_REVOKED": {
        "category": "lifecycle",
        "severity": RiskLevel.CRITICAL,
        "title": "폐기 확인된 Credential 재사용",
        "description": "분석에서 폐기가 확인된 Credential로 호출이 계속 들어옴",
    },
    "NHI_LIFECYCLE_PENDING_ACTIVATION": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "미활성화 NHI 사용",
        "description": "등록(REGISTERED)만 되어 있고 아직 사용 승인(ACTIVE) 전인 NHI로 호출이 들어옴",
    },
    "NHI_LIFECYCLE_UNKNOWN": {
        "category": "coverage",
        "severity": RiskLevel.MEDIUM,
        "title": "NHI 생명주기 상태 미확인",
        "description": "이 NHI의 생명주기 상태를 확인할 수 없어 활성 여부를 단정하지 않음",
    },
    "AGENT_CALL_RATE_SPIKE": {
        "category": "abuse",
        "severity": RiskLevel.MEDIUM,
        "title": "호출률 급증",
        "description": (
            "서버가 직접 측정한 최근 호출률이 평소 기준선 대비 비정상적으로 높음 "
            "(요청자가 신고한 값이 아니라 backend/services/usage_rate.py 가 서버 "
            "측에서 집계한 값)"
        ),
    },
    "EVALUATOR_UNAVAILABLE": {
        "category": "infrastructure",
        "severity": RiskLevel.CRITICAL,
        "title": "접근 평가 실패",
        "description": (
            "평가 로직 내부 오류로 판정을 완료하지 못해 기본 차단(fail-closed)으로 "
            "처리됨 — 이 항목은 AgentAccessEvaluator가 직접 만들지 않고 "
            "backend/services/access_enforcement.py::build_fail_closed_decision() "
            "이 이 카탈로그 설명을 그대로 참조해 만든다."
        ),
    },
}


_SEVERITY_RANK = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

#: 서버 측정 호출률이 기준선의 이 배수를 넘으면 REVIEW 사유를 남긴다.
#: 통계적 추정(오탐 가능)이라 이 자체로 DENY(blocking=True)를 만들지는 않는다
#: — QUARANTINE/자동 격리 같은 강한 조치는 이번 단계에서 도입하지 않는다.
CALL_RATE_SPIKE_RATIO = 5.0


class AgentAccessEvaluator:
    """승인된 Agent 접근 범위와 한 번의 API 호출을 결정적으로 비교한다."""

    def evaluate(
        self,
        profile: Optional[AgentAccessProfile],
        observation: AgentApiObservation,
        *,
        nhi_context: Optional[NHIAccessContext] = None,
        call_rate_ratio: Optional[float] = None,
    ) -> AgentAccessDecision:
        """`profile`/`observation`은 기존과 동일하게 평가한다.

        `nhi_context`는 선택 인자다 — `None`(기본값, 생략)이면 NHI 생명주기/
        Credential 폐기 확인 검사를 **전혀 수행하지 않는다**(기존 호출부와
        완전히 동일한 결과). 호출부가 `storage.get_nhi_lifecycle_state()`
        등으로 조회한 `NHIAccessContext`를 명시적으로 넘겨야만 이 검사가
        켜진다 — Gateway가 보낸 `observation` 자체에서는 이 정보를 절대
        신뢰하지 않는다(자가 신고로 통제를 무력화할 수 있기 때문).

        `call_rate_ratio`도 선택 인자다 — `None`(기본값)이면 호출률 검사를
        하지 않는다. 호출부가 `backend/services/usage_rate.py::UsageRateTracker`
        로 **서버가 직접 측정한** `RateSample.ratio`를 넘겨야 켜진다 — 이
        평가기는 상태를 갖지 않는 순수 함수로 유지하기 위해 측정 자체는
        하지 않는다. 통계적 추정이므로 `blocking=False`(REVIEW)로만 반영한다.
        """
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

        self._evaluate_nhi_lifecycle(nhi_context, findings)
        self._evaluate_call_rate(call_rate_ratio, findings)

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

    def _evaluate_nhi_lifecycle(
        self,
        nhi_context: Optional[NHIAccessContext],
        findings: List[AgentThreatFinding],
    ) -> None:
        """NHI 생명주기 상태·Credential 폐기 확인 여부를 평가한다.

        `nhi_context`가 `None`이면(호출부가 조회하지 않음) 아무 것도 하지
        않는다 — 기존 호출부와 완전히 동일하게 동작해야 하기 때문이다.
        `nhi_context`가 주어지면, 그 내부 필드가 둘 다 `None`이어도(= 조회는
        했지만 아직 초기화/확인되지 않음) `NHI_LIFECYCLE_UNKNOWN`으로
        REVIEW 사유를 남긴다 — "확인 안 함"과 "확인했는데 모름"을 구분한다.

        DEACTIVATED/DECOMMISSIONED NHI와 폐기가 확인된 Credential은
        `blocking=True`(DENY)로, REGISTERED(아직 미활성)와 상태 미확인은
        `blocking=False`(REVIEW, 서로 다른 rule_id)로 구분한다.
        """
        if nhi_context is None:
            return

        if nhi_context.credential_known_revoked is True:
            findings.append(
                self._finding(
                    "CREDENTIAL_KNOWN_REVOKED",
                    detail="직전 분석에서 이 Credential의 폐기가 확인됐으나 계속 사용되고 있음",
                    evidence=["credential_known_revoked=true"],
                    blocking=True,
                )
            )

        status = nhi_context.lifecycle_status
        if status in (NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.DECOMMISSIONED):
            findings.append(
                self._finding(
                    "NHI_LIFECYCLE_NOT_ACTIVE",
                    detail=f"NHI 생명주기 상태가 {status.value}임",
                    evidence=[f"nhi_lifecycle_status={status.value}"],
                    blocking=True,
                )
            )
        elif status is NHILifecycleStatus.REGISTERED:
            findings.append(
                self._finding(
                    "NHI_LIFECYCLE_PENDING_ACTIVATION",
                    detail="NHI가 등록만 되어 있고 아직 사용 승인(ACTIVE) 전임",
                    evidence=["nhi_lifecycle_status=REGISTERED"],
                    blocking=False,
                )
            )
        elif status is None:
            findings.append(
                self._finding(
                    "NHI_LIFECYCLE_UNKNOWN",
                    detail="NHI 생명주기 상태를 확인할 수 없음(조회 안 됨 또는 이 기능 도입 이전 NHI)",
                    evidence=["nhi_lifecycle_status=unknown"],
                    blocking=False,
                )
            )
        # status is ACTIVE → 추가 finding 없음(정상 상태)

    def _evaluate_call_rate(
        self,
        call_rate_ratio: Optional[float],
        findings: List[AgentThreatFinding],
    ) -> None:
        """서버가 측정한 호출률이 기준선 대비 급증했는지 반영한다.

        `call_rate_ratio`가 `None`이면(호출부가 측정하지 않음) 아무 것도
        하지 않는다 — 기존 호출부와 완전히 동일하게 동작해야 하기 때문이다
        (`_evaluate_nhi_lifecycle`과 같은 설계). 통계적 추정이라 항상
        `blocking=False`(REVIEW)다 — 이 신호만으로 DENY(차단)를 만들지
        않는다.
        """
        if call_rate_ratio is None or call_rate_ratio < CALL_RATE_SPIKE_RATIO:
            return
        findings.append(
            self._finding(
                "AGENT_CALL_RATE_SPIKE",
                detail=f"서버 측정 호출률이 기준선의 {call_rate_ratio:.1f}배임",
                evidence=[f"call_rate_ratio={call_rate_ratio:.2f}"],
                blocking=False,
            )
        )

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
