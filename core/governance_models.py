"""NHI 거버넌스 모델 — 생명주기 · 변경 승인(영향도 미리보기/롤백) · 실시간 통제.

세 축이 하나의 NHI 레코드를 공유한다.

    LifecycleStage   등록 → 사용 → 사용 중지 → 폐기 완료; 권한 변경은 이벤트
    ChangeRequest    폐기/교체/권한변경 전후 형상을 보여 주고 관리자 승인 후에만 적용
    ControlEvent     실시간 사용 이벤트의 ALLOW/ALERT/REVIEW/DENY 판정
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 생명주기
# ---------------------------------------------------------------------------
class LifecycleStage(str, Enum):
    REGISTERED = "REGISTERED"              # 등록
    ACTIVE = "ACTIVE"                      # 사용
    DEACTIVATED = "DEACTIVATED"            # 사용 중지
    DECOMMISSIONED = "DECOMMISSIONED"      # 증적이 확인된 폐기 완료

    @classmethod
    def _missing_(cls, value):
        # 기존 저장 데이터와 승인 요청의 호환 입력. 출력은 항상 4단계다.
        return {
            "CREATION": cls.REGISTERED,
            "PERMISSION_CHANGE": cls.ACTIVE,
            "TERMINATION": cls.DEACTIVATED,
            "DISPOSED": cls.DECOMMISSIONED,
        }.get(value)


#: 허용되는 단계 전이. TERMINATION → ACTIVE 는 폐기 롤백(서비스 연속성 확보)에서만 쓰인다.
STAGE_TRANSITIONS = {
    LifecycleStage.REGISTERED: {LifecycleStage.ACTIVE, LifecycleStage.DEACTIVATED},
    LifecycleStage.ACTIVE: {LifecycleStage.DEACTIVATED},
    LifecycleStage.DEACTIVATED: {LifecycleStage.DECOMMISSIONED, LifecycleStage.ACTIVE},
    LifecycleStage.DECOMMISSIONED: set(),
}

STAGE_LABELS = {
    LifecycleStage.REGISTERED: "등록",
    LifecycleStage.ACTIVE: "사용",
    LifecycleStage.DEACTIVATED: "사용 중지",
    LifecycleStage.DECOMMISSIONED: "폐기 완료",
}


class CredentialState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"      # 폐기됨(소프트 폐기 — 파기 전까지 롤백 가능)
    DISPOSED = "DISPOSED"    # Secret material 파기 완료


class ControlState(str, Enum):
    NORMAL = "NORMAL"
    QUARANTINED = "QUARANTINED"  # 실시간 통제로 격리됨 — 모든 사용 요청 차단


#: 롤백과 변경 충돌 검사에 쓰는 NHI 형상 필드. 변경 전/후 비교는 이 필드만 대상으로 한다.
SNAPSHOT_FIELDS = (
    "lifecycle_stage",
    "credential_state",
    "control_state",
    "permissions",
    "raw_scopes",
    "credential_version",
)

#: 재분석(`upsert_nhi`)이 덮어쓰지 않도록 보존해야 하는 거버넌스 상태.
#: permissions / raw_scopes 는 제외한다 — 재분석이 관측한 실제 권한이 우선해야
#: 권한 변경이 Provider 에 실제로 반영되었는지 드러난다.
PRESERVED_ON_REANALYSIS = (
    "lifecycle_stage",
    "credential_state",
    "control_state",
    "credential_version",
    "first_seen_at",
    "stage_entered_at",
    "terminated_at",
    "disposed_at",
    "last_rotated_at",
    "previous_credential_expires_at",
    "known_sources",
)


@dataclass
class LifecycleEvent:
    nhi_id: str
    stage: str
    event_type: str
    actor: str
    detail: Dict[str, Any] = field(default_factory=dict)
    change_id: Optional[str] = None
    demo_workspace: bool = False
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 변경 승인
# ---------------------------------------------------------------------------
class ChangeType(str, Enum):
    TOKEN_REVOKE = "TOKEN_REVOKE"      # 폐기
    TOKEN_ROTATE = "TOKEN_ROTATE"      # 교체
    SCOPE_CHANGE = "SCOPE_CHANGE"      # 권한 변경
    TOKEN_DISPOSE = "TOKEN_DISPOSE"    # 파기(Secret material 제거, 되돌릴 수 없음)
    QUARANTINE = "QUARANTINE"          # 실시간 통제 격리(가역)


class ChangeStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"  # 내부 Inventory 실행기가 적용에 실패 — 상태는 변경되지 않았다


class ApprovalTier(str, Enum):
    """권한 중요도에 따른 위험 표시 등급(승인 인원/역할은 모두 동일)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ChangeRequest:
    nhi_id: str
    nhi_name: str
    change_type: ChangeType
    requested_by: str
    reason: str
    tier: ApprovalTier
    approval: Dict[str, Any]
    params: Dict[str, Any]
    before: Dict[str, Any]
    after: Dict[str, Any]
    impact: Dict[str, Any]
    rollback: Dict[str, Any]
    change_id: str = field(default_factory=lambda: str(uuid4()))
    status: ChangeStatus = ChangeStatus.PENDING_APPROVAL
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    decision_reason: str = ""
    impact_acknowledged: bool = False
    applied_at: Optional[str] = None
    apply_result: Optional[Dict[str, Any]] = None
    rollback_expires_at: Optional[str] = None
    rolled_back_by: Optional[str] = None
    rolled_back_at: Optional[str] = None
    rollback_reason: str = ""
    source: str = "operator"  # operator | control-plane
    demo_workspace: bool = False
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["change_type"] = self.change_type.value
        data["status"] = self.status.value
        data["tier"] = self.tier.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChangeRequest":
        values = dict(data)
        values["change_type"] = ChangeType(values["change_type"])
        values["status"] = ChangeStatus(values["status"])
        values["tier"] = ApprovalTier(values["tier"])
        for name in ("before", "after"):
            state = dict(values.get(name) or {})
            if state.get("lifecycle_stage"):
                state["lifecycle_stage"] = LifecycleStage(state["lifecycle_stage"]).value
            values[name] = state
        known = cls.__dataclass_fields__.keys()
        return cls(**{key: value for key, value in values.items() if key in known})


# ---------------------------------------------------------------------------
# 실시간 통제
# ---------------------------------------------------------------------------
class ControlEventType(str, Enum):
    CREDENTIAL_USE = "CREDENTIAL_USE"            # 권한 사용 요청(인가 질의 포함)
    USAGE_SPIKE = "USAGE_SPIKE"                  # 사용량 급증
    EXPOSURE_DETECTED = "EXPOSURE_DETECTED"      # Credential 외부 노출 확인


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"          # 추가 검토 필요; 운영 모드로 집행 결정
    ALERT = "ALERT"            # 허용하되 경고
    DENY = "DENY"              # 이번 요청 차단
    QUARANTINE = "QUARANTINE"  # NHI 전체 격리


VERDICT_ORDER = {
    Verdict.ALLOW: 0,
    Verdict.ALERT: 1,
    Verdict.REVIEW: 2,
    Verdict.DENY: 3,
    Verdict.QUARANTINE: 4,  # 과거 저장 이벤트 호환용; 신규 접근 판정에는 사용하지 않는다.
}


@dataclass
class ControlEvent:
    nhi_id: str
    event_type: str
    verdict: str
    severity: str
    rules: List[Dict[str, Any]] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    enforced: bool = True
    allowed: bool = True
    change_id: Optional[str] = None
    follow_up_change_ids: List[str] = field(default_factory=list)
    demo_workspace: bool = False
    seq: int = 0
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
