"""NHI 생명주기 — 관리적 상태(`NHILifecycleStatus`)와 그 변화를 남기는 이벤트.

NHI "상태"(이 신원이 조직에서 등록·운영·종료·파기 중 어느 단계인가)는
`core.models.SecretFinding.credential_active`/`credential_revoked`(Credential
자체가 기술적으로 유효한가)와는 다른 축이다. 둘을 하나로 섞지 않는다 — NHI는
`DEACTIVATED`인데 Credential은 여전히 active인 경우처럼 둘이 어긋나는 상태
자체가 중요한 위험 신호이기 때문이다(`backend/services/nhi_lifecycle.py` 와
대시보드가 이 불일치를 그대로 보여줄 수 있어야 한다).

`PERMISSION_CHANGED`는 상태값이 아니라 Timeline 이벤트 유형이다 — 권한이
바뀌어도 NHI는 보통 계속 `ACTIVE`로 운영되므로, 이를 상태 전이로 취급하면
"현재 사용 중"이라는 정보가 사라진다. 상태는 그대로 두고 이벤트만 남긴다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class NHILifecycleStatus(str, Enum):
    """NHI 신원의 관리적 생명주기 상태.

    4종만 둔다 — "권한 변경"은 상태가 아니라
    `NHILifecycleEventType.PERMISSION_CHANGED` 이벤트로만 기록한다.
    """

    REGISTERED = "REGISTERED"
    ACTIVE = "ACTIVE"
    DEACTIVATED = "DEACTIVATED"
    DECOMMISSIONED = "DECOMMISSIONED"


class NHILifecycleEventType(str, Enum):
    """Timeline에 남는 생명주기 이벤트 유형.

    `CREATED`/`ACTIVATED`/`DEACTIVATED`/`REACTIVATED`/`DECOMMISSIONED`는
    상태 전이를 동반한다(`STATUS_TRANSITION_EVENTS`). `PERMISSION_CHANGED`만
    상태를 바꾸지 않고 현재 상태를 유지한 채 기록만 남긴다.
    """

    CREATED = "CREATED"                        # 생성·등록 → REGISTERED
    ACTIVATED = "ACTIVATED"                     # 사용 시작 → ACTIVE
    PERMISSION_CHANGED = "PERMISSION_CHANGED"   # 권한 변경 (상태 전이 없음)
    DEACTIVATED = "DEACTIVATED"                 # 종료 → DEACTIVATED
    REACTIVATED = "REACTIVATED"                 # 종료 후 재사용 → ACTIVE
    DECOMMISSIONED = "DECOMMISSIONED"           # 파기 → DECOMMISSIONED (최종)


#: 상태 전이를 동반하는 이벤트 유형 — `PERMISSION_CHANGED`만 제외된다.
STATUS_TRANSITION_EVENTS = frozenset(
    event
    for event in NHILifecycleEventType
    if event is not NHILifecycleEventType.PERMISSION_CHANGED
)


@dataclass
class NHILifecycleEvent:
    """NHI 1건의 생명주기 Timeline 항목 1건.

    `from_status == to_status`이면 상태를 바꾸지 않은 순수 이벤트
    (`PERMISSION_CHANGED`)라는 뜻이다 — 상태 전이 이력과 이벤트 로그를
    같은 레코드 형태로 다루기 위한 의도적인 설계다.
    """

    nhi_id: str
    event_type: NHILifecycleEventType
    from_status: Optional[NHILifecycleStatus]
    to_status: NHILifecycleStatus
    actor: str
    note: str = ""
    #: Credential 변경과 무관한 참고 정보(예: 관련 recommended_action,
    #: analysis_id). 원문 Secret은 절대 담지 않는다.
    detail: Dict[str, Any] = field(default_factory=dict)
    history_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: str = field(default_factory=_utcnow)

    @property
    def changes_status(self) -> bool:
        return self.from_status != self.to_status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "history_id": self.history_id,
            "nhi_id": self.nhi_id,
            "event_type": self.event_type.value,
            "from_status": self.from_status.value if self.from_status else None,
            "to_status": self.to_status.value,
            "changes_status": self.changes_status,
            "actor": self.actor,
            "note": self.note,
            "detail": dict(self.detail),
            "occurred_at": self.occurred_at,
        }
