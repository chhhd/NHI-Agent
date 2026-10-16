"""NHI lifecycle 상태 전이 규칙.

`backend/services/finding_lifecycle.py`와 같은 구조(허용 전이 테이블 +
`validate_transition()`)를 그대로 따른다. NHI 상태는 4종뿐이고, "권한 변경"은
상태가 아니라 `core.nhi_lifecycle_models.NHILifecycleEventType.PERMISSION_CHANGED`
이벤트로만 기록되므로 이 전이 규칙에는 등장하지 않는다. Credential 자체의
활성/폐기 여부(`core.models.SecretFinding.credential_active`/
`credential_revoked`)는 이 전이 규칙과 무관한 별도 축이다 — 이 모듈은 그 값을
읽지도, 바꾸지도 않는다.
"""

from __future__ import annotations

from typing import Dict, Set, Tuple

from core.nhi_lifecycle_models import NHILifecycleEventType, NHILifecycleStatus

ALLOWED_TRANSITIONS: Dict[NHILifecycleStatus, Set[NHILifecycleStatus]] = {
    NHILifecycleStatus.REGISTERED: {
        NHILifecycleStatus.ACTIVE,
        NHILifecycleStatus.DEACTIVATED,
    },
    NHILifecycleStatus.ACTIVE: {
        NHILifecycleStatus.DEACTIVATED,
    },
    NHILifecycleStatus.DEACTIVATED: {
        NHILifecycleStatus.ACTIVE,            # 종료 후 재사용(REACTIVATED)
        NHILifecycleStatus.DECOMMISSIONED,
    },
    NHILifecycleStatus.DECOMMISSIONED: set(),  # 최종 상태 — 이후 전이 없음
}


def validate_transition(current: NHILifecycleStatus, target: NHILifecycleStatus) -> None:
    if current == target:
        return
    if target not in ALLOWED_TRANSITIONS.get(current, set()):
        raise ValueError(
            f"허용되지 않은 NHI 생명주기 전이입니다: {current.value} -> {target.value}"
        )


#: 수동 전이 요청(`PATCH /nhi/{id}/lifecycle`)에서 (현재, 목표) 상태 조합에
#: 붙일 이벤트 이름. 전이 허용 여부의 단일 진실 공급원은 여전히
#: `ALLOWED_TRANSITIONS`/`validate_transition()` 이고, 이 맵은 "이미 허용된
#: 전이"에 이벤트 이름만 결정한다 — `(REGISTERED, DEACTIVATED)`처럼 같은
#: `to_status`라도 `(ACTIVE, DEACTIVATED)`와 이벤트 이름은 동일하지만, 기존
#: 상태가 달라 이력에서 "어디서 왔는지"는 `from_status`로 여전히 구분된다.
EVENT_TYPE_FOR_TRANSITION: Dict[
    Tuple[NHILifecycleStatus, NHILifecycleStatus], NHILifecycleEventType
] = {
    (NHILifecycleStatus.REGISTERED, NHILifecycleStatus.ACTIVE): NHILifecycleEventType.ACTIVATED,
    (NHILifecycleStatus.REGISTERED, NHILifecycleStatus.DEACTIVATED): NHILifecycleEventType.DEACTIVATED,
    (NHILifecycleStatus.ACTIVE, NHILifecycleStatus.DEACTIVATED): NHILifecycleEventType.DEACTIVATED,
    (NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.ACTIVE): NHILifecycleEventType.REACTIVATED,
    (NHILifecycleStatus.DEACTIVATED, NHILifecycleStatus.DECOMMISSIONED): NHILifecycleEventType.DECOMMISSIONED,
}


def event_type_for_transition(
    current: NHILifecycleStatus, target: NHILifecycleStatus
) -> NHILifecycleEventType:
    """(현재, 목표) 전이에 대응하는 이벤트 유형.

    먼저 `validate_transition()`으로 전이 자체가 허용되는지 확인한다 —
    허용되지 않은 전이면 거기서 `ValueError`가 난다. 허용된 전이인데도 이
    맵에 없다면(새 상태/전이가 추가되고 이 맵이 갱신되지 않은 경우) 같은
    `ValueError`로 알려 조용히 틀린 이벤트 이름이 쓰이지 않게 한다.
    """
    validate_transition(current, target)
    try:
        return EVENT_TYPE_FOR_TRANSITION[(current, target)]
    except KeyError as exc:
        raise ValueError(
            f"'{current.value} -> {target.value}' 전이에 대응하는 이벤트 유형이 "
            "정의되지 않았습니다 — EVENT_TYPE_FOR_TRANSITION 을 갱신하세요."
        ) from exc
