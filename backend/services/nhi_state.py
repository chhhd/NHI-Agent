"""거버넌스 서비스 3종이 공유하는 NHI 레코드 접근 도우미.

NHI 의 현재 형상(생명주기 단계 · Credential 상태 · 통제 상태 · 권한 · 버전)은
`nhi_identities` 레코드 하나에 있다. 변경 승인, 실시간 통제, 생명주기가 같은
레코드를 읽고 쓰므로 프로세스 단위 잠금으로 read-modify-write 를 직렬화한다.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.governance_models import (
    SNAPSHOT_FIELDS,
    ControlState,
    CredentialState,
    LifecycleStage,
)
from storage.base import Storage

#: 거버넌스 상태를 바꾸는 모든 경로가 잡는 잠금 (단일 프로세스 기준).
GOVERNANCE_LOCK = threading.RLock()

#: `get_nhi_record` 가 조회 편의로 덧붙이는 파생 필드 — 저장 시 제거한다.
_DERIVED_KEYS = ("credentials", "recent_analyses")


def load_nhi(storage: Storage, nhi_id: str) -> Dict[str, Any]:
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise KeyError(nhi_id)
    for key in _DERIVED_KEYS:
        record.pop(key, None)
    return record


def load_nhi_with_credentials(storage: Storage, nhi_id: str) -> Dict[str, Any]:
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise KeyError(nhi_id)
    return record


def save_nhi(storage: Storage, nhi: Dict[str, Any]) -> None:
    clean = {key: value for key, value in nhi.items() if key not in _DERIVED_KEYS}
    storage.upsert_nhi(clean["nhi_id"], clean)


def snapshot(nhi: Dict[str, Any]) -> Dict[str, Any]:
    """레코드에 값이 없어도 기본 형상(사용 중 · 정상 · v1)으로 해석한다."""
    return {
        "lifecycle_stage": LifecycleStage(nhi.get("lifecycle_stage") or LifecycleStage.ACTIVE.value).value,
        "credential_state": nhi.get("credential_state") or CredentialState.ACTIVE.value,
        "control_state": nhi.get("control_state") or ControlState.NORMAL.value,
        "permissions": list(nhi.get("permissions") or []),
        "raw_scopes": list(nhi.get("raw_scopes") or []),
        "credential_version": int(nhi.get("credential_version") or 1),
    }


def apply_snapshot(nhi: Dict[str, Any], values: Dict[str, Any]) -> None:
    for key in SNAPSHOT_FIELDS:
        if key in values:
            nhi[key] = values[key]


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def days_between(earlier: Optional[str], now: datetime) -> Optional[int]:
    moment = parse_dt(earlier)
    return None if moment is None else max((now - moment).days, 0)


def is_demo(nhi: Dict[str, Any]) -> bool:
    return bool(nhi.get("demo_workspace"))
