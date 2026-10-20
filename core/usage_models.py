"""공급자별 감사 로그를 분석 파이프라인으로 전달하는 공통 사용 이벤트 모델."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from core.nhi_models import parse_dt


@dataclass
class UsageEvent:
    """NHI가 API·SaaS 자원에 수행한 한 번의 관측 행위.

    공급자 원본 응답 전체를 보관하지 않고, 권한·수명·프로젝트 공유 분석에 필요한
    최소 필드만 유지한다. ``principal_id``는 조직이 관리하는 NHI 식별자다.
    """

    event_id: str
    provider: str
    principal_id: str
    action: str
    occurred_at: str
    source: str = "audit_log"
    project: Optional[str] = None
    resource: Optional[str] = None
    success: Optional[bool] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        *,
        default_provider: str = "generic",
        default_source: str = "audit_log",
    ) -> "UsageEvent":
        if not isinstance(data, dict):
            raise TypeError("usage event는 객체여야 합니다.")

        provider = _first(data, "provider") or default_provider
        principal_id = _first(
            data,
            "principal_id",
            "nhi_id",
            "actor_id",
            "client_id",
            "service_principal_id",
        )
        action = _first(data, "action", "event_type", "operation", "method")
        occurred = _first(
            data, "occurred_at", "timestamp", "created_at", "event_time"
        )
        if not principal_id:
            raise ValueError("principal_id가 없습니다.")
        if not action:
            raise ValueError("action이 없습니다.")
        occurred_at = _iso_timestamp(occurred)

        project = _first(data, "project", "project_id", "repository") or None
        resource = _first(data, "resource", "resource_id", "target") or None
        source = _first(data, "source", "log_source") or default_source
        event_id = _first(data, "event_id", "id")
        if not event_id:
            material = "|".join(
                str(item)
                for item in (
                    provider,
                    principal_id,
                    action,
                    occurred_at,
                    project or "",
                    resource or "",
                )
            )
            event_id = "usage:" + hashlib.sha256(
                material.encode("utf-8")
            ).hexdigest()[:24]

        success = data.get("success")
        if not isinstance(success, bool):
            status = str(data.get("status") or "").strip().lower()
            success = (
                True
                if status in {"success", "succeeded", "ok"}
                else (False if status in {"failure", "failed", "error"} else None)
            )
        attributes = data.get("attributes")
        return cls(
            event_id=str(event_id).strip(),
            provider=str(provider).strip().lower(),
            principal_id=str(principal_id).strip(),
            action=str(action).strip(),
            occurred_at=occurred_at,
            source=str(source).strip(),
            project=str(project).strip() if project else None,
            resource=str(resource).strip() if resource else None,
            success=success,
            attributes=dict(attributes) if isinstance(attributes, dict) else {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _first(data: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None and str(value).strip():
            return value
    return None


def _iso_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    parsed = parse_dt(str(value) if value is not None else None)
    if parsed is None:
        raise ValueError("occurred_at이 올바른 ISO 8601 시각이 아닙니다.")
    return parsed.isoformat()


__all__ = ["UsageEvent"]
