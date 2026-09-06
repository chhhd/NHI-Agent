"""수집 계층의 표준 Observation / Evidence 모델.

외부 시스템마다 서로 다른 응답을 바로 분석 엔진에 넘기지 않고, 먼저
``CredentialObservation`` 으로 정규화한다. 모든 사실에는 출처·수집 시각·
신뢰도를 남겨 이후 점수의 재현성과 감사 가능성을 보장한다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Evidence:
    """Observation 을 구성하는 단일 근거."""

    source: str
    field: str
    value: Any
    confidence: float = 1.0
    collected_at: str = field(default_factory=_utcnow)
    expires_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(
            source=str(data.get("source", "")),
            field=str(data.get("field", "")),
            value=data.get("value"),
            confidence=float(data.get("confidence", 1.0)),
            collected_at=str(data.get("collected_at") or _utcnow()),
            expires_at=data.get("expires_at"),
        )


@dataclass
class CredentialObservation:
    """수집원이 관측한 Credential 관련 사실의 공통 표현."""

    source_type: str
    source_event_id: str
    provider: str
    raw_type: str
    fingerprint: str
    observation_id: str = field(default_factory=lambda: str(uuid4()))
    observed_at: str = field(default_factory=_utcnow)
    repository: Optional[str] = None
    path: Optional[str] = None
    masked_value: str = ""
    secret_ref: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [item.to_dict() for item in self.evidence]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CredentialObservation":
        return cls(
            observation_id=str(data.get("observation_id") or uuid4()),
            source_type=str(data.get("source_type", "")),
            source_event_id=str(data.get("source_event_id", "")),
            provider=str(data.get("provider", "unknown")),
            raw_type=str(data.get("raw_type", "")),
            fingerprint=str(data.get("fingerprint", "")),
            observed_at=str(data.get("observed_at") or _utcnow()),
            repository=data.get("repository"),
            path=data.get("path"),
            masked_value=str(data.get("masked_value", "")),
            secret_ref=data.get("secret_ref"),
            evidence=[
                Evidence.from_dict(item)
                for item in data.get("evidence", [])
                if isinstance(item, dict)
            ],
            raw_metadata=dict(data.get("raw_metadata") or {}),
        )


@dataclass
class UsageEvent:
    """Provider-independent representation of an NHI usage event."""

    nhi_id: str
    timestamp: str
    action: str
    resource_type: str
    provider: str = "unknown"
    resource_id: Optional[str] = None
    resource: Optional[str] = None
    raw_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsageEvent":
        return cls(
            nhi_id=str(data.get("nhi_id") or data.get("credential_id") or ""),
            timestamp=str(data.get("timestamp") or ""),
            action=str(data.get("action") or ""),
            resource_type=str(data.get("resource_type") or "unknown"),
            provider=str(data.get("provider") or "unknown"),
            resource_id=data.get("resource_id"),
            resource=data.get("resource"),
            raw_action=data.get("raw_action"),
            metadata=dict(data.get("metadata") or {}),
        )
