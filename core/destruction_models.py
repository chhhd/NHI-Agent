"""NHI 파기 증적 모델.

`DECOMMISSIONED`는 "파기했다"는 주장이 아니라 증적이 있어야만 의미가 있다.
증적에는 파기 방법, 수행자와 **다른** 검증자, 검증 방법, 그리고 파기 후
"더 이상 쓸 수 없음"을 보여주는 결과가 필요하다. 수행자가 자기 작업을
스스로 검증하면 증적으로 인정하지 않는다.

`DestructionMethod`는 "실제 Provider 측 Credential 폐기(`PROVIDER_REVOKED`)"와
"우리 내부에 보관 중인 암호문 삭제(`SECRET_MATERIAL_DELETED`)"를 서로 다른
값으로 구분한다 — 후자는 우리 저장소의 복사본을 지운 것일 뿐, Provider(GitHub/
Slack/AWS 등)에 아직 유효한 Credential이 남아있을 수 있다는 사실을 숨기지
않기 위함이다. `backend/services/nhi_lifecycle.py`가 관리하는 NHI "관리적
상태"(DECOMMISSIONED)와 이 증적은 서로 다른 축이다 — 상태 전이는 증적 없이도
일어날 수 있고(하위 호환), 증적이 있으면 그 사실과 방법까지 Timeline에
남는다는 차이만 있다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class DestructionMethod(str, Enum):
    PROVIDER_REVOKED = "PROVIDER_REVOKED"                # 공급자 API 로 Credential 폐기
    ACCOUNT_DELETED = "ACCOUNT_DELETED"                  # 서비스 계정·App 자체 삭제
    SECRET_MATERIAL_DELETED = "SECRET_MATERIAL_DELETED"  # 보관 중인 원문·키 삭제 (Provider 폐기와 무관)


#: 파기 후 "더 이상 쓸 수 없음"을 보여주는 검증 결과만 증적으로 인정한다.
ACCEPTED_DESTRUCTION_RESULTS = frozenset(
    {"AUTH_REJECTED_401", "AUTH_REJECTED_403", "NOT_FOUND_404", "MATERIAL_ABSENT"}
)


@dataclass
class DestructionEvidence:
    """파기 증적 1건. `performed_by`(수행자)와 `verified_by`(검증자)는 반드시 달라야 한다."""

    method: DestructionMethod
    performed_by: str
    verified_by: str
    verification_check: str
    verification_result: str
    verified_at: str = field(default_factory=_utcnow)
    notes: str = ""

    def validate(self) -> None:
        if not self.performed_by.strip() or not self.verified_by.strip():
            raise ValueError("파기 수행자와 검증자를 모두 기록해야 합니다.")
        if self.performed_by.strip() == self.verified_by.strip():
            raise ValueError("파기 수행자와 검증자는 서로 달라야 합니다.")
        if not self.verification_check.strip():
            raise ValueError("파기 검증 방법을 기록해야 합니다.")
        if self.verification_result not in ACCEPTED_DESTRUCTION_RESULTS:
            raise ValueError(
                "파기 검증 결과는 다음 중 하나여야 합니다: "
                + ", ".join(sorted(ACCEPTED_DESTRUCTION_RESULTS))
            )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["method"] = self.method.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, default_performer: str = "") -> "DestructionEvidence":
        try:
            method = DestructionMethod(str(data.get("method") or ""))
        except ValueError as exc:
            raise ValueError(
                "파기 방법은 다음 중 하나여야 합니다: "
                + ", ".join(item.value for item in DestructionMethod)
            ) from exc
        return cls(
            method=method,
            performed_by=str(data.get("performed_by") or default_performer),
            verified_by=str(data.get("verified_by") or ""),
            verification_check=str(data.get("verification_check") or ""),
            verification_result=str(data.get("verification_result") or ""),
            verified_at=str(data.get("verified_at") or _utcnow()),
            notes=str(data.get("notes") or "")[:1000],
        )


def evidence_digest(evidence: Dict[str, Any], previous_event_id: Optional[str]) -> str:
    """증적과 직전 생명주기 이력 ID 를 묶은 해시. 타임라인 중간 변조를 탐지하는 데 쓴다."""
    material = json.dumps(
        {"evidence": evidence, "previous_event_id": previous_event_id},
        sort_keys=True,
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


__all__ = [
    "ACCEPTED_DESTRUCTION_RESULTS",
    "DestructionEvidence",
    "DestructionMethod",
    "evidence_digest",
]
