"""탐지 계층 데이터 모델.

Scanner → NHI 분석 Agent 로 넘어가는 표준 스키마를 정의한다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectorType(str, Enum):
    REGEX = "regex"
    ENTROPY = "entropy"


class ScanTrigger(str, Enum):
    MANUAL = "manual"
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    RESCAN = "rescan"


class ResolutionStatus(str, Enum):
    """재스캔 결과 상태."""

    RESOLVED = "resolved"        # 이전에 있었으나 이번 스캔에서 사라짐
    UNRESOLVED = "unresolved"    # 계속 존재
    RECURRED = "recurred"        # 해결 처리 후 동일 Fingerprint 재탐지
    NEW = "new"                  # 이번 스캔에서 처음 발견


@dataclass
class CodeContext:
    """탐지 지점 주변 코드 문맥 (원문 Secret 은 마스킹된 상태)."""

    before: List[str] = field(default_factory=list)
    line: str = ""
    after: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CredentialStatus:
    """외부 API 재검증 결과."""

    provider: str
    active: Optional[bool] = None          # None = 확인 불가
    revoked: Optional[bool] = None
    raw_scopes: List[str] = field(default_factory=list)
    account: Dict[str, Any] = field(default_factory=dict)   # team/user/app 식별 정보
    accessible_resources: List[Dict[str, Any]] = field(default_factory=list)
    #: 접근 가능 자원 조회 자체가 실패한 사유. `accessible_resources` 는 실패해도
    #: 빈 리스트로 남으므로("조회 성공 + 0개"와 동일한 모양), 이 필드가 없으면
    #: 둘을 구분할 방법이 없다. None = 조회를 시도하지 않았거나 성공함(빈 결과
    #: 포함), 문자열 = 조회를 시도했으나 실패한 사유.
    accessible_resources_error: Optional[str] = None
    checked_at: str = field(default_factory=_utcnow)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecretFinding:
    """단일 Secret 탐지 결과."""

    secret_type: str
    provider: str
    masked_value: str
    fingerprint: str
    file_path: str
    line_number: int
    detector: DetectorType = DetectorType.REGEX
    severity: Severity = Severity.MEDIUM
    entropy: Optional[float] = None
    match_start: int = 0
    match_end: int = 0
    context: CodeContext = field(default_factory=CodeContext)
    # 외부 API 재검증 결과 (Slack/GitHub 등)
    credential_active: Optional[bool] = None
    credential_revoked: Optional[bool] = None
    raw_scopes: List[str] = field(default_factory=list)
    credential_detail: Optional[Dict[str, Any]] = None
    # 중복/재발 관리
    occurrence_count: int = 1
    duplicate_locations: List[Dict[str, Any]] = field(default_factory=list)
    status: ResolutionStatus = ResolutionStatus.NEW
    detected_at: str = field(default_factory=_utcnow)
    # 암호문 자체가 아니라 분리된 SecretMaterialStore 의 불투명 참조만 보관한다.
    secret_ref: Optional[str] = None

    # 원문은 메모리 내부 재검증 용도로만 보유하며 직렬화하지 않는다.
    _raw_value: str = field(default="", repr=False)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("_raw_value", None)
        data["detector"] = self.detector.value
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data

    @property
    def raw_value(self) -> str:
        return self._raw_value


@dataclass
class ScanTarget:
    """검사 대상 파일 1건."""

    path: str
    content: str
    ref: Optional[str] = None
    sha: Optional[str] = None


@dataclass
class ScanResult:
    """스캔 1회 결과."""

    repository: str
    trigger: ScanTrigger = ScanTrigger.MANUAL
    ref: Optional[str] = None
    commit_sha: Optional[str] = None
    pull_request: Optional[int] = None
    scanned_files: int = 0
    skipped_files: List[Dict[str, str]] = field(default_factory=list)
    findings: List[SecretFinding] = field(default_factory=list)
    started_at: str = field(default_factory=_utcnow)
    finished_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "trigger": self.trigger.value,
            "ref": self.ref,
            "commit_sha": self.commit_sha,
            "pull_request": self.pull_request,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass
class RescanReport:
    """재스캔 + 외부 API 재검증 결과 요약."""

    repository: str
    resolved: List[SecretFinding] = field(default_factory=list)
    unresolved: List[SecretFinding] = field(default_factory=list)
    recurred: List[SecretFinding] = field(default_factory=list)
    new: List[SecretFinding] = field(default_factory=list)
    generated_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "summary": {
                "resolved": len(self.resolved),
                "unresolved": len(self.unresolved),
                "recurred": len(self.recurred),
                "new": len(self.new),
            },
            "resolved": [f.to_dict() for f in self.resolved],
            "unresolved": [f.to_dict() for f in self.unresolved],
            "recurred": [f.to_dict() for f in self.recurred],
            "new": [f.to_dict() for f in self.new],
            "generated_at": self.generated_at,
        }
