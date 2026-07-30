"""저장소 인터페이스.

`api/app.py` 는 이 추상 타입에만 의존한다. 구현체를 갈아끼우면
SQLite → PostgreSQL 등으로 백엔드를 바꿀 수 있다.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Set

from connectors.github_connector import Repository
from core.models import ScanResult, SecretFinding


class Storage(abc.ABC):
    """Repository / 스캔 결과 / 해결 상태 영속화 인터페이스."""

    # -- Repository ------------------------------------------------------
    @abc.abstractmethod
    def upsert_repository(self, repo: Repository) -> None:
        """Repository 등록/갱신."""

    @abc.abstractmethod
    def get_repository(self, full_name: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_repositories(self) -> List[Dict[str, Any]]:
        ...

    # -- 스캔 결과 -------------------------------------------------------
    @abc.abstractmethod
    def save_scan_result(self, result: ScanResult) -> int:
        """스캔 1회 결과를 저장하고 scan_id 를 반환한다."""

    @abc.abstractmethod
    def list_scan_results(self, full_name: str, *, limit: int = 10) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def latest_findings(self, full_name: str) -> List[SecretFinding]:
        """가장 최근 스캔에서 탐지된 finding 목록 (재스캔 비교 기준)."""

    @abc.abstractmethod
    def all_findings(self, full_name: str) -> List[SecretFinding]:
        """해당 repo 에서 지금까지 탐지된 전체 finding (중복 제거)."""

    @abc.abstractmethod
    def known_fingerprints(self, full_name: str) -> Set[str]:
        """지금까지 관측된 Fingerprint 집합."""

    # -- 해결 상태 -------------------------------------------------------
    @abc.abstractmethod
    def mark_resolved(self, full_name: str, fingerprint: str) -> None:
        ...

    @abc.abstractmethod
    def resolved_fingerprints(self, full_name: str) -> Set[str]:
        ...

    # -- 수명주기 --------------------------------------------------------
    def close(self) -> None:  # 선택적
        ...
