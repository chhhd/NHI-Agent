"""저장소 인터페이스.

`api/app.py` 는 이 추상 타입에만 의존한다. 구현체를 갈아끼우면
SQLite → PostgreSQL 등으로 백엔드를 바꿀 수 있다.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Set

from connectors.github_connector import Repository
from backend.models.entities import ConnectorRecord, FindingRecord, FindingStatus, ProjectRecord
from core.action_models import ActionRequest, ActionStatus
from core.models import ScanResult, SecretFinding
from core.observation_models import CredentialObservation


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
    def list_all_scan_results(self, *, limit: int = 100) -> List[Dict[str, Any]]:
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

    # -- 표준 수집 Observation ------------------------------------------
    @abc.abstractmethod
    def save_observation(self, observation: CredentialObservation) -> str:
        """정규화된 수집 사실을 멱등 저장하고 observation_id 를 반환한다."""

    @abc.abstractmethod
    def list_observations(
        self, *, fingerprint: Optional[str] = None, limit: int = 100
    ) -> List[CredentialObservation]:
        ...

    # -- NHI / 분석 스냅샷 ----------------------------------------------
    @abc.abstractmethod
    def upsert_nhi(self, nhi_id: str, data: Dict[str, Any]) -> None:
        ...

    @abc.abstractmethod
    def bind_credential_to_nhi(
        self,
        fingerprint: str,
        nhi_id: str,
        *,
        confidence: float,
        evidence: List[str],
    ) -> None:
        ...

    @abc.abstractmethod
    def save_analysis(
        self,
        data: Dict[str, Any],
        *,
        repository: str,
        fingerprint: str,
        input_revision: str = "",
        scoring_version: str = "1.0",
        policy_version: str = "1.0",
    ) -> str:
        ...

    @abc.abstractmethod
    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_analyses(
        self, *, repository: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        ...

    # -- 조치 요청 ------------------------------------------------------
    @abc.abstractmethod
    def create_action(self, action: ActionRequest) -> ActionRequest:
        ...

    @abc.abstractmethod
    def get_action(self, action_id: str) -> Optional[ActionRequest]:
        ...

    @abc.abstractmethod
    def list_actions(
        self, *, status: Optional[ActionStatus] = None, limit: int = 100
    ) -> List[ActionRequest]:
        ...

    @abc.abstractmethod
    def update_action(self, action: ActionRequest) -> None:
        ...

    # -- 암호화 Secret material -----------------------------------------
    @abc.abstractmethod
    def put_encrypted_secret(self, record: Dict[str, Any]) -> None:
        ...

    @abc.abstractmethod
    def get_encrypted_secret(self, secret_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def delete_encrypted_secret(self, secret_id: str) -> None:
        ...

    # -- 감사 로그 ------------------------------------------------------
    @abc.abstractmethod
    def append_audit_event(
        self, event_type: str, *, actor: str, target: str, detail: Dict[str, Any]
    ) -> str:
        ...

    # -- 운영 Backend 엔티티 -------------------------------------------
    @abc.abstractmethod
    def save_project(self, project: ProjectRecord) -> ProjectRecord:
        ...

    @abc.abstractmethod
    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_projects(self) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def save_connector(self, connector: ConnectorRecord) -> ConnectorRecord:
        ...

    @abc.abstractmethod
    def list_connectors(self) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_finding_records(
        self,
        *,
        status: Optional[FindingStatus] = None,
        risk_level: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def get_finding_record(self, finding_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def update_finding_status(
        self,
        finding_id: str,
        status: FindingStatus,
        *,
        actor: str,
        note: str = "",
        assigned_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    def update_finding_analysis(
        self, *, repository: str, fingerprint: str, analysis: Dict[str, Any]
    ) -> None:
        ...

    @abc.abstractmethod
    def list_nhi_records(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def get_nhi_record(self, nhi_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def dashboard_summary(self) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    def list_audit_events(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def clear_demo_workspace(self, workspace_id: str) -> Dict[str, int]:
        """지정한 합성 데모 workspace와 그 연결 데이터만 삭제한다."""
        ...

    # -- 수명주기 --------------------------------------------------------
    def close(self) -> None:  # 선택적
        ...
