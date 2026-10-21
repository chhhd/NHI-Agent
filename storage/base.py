"""저장소 인터페이스.

`api/app.py` 는 이 추상 타입에만 의존한다. 구현체를 갈아끼우면
SQLite → PostgreSQL 등으로 백엔드를 바꿀 수 있다.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Sequence, Set

from connectors.github_connector import Repository
from backend.models.entities import ConnectorRecord, FindingRecord, FindingStatus, ProjectRecord
from core.action_models import ActionRequest, ActionStatus
from core.governance_models import (
    ChangeRequest,
    ChangeStatus,
    ControlEvent,
    LifecycleEvent,
)
from core.models import ScanResult, SecretFinding
from core.observation_models import CredentialObservation
from core.usage_models import UsageEvent


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

    # -- 개인정보 최소화된 사용 이벤트 / 수집 checkpoint --------------
    @abc.abstractmethod
    def save_usage_events(
        self, events: Sequence[UsageEvent], *, retention_days: int
    ) -> Dict[str, int]:
        """원본 로그가 아닌 최소화된 이벤트만 멱등 저장한다."""
        ...

    @abc.abstractmethod
    def list_usage_events(
        self,
        *,
        principal_id: Optional[str] = None,
        provider: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 1000,
    ) -> List[UsageEvent]:
        ...

    @abc.abstractmethod
    def purge_expired_usage_events(self, *, now: Optional[str] = None) -> int:
        ...

    @abc.abstractmethod
    def save_collection_checkpoint(
        self,
        *,
        provider: str,
        source: str,
        scope: str,
        cursor: Optional[str],
        detail: Dict[str, Any],
    ) -> None:
        ...

    @abc.abstractmethod
    def get_collection_checkpoint(
        self, *, provider: str, source: str, scope: str
    ) -> Optional[Dict[str, Any]]:
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

    @abc.abstractmethod
    def list_nhi_analyses(
        self, nhi_id: str, *, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """NHI에 연결된 분석 스냅샷을 최신순으로 반환한다."""
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

    @abc.abstractmethod
    def list_encrypted_secret_ids(self, fingerprint: str) -> List[str]:
        """파기되지 않은 암호문의 secret_id 목록 (NHI 파기 단계에서 사용)."""

    # -- 거버넌스: 생명주기 / 변경 승인 / 실시간 통제 -------------------
    @abc.abstractmethod
    def append_lifecycle_event(self, event: LifecycleEvent) -> LifecycleEvent:
        ...

    @abc.abstractmethod
    def list_lifecycle_events(
        self, *, nhi_id: Optional[str] = None, limit: int = 200
    ) -> List[Dict[str, Any]]:
        """최신순."""

    @abc.abstractmethod
    def save_change_request(self, change: ChangeRequest) -> ChangeRequest:
        """change_id 기준 upsert."""

    @abc.abstractmethod
    def get_change_request(self, change_id: str) -> Optional[ChangeRequest]:
        ...

    @abc.abstractmethod
    def list_change_requests(
        self,
        *,
        status: Optional[ChangeStatus] = None,
        nhi_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ChangeRequest]:
        """최신순."""

    @abc.abstractmethod
    def append_control_event(self, event: ControlEvent) -> ControlEvent:
        """저장하고 단조 증가하는 `seq` 가 채워진 이벤트를 반환한다."""

    @abc.abstractmethod
    def list_control_events(
        self,
        *,
        after_seq: Optional[int] = None,
        nhi_id: Optional[str] = None,
        since: Optional[str] = None,
        verdict: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """`after_seq` 가 있으면 그 이후를 오래된 순으로(폴링용), 없으면 최신순으로."""

    # -- DPoP replay 방지 -----------------------------------------------
    @abc.abstractmethod
    def consume_replay_key(
        self, digest: str, *, expires_at: float, now: float, max_entries: int
    ) -> str:
        """처음 본 key 면 "NEW", 유효한 중복이면 "DUPLICATE", 저장 한도 초과면 "FULL".

        만료된 항목은 이 호출에서 정리한다. 확인과 저장은 원자적이어야 한다.
        """

    # -- 실시간 통제 승인 대기 -------------------------------------------
    @abc.abstractmethod
    def save_control_approval(self, approval: Dict[str, Any]) -> None:
        """`decision_id` 가 이미 있으면 덮어쓰지 않는다(재전송이 결정을 되돌리지 못하게)."""

    @abc.abstractmethod
    def get_control_approval(self, decision_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_control_approvals(
        self, *, status: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """최신순."""

    @abc.abstractmethod
    def compare_and_set_control_approval(
        self, decision_id: str, *, expected_status: str, approval: Dict[str, Any]
    ) -> bool:
        """현재 상태가 `expected_status` 일 때만 갱신하고 성공 여부를 돌려준다(원자적)."""

    # -- Agent 접근 기준선 ----------------------------------------------
    @abc.abstractmethod
    def save_agent_access_profile(self, profile: Dict[str, Any]) -> None:
        """`agent_id` 기준 upsert. `updated_at` 은 호출자가 채운다."""

    @abc.abstractmethod
    def get_agent_access_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_agent_access_profiles(self, *, limit: int = 100) -> List[Dict[str, Any]]:
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
