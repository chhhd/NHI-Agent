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
from core.approval_models import ApprovalRequest
from core.destruction_models import DestructionEvidence
from core.models import ScanResult, SecretFinding
from core.nhi_lifecycle_models import NHILifecycleEventType, NHILifecycleStatus
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

    # -- Human Approval (Dry-run 기반 승인 요청) --------------------------
    @abc.abstractmethod
    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        ...

    @abc.abstractmethod
    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        ...

    @abc.abstractmethod
    def list_approvals(self, *, limit: int = 100) -> List[ApprovalRequest]:
        ...

    @abc.abstractmethod
    def update_approval(self, approval: ApprovalRequest) -> None:
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
    def list_nhi_records(
        self, *, limit: int = 100, provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """저장된 NHI 레코드 목록. `provider` 를 주면 정확히 일치하는 것만 반환한다
        (일치하는 레코드가 없으면 빈 리스트 — 존재하지 않는 provider 도 오류가
        아니라 빈 결과다)."""
        ...

    @abc.abstractmethod
    def get_nhi_record(self, nhi_id: str) -> Optional[Dict[str, Any]]:
        ...

    # -- NHI 생명주기 (NHI 상태 — Credential 활성/폐기 상태와는 별개 축) ----
    @abc.abstractmethod
    def get_nhi_lifecycle_state(self, nhi_id: str) -> Optional[Dict[str, Any]]:
        """현재 생명주기 상태. 이 기능 도입 이전 NHI 등 초기화되지 않았으면 `None`."""
        ...

    @abc.abstractmethod
    def initialize_nhi_lifecycle(
        self,
        nhi_id: str,
        *,
        actor: str,
        note: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """`REGISTERED` 상태로 최초 등록한다 + `CREATED` 이벤트 기록.

        이미 초기화돼 있으면 아무것도 바꾸지 않고 현재 상태를 그대로
        반환한다(멱등) — 재분석마다 반복 호출돼도 안전하다.
        """
        ...

    @abc.abstractmethod
    def update_nhi_lifecycle_status(
        self,
        nhi_id: str,
        status: NHILifecycleStatus,
        *,
        event_type: NHILifecycleEventType,
        actor: str,
        note: str = "",
        detail: Optional[Dict[str, Any]] = None,
        destruction_evidence: Optional[DestructionEvidence] = None,
    ) -> Dict[str, Any]:
        """실제 상태 전이 + 이력 기록을 하나의 트랜잭션으로 처리한다.

        허용되지 않은 전이면 `ValueError`, 아직 초기화되지 않은 `nhi_id`면
        `KeyError`를 던진다. `event_type`은 상태 전이를 동반하는 유형만
        허용된다 — `PERMISSION_CHANGED`는 `record_nhi_permission_change()`를
        쓴다.

        `destruction_evidence`는 `DECOMMISSIONED` 전이에서만 의미가 있고
        선택 사항이다(기존 호출부와의 하위 호환을 위해 기본값 없이도 전이는
        그대로 동작한다). 전달되면 `DestructionEvidence.validate()`(수행자
        ≠ 검증자 등)를 통과해야 하며, 통과하지 못하면 `ValueError`로
        아무것도 쓰지 않고 거부한다. 전달되지 않으면 이력에
        `destruction_evidence_provided: False`만 남아, 조회하는 쪽이
        "파기를 주장했지만 증적은 없음"과 "증적까지 확인된 파기"를 구분할
        수 있게 한다.
        """
        ...

    @abc.abstractmethod
    def record_nhi_permission_change(
        self,
        nhi_id: str,
        *,
        actor: str,
        note: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """권한 변경 — 상태는 그대로 두고 Timeline 이벤트만 남긴다."""
        ...

    @abc.abstractmethod
    def get_nhi_lifecycle_history(
        self, nhi_id: str, *, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """시간순(오래된 것부터)으로 생명주기 Timeline 이벤트를 반환한다."""
        ...

    # -- 회사 AI Agent 접근 기준선 / API 호출 판정 ----------------------
    @abc.abstractmethod
    def upsert_agent_access_profile(
        self, agent_id: str, data: Dict[str, Any]
    ) -> None:
        """Agent ↔ NHI ↔ 권한·자원 승인 기준선을 저장한다."""
        ...

    # -- DPoP proof 재전송(replay) 방지 — 다중 워커·프로세스 재시작 간 공유 ----
    @abc.abstractmethod
    def consume_replay_key(
        self, digest: str, *, expires_at: float, now: float, max_entries: int
    ) -> str:
        """``digest``(원문 replay key의 SHA-256) 를 원자적으로 "처음 봄"으로 기록한다.

        반환값은 세 가지뿐이다:

        * ``"NEW"``       — 처음 보는 키라 기록에 성공했다. 호출부는 요청을 통과시킨다.
        * ``"DUPLICATE"`` — 이미 유효기간 내에 기록된 키다. 호출부는 재전송으로 보고 거부한다.
        * ``"FULL"``      — 저장 한도(``max_entries``)에 도달해 새 키를 받지 않았다.
          호출부는 이 경우도 거부해야 한다(fail-closed) — "가득 차서 못 막았다"를
          "통과시켰다"로 착각하면 안 된다.

        같은 ``digest``로 동시에 들어온 두 호출 중 **정확히 하나만** ``"NEW"``를
        받아야 한다 — 구현은(예: SQLite의 ``INSERT OR IGNORE`` + UNIQUE 제약) 이
        원자성을 보장해야 한다. 만료된(``expires_at <= now``) 과거 키는 매 호출마다
        함께 청소해도 되고 별도 배치로 해도 된다 — 다만 삭제 자체가 이 함수의
        원자성을 깨서는 안 된다.
        """
        ...

    @abc.abstractmethod
    def clear_replay_keys(self) -> None:
        """기록된 DPoP replay 키를 전부 지운다 (테스트/운영 리셋용)."""
        ...

    # -- 변경 승인(Change Control) ---------------------------------------
    @abc.abstractmethod
    def create_change_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """`idempotency_key`가 이미 있으면 기존 레코드를 그대로 반환한다(멱등)."""
        ...

    @abc.abstractmethod
    def get_change_request(self, change_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_change_requests(
        self, *, nhi_id: Optional[str] = None, status: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def transition_change_request(
        self,
        change_id: str,
        *,
        expected_status: str,
        new_status: str,
        fields: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """`expected_status`일 때만 원자적으로 전이한다. 성공 여부를 반환한다 —

        동시에 두 호출이 같은 `change_id`를 같은 `expected_status`에서 전이시키려
        하면 정확히 하나만 `True`를 받아야 한다(중복 적용/중복 롤백 방지).
        """
        ...

    @abc.abstractmethod
    def get_agent_access_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def list_agent_access_profiles(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def save_agent_access_decision(self, data: Dict[str, Any]) -> str:
        """위장·권한/자원 초과 판정 결과를 영속화한다."""
        ...

    @abc.abstractmethod
    def list_agent_access_decisions(
        self,
        *,
        agent_id: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
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
