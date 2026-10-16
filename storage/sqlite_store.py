"""SQLite 기반 저장소 구현.

주의: **원문 토큰은 저장하지 않는다.** finding 은 `to_dict()`(마스킹된 형태)로
직렬화되므로, DB 에서 다시 읽어들인 finding 은 `_raw_value` 가 비어 있다.
즉 DB 재조회만으로는 외부 API 재검증이 불가능하며, 재검증하려면 반드시
재스캔(원문을 다시 읽는 경로)을 거쳐야 한다 — 이는 의도된 보안 속성이다.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from connectors.github_connector import Repository
from backend.models.entities import (
    ConnectorRecord,
    FindingRecord,
    FindingStatus,
    ProjectRecord,
)
from backend.services.finding_lifecycle import validate_transition
from backend.services.nhi_lifecycle import validate_transition as validate_nhi_lifecycle_transition
from core.action_models import ActionRequest, ActionStatus
from core.approval_models import ApprovalRequest
from core.destruction_models import DestructionEvidence, evidence_digest
from core.models import (
    CodeContext,
    DetectorType,
    ResolutionStatus,
    ScanResult,
    ScanTrigger,
    SecretFinding,
    Severity,
)
from core.nhi_lifecycle_models import (
    STATUS_TRANSITION_EVENTS,
    NHILifecycleEventType,
    NHILifecycleStatus,
)
from core.observation_models import CredentialObservation
from security.redaction import sanitize_security_text, sanitize_security_value
from storage.base import Storage

_SCHEMA = """
CREATE TABLE IF NOT EXISTS repositories (
    full_name       TEXT PRIMARY KEY,
    default_branch  TEXT,
    private         INTEGER,
    html_url        TEXT,
    registered_at   TEXT,
    data            TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name   TEXT NOT NULL,
    trigger     TEXT,
    ref         TEXT,
    commit_sha  TEXT,
    pull_request INTEGER,
    scanned_files INTEGER,
    started_at  TEXT,
    finished_at TEXT,
    data        TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(full_name);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    full_name   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    secret_type TEXT,
    provider    TEXT,
    severity    TEXT,
    file_path   TEXT,
    line_number INTEGER,
    data        TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(full_name);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);

CREATE TABLE IF NOT EXISTS resolutions (
    full_name   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    resolved_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (full_name, fingerprint)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    source_type     TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    provider       TEXT,
    repository     TEXT,
    path           TEXT,
    observed_at    TEXT,
    data           TEXT NOT NULL,
    UNIQUE(source_event_id, fingerprint, path)
);
CREATE INDEX IF NOT EXISTS idx_observations_fp ON observations(fingerprint);

CREATE TABLE IF NOT EXISTS nhi_identities (
    nhi_id      TEXT PRIMARY KEY,
    provider    TEXT,
    owner       TEXT,
    updated_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_nhi_bindings (
    fingerprint TEXT NOT NULL,
    nhi_id      TEXT NOT NULL,
    confidence  REAL NOT NULL,
    evidence    TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (fingerprint, nhi_id)
);

-- NHI 생명주기(관리적 축 — REGISTERED/ACTIVE/DEACTIVATED/DECOMMISSIONED).
-- Credential 자체의 활성/폐기 여부(`findings.credential_active` 등)는 이
-- 테이블과 무관한 별도 축이라 여기서 다루지 않는다.
CREATE TABLE IF NOT EXISTS nhi_lifecycle_state (
    nhi_id      TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nhi_lifecycle_history (
    history_id  TEXT PRIMARY KEY,
    nhi_id      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    from_status TEXT,
    to_status   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    note        TEXT,
    detail      TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nhi_lifecycle_history_nhi
    ON nhi_lifecycle_history(nhi_id, occurred_at);

-- 변경 승인(Change Control) — Change Preview 결과를 승인·적용·롤백까지 추적한다.
-- 실제 Provider 호출은 전혀 하지 않는다(executor_result.provider_call 이 항상
-- "not_configured") — InventoryStateExecutor 가 내부 상태(NHI Lifecycle)만 바꾼다.
CREATE TABLE IF NOT EXISTS change_requests (
    change_id          TEXT PRIMARY KEY,
    nhi_id              TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL UNIQUE,
    status              TEXT NOT NULL,
    data                TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_requests_nhi ON change_requests(nhi_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_change_requests_status ON change_requests(status);

-- DPoP proof(jti) 재전송 방지 — jkt|method|htu|jti 조합의 SHA-256만 저장한다
-- (원문 jti/jkt/서명은 저장하지 않는다). 여러 워커·프로세스 재시작 사이에서도
-- 같은 DB 파일을 공유하면 단일 사용이 유지된다.
CREATE TABLE IF NOT EXISTS dpop_replay (
    digest      TEXT PRIMARY KEY,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dpop_replay_expires ON dpop_replay(expires_at);

CREATE TABLE IF NOT EXISTS agent_access_profiles (
    agent_id    TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    owner       TEXT,
    updated_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_access_decisions (
    decision_id TEXT PRIMARY KEY,
    event_id    TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    severity    TEXT,
    occurred_at TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_access_decisions_agent
    ON agent_access_decisions(agent_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_access_decisions_outcome
    ON agent_access_decisions(outcome, occurred_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_access_decisions_event
    ON agent_access_decisions(agent_id, event_id);

CREATE TABLE IF NOT EXISTS analysis_runs (
    analysis_id     TEXT PRIMARY KEY,
    repository      TEXT,
    fingerprint     TEXT NOT NULL,
    input_revision  TEXT,
    scoring_version TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    analyzed_at     TEXT NOT NULL,
    data            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_repo ON analysis_runs(repository);
CREATE INDEX IF NOT EXISTS idx_analysis_fp ON analysis_runs(fingerprint);

CREATE TABLE IF NOT EXISTS action_requests (
    action_id       TEXT PRIMARY KEY,
    analysis_id     TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    status          TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    data            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON action_requests(status);

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id         TEXT PRIMARY KEY,
    target_nhi_id       TEXT NOT NULL,
    recommended_action  TEXT NOT NULL,
    status              TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    decided_at          TEXT,
    data                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approvals_target ON approval_requests(target_nhi_id);

CREATE TABLE IF NOT EXISTS encrypted_secret_material (
    secret_id    TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL,
    key_id       TEXT NOT NULL,
    algorithm    TEXT NOT NULL,
    nonce        BLOB NOT NULL,
    ciphertext   BLOB NOT NULL,
    aad          TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    destroyed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_secret_material_fp ON encrypted_secret_material(fingerprint);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL,
    target      TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    detail      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id       TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    repository       TEXT NOT NULL UNIQUE,
    status           TEXT NOT NULL,
    policy_enabled   INTEGER NOT NULL,
    schedule_enabled INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    data             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connectors (
    connector_id    TEXT PRIMARY KEY,
    project_id      TEXT,
    provider        TEXT NOT NULL,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL,
    secret_ref      TEXT,
    last_checked_at TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    data            TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX IF NOT EXISTS idx_connectors_provider ON connectors(provider);

CREATE TABLE IF NOT EXISTS finding_records (
    finding_id       TEXT PRIMARY KEY,
    project_id       TEXT,
    repository       TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    secret_type      TEXT,
    provider         TEXT,
    severity         TEXT,
    risk_score       INTEGER,
    risk_level       TEXT,
    status           TEXT NOT NULL,
    file_path        TEXT,
    line_number      INTEGER,
    first_detected_at TEXT NOT NULL,
    last_detected_at  TEXT NOT NULL,
    resolved_at       TEXT,
    sla_due_at        TEXT,
    data             TEXT NOT NULL,
    UNIQUE(repository, fingerprint, file_path),
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_records_status ON finding_records(status);
CREATE INDEX IF NOT EXISTS idx_finding_records_risk ON finding_records(risk_level);
CREATE INDEX IF NOT EXISTS idx_finding_records_project ON finding_records(project_id);

CREATE TABLE IF NOT EXISTS finding_status_history (
    history_id  TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    from_status TEXT,
    to_status   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    note        TEXT,
    changed_at  TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES finding_records(finding_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_history_id ON finding_status_history(finding_id);
"""


def _finding_to_json(finding: SecretFinding) -> str:
    return json.dumps(finding.to_dict(), ensure_ascii=False)


def _finding_from_row(data_json: str) -> SecretFinding:
    """DB 행 → SecretFinding 복원 (원문은 항상 빈 값)."""
    d = json.loads(data_json)
    ctx = d.get("context") or {}
    return SecretFinding(
        secret_type=d["secret_type"],
        provider=d["provider"],
        masked_value=d["masked_value"],
        fingerprint=d["fingerprint"],
        file_path=d["file_path"],
        line_number=d["line_number"],
        detector=DetectorType(d.get("detector", "regex")),
        severity=Severity(d.get("severity", "medium")),
        entropy=d.get("entropy"),
        match_start=d.get("match_start", 0),
        match_end=d.get("match_end", 0),
        context=CodeContext(
            before=ctx.get("before", []), line=ctx.get("line", ""), after=ctx.get("after", [])
        ),
        credential_active=d.get("credential_active"),
        credential_revoked=d.get("credential_revoked"),
        raw_scopes=d.get("raw_scopes", []),
        credential_detail=d.get("credential_detail"),
        occurrence_count=d.get("occurrence_count", 1),
        duplicate_locations=d.get("duplicate_locations", []),
        status=ResolutionStatus(d.get("status", "new")),
        detected_at=d.get("detected_at", ""),
        secret_ref=d.get("secret_ref"),
    )


class SQLiteStorage(Storage):
    """스레드 안전(직렬화된) SQLite 저장소."""

    def __init__(self, db_path: str = "nhi_scanner.db") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + Lock 으로 FastAPI 다중 스레드에서 공유
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        # busy_timeout: 다른 프로세스(워커)가 쓰기 중이면 즉시 "database is
        # locked" 에러를 내지 않고 잠깐 기다린다 — DPoP replay 키처럼 여러
        # 워커가 동시에 쓸 수 있는 테이블의 정상적인 경합을 에러로 착각하지
        # 않게 한다. WAL은 파일 기반 DB에서만 의미가 있다(:memory: 는 그대로).
        self._conn.execute("PRAGMA busy_timeout = 5000")
        if db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- Repository ------------------------------------------------------
    def upsert_repository(self, repo: Repository) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO repositories (full_name, default_branch, private, html_url, registered_at, data)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(full_name) DO UPDATE SET
                    default_branch=excluded.default_branch,
                    private=excluded.private,
                    html_url=excluded.html_url,
                    registered_at=excluded.registered_at,
                    data=excluded.data
                """,
                (
                    repo.full_name,
                    repo.default_branch,
                    int(repo.private),
                    repo.html_url,
                    repo.registered_at,
                    json.dumps(repo.to_dict(), ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def get_repository(self, full_name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM repositories WHERE full_name=?", (full_name,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_repositories(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM repositories ORDER BY full_name"
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    # -- 스캔 결과 -------------------------------------------------------
    def save_scan_result(self, result: ScanResult) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO scans
                    (full_name, trigger, ref, commit_sha, pull_request, scanned_files,
                     started_at, finished_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.repository,
                    result.trigger.value,
                    result.ref,
                    result.commit_sha,
                    result.pull_request,
                    result.scanned_files,
                    result.started_at,
                    result.finished_at,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                ),
            )
            scan_id = int(cur.lastrowid)

            self._conn.executemany(
                """
                INSERT INTO findings
                    (scan_id, full_name, fingerprint, secret_type, provider, severity,
                     file_path, line_number, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        result.repository,
                        f.fingerprint,
                        f.secret_type,
                        f.provider,
                        f.severity.value,
                        f.file_path,
                        f.line_number,
                        _finding_to_json(f),
                    )
                    for f in result.findings
                ],
            )
            for finding in result.findings:
                self._upsert_finding_record_locked(result.repository, finding)
            self._conn.commit()
        return scan_id

    def _upsert_finding_record_locked(
        self, repository: str, finding: SecretFinding
    ) -> str:
        """스캔 finding 을 장기 lifecycle 레코드로 동기화한다."""
        path = finding.file_path or ""
        existing = self._conn.execute(
            """
            SELECT data FROM finding_records
            WHERE repository=? AND fingerprint=? AND file_path=?
            """,
            (repository, finding.fingerprint, path),
        ).fetchone()
        project = self._conn.execute(
            "SELECT project_id FROM projects WHERE repository=?", (repository,)
        ).fetchone()
        project_id = project["project_id"] if project else None

        if existing:
            record = FindingRecord(**_finding_record_kwargs(json.loads(existing["data"])))
            if finding.status is ResolutionStatus.RECURRED or record.status is FindingStatus.RESOLVED:
                record.status = FindingStatus.RECURRENCE
            record.last_detected_at = finding.detected_at or _utcnow()
            record.project_id = project_id or record.project_id
            record.metadata.update(
                {
                    "scan_status": finding.status.value,
                    "occurrence_count": finding.occurrence_count,
                }
            )
        else:
            status = (
                FindingStatus.RECURRENCE
                if finding.status is ResolutionStatus.RECURRED
                else FindingStatus.NEW
            )
            detected_at = finding.detected_at or _utcnow()
            record = FindingRecord(
                repository=repository,
                fingerprint=finding.fingerprint,
                secret_type=finding.secret_type,
                provider=finding.provider,
                file_path=path,
                line_number=finding.line_number,
                masked_value=finding.masked_value,
                severity=finding.severity.value,
                project_id=project_id,
                status=status,
                first_detected_at=detected_at,
                last_detected_at=detected_at,
                sla_due_at=_sla_due_at(detected_at, finding.severity.value),
                metadata={
                    "scan_status": finding.status.value,
                    "detector": finding.detector.value,
                    "occurrence_count": finding.occurrence_count,
                },
            )

        payload = record.to_dict()
        self._conn.execute(
            """
            INSERT INTO finding_records
                (finding_id, project_id, repository, fingerprint, secret_type,
                 provider, severity, risk_score, risk_level, status, file_path,
                 line_number, first_detected_at, last_detected_at, resolved_at,
                 sla_due_at, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(repository, fingerprint, file_path) DO UPDATE SET
                project_id=excluded.project_id,
                severity=excluded.severity,
                status=excluded.status,
                line_number=excluded.line_number,
                last_detected_at=excluded.last_detected_at,
                resolved_at=excluded.resolved_at,
                sla_due_at=excluded.sla_due_at,
                data=excluded.data
            """,
            (
                record.finding_id,
                record.project_id,
                record.repository,
                record.fingerprint,
                record.secret_type,
                record.provider,
                record.severity,
                record.risk_score,
                record.risk_level,
                record.status.value,
                record.file_path,
                record.line_number,
                record.first_detected_at,
                record.last_detected_at,
                record.resolved_at,
                record.sla_due_at,
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        if not existing:
            self._insert_finding_history_locked(
                record.finding_id,
                None,
                record.status,
                actor="scanner",
                note="최초 탐지",
            )
        return record.finding_id

    def list_scan_results(self, full_name: str, *, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM scans WHERE full_name=? ORDER BY id DESC LIMIT ?",
                (full_name, limit),
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def list_all_scan_results(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, data FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        results: List[Dict[str, Any]] = []
        for row in rows:
            data = json.loads(row["data"])
            data["scan_id"] = row["id"]
            results.append(data)
        return results

    def latest_findings(self, full_name: str) -> List[SecretFinding]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM scans WHERE full_name=? ORDER BY id DESC LIMIT 1",
                (full_name,),
            ).fetchone()
            if row is None:
                return []
            scan_id = row["id"]
            rows = self._conn.execute(
                "SELECT data FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()
        return [_finding_from_row(r["data"]) for r in rows]

    def all_findings(self, full_name: str) -> List[SecretFinding]:
        """Fingerprint 당 가장 최근 finding 1건씩."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT data FROM findings
                WHERE id IN (
                    SELECT MAX(id) FROM findings WHERE full_name=? GROUP BY fingerprint
                )
                """,
                (full_name,),
            ).fetchall()
        return [_finding_from_row(r["data"]) for r in rows]

    def known_fingerprints(self, full_name: str) -> Set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT fingerprint FROM findings WHERE full_name=?", (full_name,)
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    # -- 해결 상태 -------------------------------------------------------
    def mark_resolved(self, full_name: str, fingerprint: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO resolutions (full_name, fingerprint) VALUES (?, ?)
                ON CONFLICT(full_name, fingerprint) DO NOTHING
                """,
                (full_name, fingerprint),
            )
            self._conn.commit()

    def resolved_fingerprints(self, full_name: str) -> Set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT fingerprint FROM resolutions WHERE full_name=?", (full_name,)
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    # -- 표준 수집 Observation ------------------------------------------
    def save_observation(self, observation: CredentialObservation) -> str:
        data = observation.to_dict()
        normalized_path = observation.path or ""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO observations
                    (observation_id, source_type, source_event_id, fingerprint,
                     provider, repository, path, observed_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_event_id, fingerprint, path) DO UPDATE SET
                    provider=excluded.provider,
                    repository=excluded.repository,
                    observed_at=excluded.observed_at,
                    data=excluded.data
                """,
                (
                    observation.observation_id,
                    observation.source_type,
                    observation.source_event_id,
                    observation.fingerprint,
                    observation.provider,
                    observation.repository,
                    normalized_path,
                    observation.observed_at,
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            row = self._conn.execute(
                """
                SELECT observation_id FROM observations
                WHERE source_event_id=? AND fingerprint=? AND path IS ?
                """,
                (
                    observation.source_event_id,
                    observation.fingerprint,
                    normalized_path,
                ),
            ).fetchone()
            self._conn.commit()
        return str(row["observation_id"])

    def list_observations(
        self, *, fingerprint: Optional[str] = None, limit: int = 100
    ) -> List[CredentialObservation]:
        sql = "SELECT data FROM observations"
        args: tuple = ()
        if fingerprint is not None:
            sql += " WHERE fingerprint=?"
            args = (fingerprint,)
        sql += " ORDER BY observed_at DESC LIMIT ?"
        args += (limit,)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [CredentialObservation.from_dict(json.loads(row["data"])) for row in rows]

    # -- NHI / 분석 스냅샷 ----------------------------------------------
    def upsert_nhi(self, nhi_id: str, data: Dict[str, Any]) -> None:
        now = _utcnow()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO nhi_identities (nhi_id, provider, owner, updated_at, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(nhi_id) DO UPDATE SET
                    provider=excluded.provider,
                    owner=excluded.owner,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (
                    nhi_id,
                    data.get("provider"),
                    data.get("owner"),
                    now,
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def bind_credential_to_nhi(
        self,
        fingerprint: str,
        nhi_id: str,
        *,
        confidence: float,
        evidence: List[str],
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO credential_nhi_bindings
                    (fingerprint, nhi_id, confidence, evidence, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint, nhi_id) DO UPDATE SET
                    confidence=excluded.confidence,
                    evidence=excluded.evidence,
                    updated_at=excluded.updated_at
                """,
                (
                    fingerprint,
                    nhi_id,
                    confidence,
                    json.dumps(evidence, ensure_ascii=False),
                    _utcnow(),
                ),
            )
            self._conn.commit()

    # -- NHI 생명주기 (NHI 상태 — Credential 활성/폐기 상태와는 별개 축) ----
    def get_nhi_lifecycle_state(self, nhi_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT nhi_id, status, updated_at FROM nhi_lifecycle_state WHERE nhi_id=?",
                (nhi_id,),
            ).fetchone()
        return dict(row) if row else None

    def initialize_nhi_lifecycle(
        self,
        nhi_id: str,
        *,
        actor: str,
        note: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            existing = self._conn.execute(
                "SELECT nhi_id, status, updated_at FROM nhi_lifecycle_state WHERE nhi_id=?",
                (nhi_id,),
            ).fetchone()
            if existing is not None:
                return dict(existing)

            now = _utcnow()
            self._conn.execute(
                "INSERT INTO nhi_lifecycle_state (nhi_id, status, updated_at) VALUES (?, ?, ?)",
                (nhi_id, NHILifecycleStatus.REGISTERED.value, now),
            )
            self._insert_nhi_lifecycle_history_locked(
                nhi_id,
                NHILifecycleEventType.CREATED,
                from_status=None,
                to_status=NHILifecycleStatus.REGISTERED,
                actor=actor,
                note=note,
                detail=detail,
            )
            self._conn.commit()
        return {"nhi_id": nhi_id, "status": NHILifecycleStatus.REGISTERED.value, "updated_at": now}

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
        if event_type not in STATUS_TRANSITION_EVENTS:
            raise ValueError(
                f"'{event_type.value}' 는 상태 전이를 동반하지 않는 이벤트입니다 — "
                "record_nhi_permission_change() 를 사용하세요."
            )
        # DECOMMISSIONED 로 전이할 때만 증적을 다룬다. 전달되면 먼저 검증하고
        # (수행자≠검증자 등), 실패 시 아래 쓰기 전체를 건너뛴다 — 상태/이력
        # 어느 쪽도 바뀌지 않는다.
        if destruction_evidence is not None and status is not NHILifecycleStatus.DECOMMISSIONED:
            raise ValueError("destruction_evidence 는 DECOMMISSIONED 전이에서만 사용합니다.")
        if destruction_evidence is not None:
            destruction_evidence.validate()

        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM nhi_lifecycle_state WHERE nhi_id=?", (nhi_id,)
            ).fetchone()
            if row is None:
                raise KeyError(nhi_id)
            current = NHILifecycleStatus(row["status"])
            # 잘못된 전이 방지 — 허용되지 않으면 ValueError, 상태/이력 모두 쓰지 않는다
            # (아래 쓰기 전에 검증하므로 실패 시 트랜잭션에 아무 변경도 남지 않는다).
            validate_nhi_lifecycle_transition(current, status)

            final_detail = dict(detail or {})
            preserve_detail_keys = False
            extra_unsanitized_detail: Optional[Dict[str, Any]] = None
            if status is NHILifecycleStatus.DECOMMISSIONED:
                # 두 분기 모두 20자 이상의 구조화된 키(destruction_*,
                # destruction_evidence_provided)를 depth 0에 넣으므로, 증적
                # 유무와 무관하게 키 이름을 보존해야 한다.
                preserve_detail_keys = True
                if destruction_evidence is not None:
                    previous_row = self._conn.execute(
                        "SELECT history_id FROM nhi_lifecycle_history WHERE nhi_id=? "
                        "ORDER BY occurred_at DESC, rowid DESC LIMIT 1",
                        (nhi_id,),
                    ).fetchone()
                    previous_event_id = previous_row["history_id"] if previous_row else None
                    evidence_dict = destruction_evidence.to_dict()
                    # `preserve_top_level_keys`는 depth 0 키만 보존하므로, 증적을
                    # 중첩 dict로 넣으면 그 내부 필드명(예: verification_result,
                    # 20자)이 depth 1에서 다시 마스킹 대상이 된다 — Change Preview
                    # replay snapshot 버그와 같은 원인이라, 애초에 중첩시키지 않고
                    # detail 최상위에 펼쳐 담는다.
                    final_detail["destruction_method"] = evidence_dict["method"]
                    final_detail["destruction_performed_by"] = evidence_dict["performed_by"]
                    final_detail["destruction_verified_by"] = evidence_dict["verified_by"]
                    final_detail["destruction_verification_check"] = evidence_dict[
                        "verification_check"
                    ]
                    final_detail["destruction_verification_result"] = evidence_dict[
                        "verification_result"
                    ]
                    final_detail["destruction_verified_at"] = evidence_dict["verified_at"]
                    final_detail["destruction_notes"] = evidence_dict["notes"]
                    final_detail["destruction_evidence_provided"] = True
                    # sha256 다이제스트는 20자 이상의 불투명 문자열이라 값
                    # 마스킹(redact_unknown_tokens)에 그대로 걸린다 — 우리가
                    # 계산한 해시일 뿐 사용자 입력이 아니므로 sanitize 이후에
                    # 그대로 붙인다(위 docstring 참고).
                    extra_unsanitized_detail = {
                        "evidence_digest": evidence_digest(evidence_dict, previous_event_id)
                    }
                else:
                    final_detail["destruction_evidence_provided"] = False

            now = _utcnow()
            self._conn.execute(
                "UPDATE nhi_lifecycle_state SET status=?, updated_at=? WHERE nhi_id=?",
                (status.value, now, nhi_id),
            )
            self._insert_nhi_lifecycle_history_locked(
                nhi_id,
                event_type,
                from_status=current,
                to_status=status,
                actor=actor,
                note=note,
                detail=final_detail,
                preserve_detail_keys=preserve_detail_keys,
                extra_unsanitized_detail=extra_unsanitized_detail,
            )
            # 상태 갱신과 이력 기록을 같은 커밋으로 묶어 하나의 트랜잭션으로 처리한다.
            self._conn.commit()
        return {"nhi_id": nhi_id, "status": status.value, "updated_at": now}

    def record_nhi_permission_change(
        self,
        nhi_id: str,
        *,
        actor: str,
        note: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """권한 변경 — 상태(`nhi_lifecycle_state.status`)는 건드리지 않고
        Timeline 이벤트만 남긴다. `from_status`/`to_status`가 같은 값으로
        기록되는 것으로 "상태 전이가 아님"을 표시한다.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM nhi_lifecycle_state WHERE nhi_id=?", (nhi_id,)
            ).fetchone()
            if row is None:
                raise KeyError(nhi_id)
            current = NHILifecycleStatus(row["status"])
            self._insert_nhi_lifecycle_history_locked(
                nhi_id,
                NHILifecycleEventType.PERMISSION_CHANGED,
                from_status=current,
                to_status=current,
                actor=actor,
                note=note,
                detail=detail,
            )
            self._conn.commit()
        return {"nhi_id": nhi_id, "status": current.value}

    def _insert_nhi_lifecycle_history_locked(
        self,
        nhi_id: str,
        event_type: NHILifecycleEventType,
        *,
        from_status: Optional[NHILifecycleStatus],
        to_status: NHILifecycleStatus,
        actor: str,
        note: str,
        detail: Optional[Dict[str, Any]],
        preserve_detail_keys: bool = False,
        extra_unsanitized_detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        """호출부가 이미 `self._lock`을 쥔 상태에서만 호출한다(커밋은 호출부 책임).

        `note`/`detail`은 관리자가 자유 텍스트로 입력할 수 있는 필드라 — 다른
        보안 이벤트 직렬화와 동일하게 `sanitize_security_text`/
        `sanitize_security_value`로 Credential-like 값을 제거한 뒤 저장한다.

        `preserve_detail_keys=True`면 `detail`의 최상위 키 이름은 보존한다
        (값은 여전히 마스킹) — `destruction_evidence`처럼 구조화된 긴
        필드명(예: `verification_result`, 20자)이 토큰형 문자열로 오인돼
        마스킹되는 걸 막는다(`security/redaction.py` 의
        `preserve_top_level_keys` 와 같은 설계, Change Preview replay
        snapshot 버그 수정과 동일한 원인·대응).

        `extra_unsanitized_detail`은 정리(sanitize) 이후에 그대로 덧붙인다 —
        `evidence_digest`처럼 우리가 직접 계산한 해시값은 20자 이상의
        불투명한 문자열이라 값 마스킹(`redact_unknown_tokens`)에 걸려
        깨지지만, 사용자 입력이 아니라 우리 데이터로만 계산한 해시라 애초에
        정리할 민감정보가 없다. 자유 텍스트(`note`/`detail`의 다른 필드)는
        여기 넣지 않는다.
        """
        safe_note = sanitize_security_text(note) if note else ""
        safe_detail = sanitize_security_value(
            detail or {}, preserve_top_level_keys=preserve_detail_keys
        )
        if extra_unsanitized_detail:
            safe_detail.update(extra_unsanitized_detail)
        self._conn.execute(
            """
            INSERT INTO nhi_lifecycle_history
                (history_id, nhi_id, event_type, from_status, to_status,
                 actor, note, detail, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                nhi_id,
                event_type.value,
                from_status.value if from_status else None,
                to_status.value,
                actor,
                safe_note,
                json.dumps(safe_detail, ensure_ascii=False),
                _utcnow(),
            ),
        )

    def get_nhi_lifecycle_history(
        self, nhi_id: str, *, limit: int = 100
    ) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT history_id, nhi_id, event_type, from_status, to_status,
                       actor, note, detail, occurred_at
                FROM nhi_lifecycle_history WHERE nhi_id=? ORDER BY occurred_at LIMIT ?
                """,
                (nhi_id, limit),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"]) if item.get("detail") else {}
            results.append(item)
        return results

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
        analysis_id = str(uuid4())
        analyzed_at = str(data.get("analyzed_at") or _utcnow())
        stored = dict(data)
        stored["analysis_id"] = analysis_id
        stored["input_revision"] = input_revision
        stored["scoring_version"] = scoring_version
        stored["policy_version"] = policy_version
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO analysis_runs
                    (analysis_id, repository, fingerprint, input_revision,
                     scoring_version, policy_version, analyzed_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    repository,
                    fingerprint,
                    input_revision,
                    scoring_version,
                    policy_version,
                    analyzed_at,
                    json.dumps(stored, ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return analysis_id

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM analysis_runs WHERE analysis_id=?", (analysis_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_analyses(
        self, *, repository: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        if repository is None:
            sql = "SELECT data FROM analysis_runs ORDER BY analyzed_at DESC LIMIT ?"
            args = (limit,)
        else:
            sql = (
                "SELECT data FROM analysis_runs WHERE repository=? "
                "ORDER BY analyzed_at DESC LIMIT ?"
            )
            args = (repository, limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def list_nhi_analyses(
        self, nhi_id: str, *, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Credential↔NHI binding을 기준으로 분석 이력을 최신순 조회한다.

        `analyzed_at`만으로 정렬하면, 짧은 시간에 분석이 여러 번 저장될 때
        (테스트처럼 아주 빠르게 연속 저장되는 경우 등) 타임스탬프가 같은 값으로
        겹쳐 "최신"이 어느 쪽인지 결정할 수 없는 경우가 생긴다 — `ar.rowid`
        (삽입 순서)를 2차 정렬 키로 둬 항상 실제로 더 나중에 저장된 분석이
        먼저 오게 한다(`ar`에서 온 같은 물리적 행은 join으로 몇 번 중복돼도
        rowid가 같으므로 `SELECT DISTINCT`의 중복 제거는 그대로 유지된다).
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT DISTINCT ar.data, ar.analyzed_at, ar.rowid
                FROM analysis_runs ar
                JOIN credential_nhi_bindings binding
                  ON binding.fingerprint = ar.fingerprint
                WHERE binding.nhi_id=?
                ORDER BY ar.analyzed_at DESC, ar.rowid DESC
                LIMIT ?
                """,
                (nhi_id, limit),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # -- 조치 요청 ------------------------------------------------------
    def create_action(self, action: ActionRequest) -> ActionRequest:
        payload = action.to_dict()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO action_requests
                    (action_id, analysis_id, fingerprint, action_type, status,
                     idempotency_key, created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO NOTHING
                """,
                (
                    action.action_id,
                    action.analysis_id,
                    action.credential_fingerprint,
                    action.action_type,
                    action.status.value,
                    action.idempotency_key,
                    action.created_at,
                    action.updated_at,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            row = self._conn.execute(
                "SELECT data FROM action_requests WHERE idempotency_key=?",
                (action.idempotency_key,),
            ).fetchone()
            self._conn.commit()
        return ActionRequest.from_dict(json.loads(row["data"]))

    def get_action(self, action_id: str) -> Optional[ActionRequest]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM action_requests WHERE action_id=?", (action_id,)
            ).fetchone()
        return ActionRequest.from_dict(json.loads(row["data"])) if row else None

    def list_actions(
        self, *, status: Optional[ActionStatus] = None, limit: int = 100
    ) -> List[ActionRequest]:
        if status is None:
            sql = "SELECT data FROM action_requests ORDER BY created_at DESC LIMIT ?"
            args = (limit,)
        else:
            sql = (
                "SELECT data FROM action_requests WHERE status=? "
                "ORDER BY created_at DESC LIMIT ?"
            )
            args = (status.value, limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [ActionRequest.from_dict(json.loads(row["data"])) for row in rows]

    def update_action(self, action: ActionRequest) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE action_requests
                SET status=?, updated_at=?, data=?
                WHERE action_id=?
                """,
                (
                    action.status.value,
                    action.updated_at,
                    json.dumps(action.to_dict(), ensure_ascii=False),
                    action.action_id,
                ),
            )
            self._conn.commit()

    # -- Human Approval (Dry-run 기반 승인 요청) --------------------------
    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO approval_requests
                    (approval_id, target_nhi_id, recommended_action, status,
                     created_at, decided_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id,
                    approval.target_nhi_id,
                    approval.recommended_action,
                    approval.status.value,
                    approval.created_at,
                    approval.decided_at,
                    json.dumps(approval.to_dict(), ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return approval

    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM approval_requests WHERE approval_id=?", (approval_id,)
            ).fetchone()
        return ApprovalRequest.from_dict(json.loads(row["data"])) if row else None

    def list_approvals(self, *, limit: int = 100) -> List[ApprovalRequest]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM approval_requests ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [ApprovalRequest.from_dict(json.loads(row["data"])) for row in rows]

    def update_approval(self, approval: ApprovalRequest) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE approval_requests
                SET status=?, decided_at=?, data=?
                WHERE approval_id=?
                """,
                (
                    approval.status.value,
                    approval.decided_at,
                    json.dumps(approval.to_dict(), ensure_ascii=False),
                    approval.approval_id,
                ),
            )
            self._conn.commit()

    # -- 암호화 Secret material -----------------------------------------
    def put_encrypted_secret(self, record: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO encrypted_secret_material
                    (secret_id, fingerprint, key_id, algorithm, nonce, ciphertext,
                     aad, created_at, expires_at, destroyed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    record["secret_id"],
                    record["fingerprint"],
                    record["key_id"],
                    record["algorithm"],
                    record["nonce"],
                    record["ciphertext"],
                    record["aad"],
                    record["created_at"],
                    record.get("expires_at"),
                ),
            )
            self._conn.commit()

    def get_encrypted_secret(self, secret_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM encrypted_secret_material
                WHERE secret_id=? AND destroyed_at IS NULL
                """,
                (secret_id,),
            ).fetchone()
        return dict(row) if row else None

    def delete_encrypted_secret(self, secret_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE encrypted_secret_material
                SET ciphertext=x'', nonce=x'', destroyed_at=?
                WHERE secret_id=?
                """,
                (_utcnow(), secret_id),
            )
            self._conn.commit()

    # -- 감사 로그 ------------------------------------------------------
    def append_audit_event(
        self, event_type: str, *, actor: str, target: str, detail: Dict[str, Any]
    ) -> str:
        event_id = str(uuid4())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, event_type, actor, target, occurred_at, detail)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    actor,
                    target,
                    _utcnow(),
                    json.dumps(detail, ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return event_id

    # -- 운영 Backend 엔티티 -------------------------------------------
    def save_project(self, project: ProjectRecord) -> ProjectRecord:
        project.updated_at = _utcnow()
        with self._lock:
            existing = self._conn.execute(
                "SELECT project_id, created_at FROM projects WHERE repository=?",
                (project.repository,),
            ).fetchone()
            if existing:
                project.project_id = existing["project_id"]
                project.created_at = existing["created_at"]
            self._conn.execute(
                """
                INSERT INTO projects
                    (project_id, name, repository, status, policy_enabled,
                     schedule_enabled, created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository) DO UPDATE SET
                    name=excluded.name,
                    status=excluded.status,
                    policy_enabled=excluded.policy_enabled,
                    schedule_enabled=excluded.schedule_enabled,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (
                    project.project_id,
                    project.name,
                    project.repository,
                    project.status,
                    int(project.policy_enabled),
                    int(project.schedule_enabled),
                    project.created_at,
                    project.updated_at,
                    json.dumps(project.to_dict(), ensure_ascii=False),
                ),
            )
            row = self._conn.execute(
                "SELECT data FROM projects WHERE repository=?", (project.repository,)
            ).fetchone()
            saved = ProjectRecord(**json.loads(row["data"]))
            # Project 등록 전에 수집된 finding 을 뒤늦게 연결한다.
            self._conn.execute(
                "UPDATE finding_records SET project_id=? WHERE repository=?",
                (saved.project_id, saved.repository),
            )
            rows = self._conn.execute(
                "SELECT finding_id, data FROM finding_records WHERE repository=?",
                (saved.repository,),
            ).fetchall()
            for finding_row in rows:
                data = json.loads(finding_row["data"])
                data["project_id"] = saved.project_id
                self._conn.execute(
                    "UPDATE finding_records SET data=? WHERE finding_id=?",
                    (json.dumps(data, ensure_ascii=False), finding_row["finding_id"]),
                )
            self._conn.commit()
        return saved

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM projects WHERE project_id=?", (project_id,)
            ).fetchone()
        return self._project_with_coverage(json.loads(row["data"])) if row else None

    def list_projects(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM projects ORDER BY name"
            ).fetchall()
        return [self._project_with_coverage(json.loads(row["data"])) for row in rows]

    def _project_with_coverage(self, project: Dict[str, Any]) -> Dict[str, Any]:
        repository = project["repository"]
        with self._lock:
            scan = self._conn.execute(
                """
                SELECT finished_at, started_at, data FROM scans
                WHERE full_name=? ORDER BY id DESC LIMIT 1
                """,
                (repository,),
            ).fetchone()
            count = self._conn.execute(
                """
                SELECT COUNT(*) AS count FROM finding_records
                WHERE repository=? AND status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
                """,
                (repository,),
            ).fetchone()["count"]
            connectors = self._conn.execute(
                "SELECT status FROM connectors WHERE project_id=?",
                (project["project_id"],),
            ).fetchall()
        result = dict(project)
        result["last_scan_at"] = (
            (scan["finished_at"] or scan["started_at"]) if scan else None
        )
        result["last_scan_status"] = "SUCCEEDED" if scan else "NEVER"
        result["finding_count"] = count
        result["connector_status"] = (
            "CONNECTED"
            if connectors and all(row["status"] == "CONNECTED" for row in connectors)
            else ("CONFIGURED" if connectors else "NOT_CONFIGURED")
        )
        return result

    def save_connector(self, connector: ConnectorRecord) -> ConnectorRecord:
        connector.updated_at = _utcnow()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO connectors
                    (connector_id, project_id, provider, name, status, secret_ref,
                     last_checked_at, created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(connector_id) DO UPDATE SET
                    project_id=excluded.project_id,
                    status=excluded.status,
                    secret_ref=excluded.secret_ref,
                    last_checked_at=excluded.last_checked_at,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (
                    connector.connector_id,
                    connector.project_id,
                    connector.provider,
                    connector.name,
                    connector.status.value,
                    connector.secret_ref,
                    connector.last_checked_at,
                    connector.created_at,
                    connector.updated_at,
                    json.dumps(connector.to_dict(), ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return connector

    def list_connectors(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM connectors ORDER BY provider, name"
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def list_finding_records(
        self,
        *,
        status: Optional[FindingStatus] = None,
        risk_level: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        values: List[Any] = []
        if status is not None:
            clauses.append("status=?")
            values.append(status.value)
        if risk_level:
            clauses.append("risk_level=?")
            values.append(risk_level.upper())
        if project_id:
            clauses.append("project_id=?")
            values.append(project_id)
        sql = "SELECT data FROM finding_records"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += (
            " ORDER BY CASE risk_level WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
            "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, "
            "last_detected_at DESC LIMIT ?"
        )
        values.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, tuple(values)).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def get_finding_record(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM finding_records WHERE finding_id=?", (finding_id,)
            ).fetchone()
            history = self._conn.execute(
                """
                SELECT from_status, to_status, actor, note, changed_at
                FROM finding_status_history WHERE finding_id=? ORDER BY changed_at
                """,
                (finding_id,),
            ).fetchall()
        if not row:
            return None
        result = json.loads(row["data"])
        result["status_history"] = [dict(item) for item in history]
        return result

    def update_finding_status(
        self,
        finding_id: str,
        status: FindingStatus,
        *,
        actor: str,
        note: str = "",
        assigned_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM finding_records WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if row is None:
                raise KeyError(finding_id)
            data = json.loads(row["data"])
            current = FindingStatus(data["status"])
            validate_transition(current, status)
            data["status"] = status.value
            if assigned_to is not None:
                data["assigned_to"] = assigned_to
            if status is FindingStatus.RESOLVED:
                data["resolved_at"] = _utcnow()
            elif current is FindingStatus.RESOLVED:
                data["resolved_at"] = None
            self._conn.execute(
                """
                UPDATE finding_records
                SET status=?, resolved_at=?, data=? WHERE finding_id=?
                """,
                (
                    status.value,
                    data.get("resolved_at"),
                    json.dumps(data, ensure_ascii=False),
                    finding_id,
                ),
            )
            self._insert_finding_history_locked(
                finding_id, current, status, actor=actor, note=note
            )
            self._conn.commit()
        return self.get_finding_record(finding_id) or data

    def _insert_finding_history_locked(
        self,
        finding_id: str,
        from_status: Optional[FindingStatus],
        to_status: FindingStatus,
        *,
        actor: str,
        note: str,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO finding_status_history
                (history_id, finding_id, from_status, to_status, actor, note, changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                finding_id,
                from_status.value if from_status else None,
                to_status.value,
                actor,
                note,
                _utcnow(),
            ),
        )

    def update_finding_analysis(
        self, *, repository: str, fingerprint: str, analysis: Dict[str, Any]
    ) -> None:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT finding_id, data FROM finding_records
                WHERE repository=? AND fingerprint=?
                """,
                (repository, fingerprint),
            ).fetchall()
            for row in rows:
                data = json.loads(row["data"])
                data.update(
                    {
                        "nhi_id": (analysis.get("discovery") or {}).get("nhi_id"),
                        "nhi_name": analysis.get("nhi_name"),
                        "owner": analysis.get("owner"),
                        "risk_score": analysis.get("risk_score"),
                        "risk_level": analysis.get("risk_level"),
                    }
                )
                self._conn.execute(
                    """
                    UPDATE finding_records
                    SET risk_score=?, risk_level=?, data=? WHERE finding_id=?
                    """,
                    (
                        analysis.get("risk_score"),
                        analysis.get("risk_level"),
                        json.dumps(data, ensure_ascii=False),
                        row["finding_id"],
                    ),
                )
            self._conn.commit()

    def list_nhi_records(
        self, *, limit: int = 100, provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT data FROM nhi_identities"
        args: tuple = ()
        if provider is not None:
            sql += " WHERE provider=?"
            args = (provider,)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        args += (limit,)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def get_nhi_record(self, nhi_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM nhi_identities WHERE nhi_id=?", (nhi_id,)
            ).fetchone()
            if row is None:
                return None
            bindings = self._conn.execute(
                """
                SELECT fingerprint, confidence, evidence
                FROM credential_nhi_bindings WHERE nhi_id=?
                """,
                (nhi_id,),
            ).fetchall()
            analyses = self._conn.execute(
                """
                SELECT data FROM analysis_runs
                WHERE fingerprint IN (
                    SELECT fingerprint FROM credential_nhi_bindings WHERE nhi_id=?
                ) ORDER BY analyzed_at DESC LIMIT 10
                """,
                (nhi_id,),
            ).fetchall()
        result = json.loads(row["data"])
        result["credentials"] = [
            {
                "fingerprint": binding["fingerprint"],
                "confidence": binding["confidence"],
                "evidence": json.loads(binding["evidence"]),
            }
            for binding in bindings
        ]
        result["recent_analyses"] = [json.loads(item["data"]) for item in analyses]
        return result

    # -- 변경 승인(Change Control) --------------------------------------
    def create_change_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """`idempotency_key`가 이미 있으면 새로 만들지 않고 기존 레코드를 그대로
        반환한다 — 같은 키로 재요청(예: 네트워크 재시도)해도 중복 생성되지 않는다.
        """
        with self._lock:
            existing = self._conn.execute(
                "SELECT data FROM change_requests WHERE idempotency_key=?",
                (data["idempotency_key"],),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["data"])
            now = data.get("created_at") or _utcnow()
            self._conn.execute(
                """
                INSERT INTO change_requests
                    (change_id, nhi_id, idempotency_key, status, data, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["change_id"], data["nhi_id"], data["idempotency_key"],
                    data["status"], json.dumps(data, ensure_ascii=False), now, now,
                ),
            )
            self._conn.commit()
        return data

    def get_change_request(self, change_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM change_requests WHERE change_id=?", (change_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_change_requests(
        self,
        *,
        nhi_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses = []
        args: List[Any] = []
        if nhi_id:
            clauses.append("nhi_id=?")
            args.append(nhi_id)
        if status:
            clauses.append("status=?")
            args.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT data FROM change_requests {where} "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (*args, limit),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def transition_change_request(
        self,
        change_id: str,
        *,
        expected_status: str,
        new_status: str,
        fields: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """`expected_status`일 때만 원자적으로 `new_status`로 전이하고 `fields`를
        병합한다. 반환값이 `False`면 아무것도 바뀌지 않았다 — 호출부는 "이미
        다른 요청이 처리함" 또는 "더 이상 그 상태가 아님"으로 해석해야 한다.

        `UPDATE ... WHERE change_id=? AND status=?`의 `WHERE`가 전이 가능 여부를
        최종적으로 판단하므로, 동시에 여러 호출이 들어와도 정확히 하나만
        `rowcount == 1`을 받는다 — 중복 적용·중복 롤백 방지의 핵심이다.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM change_requests WHERE change_id=? AND status=?",
                (change_id, expected_status),
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["data"])
            payload.update(fields or {})
            payload["status"] = new_status
            now = _utcnow()
            payload["updated_at"] = now
            cursor = self._conn.execute(
                "UPDATE change_requests SET status=?, data=?, updated_at=? "
                "WHERE change_id=? AND status=?",
                (new_status, json.dumps(payload, ensure_ascii=False), now, change_id, expected_status),
            )
            self._conn.commit()
            return cursor.rowcount == 1

    # -- DPoP proof(jti) 재전송 방지 ------------------------------------
    def consume_replay_key(
        self, digest: str, *, expires_at: float, now: float, max_entries: int
    ) -> str:
        """``digest``를 원자적으로 "처음 봄"으로 기록한다. `NEW`/`DUPLICATE`/`FULL`.

        `DELETE`(만료 정리) → `COUNT(*)`(한도 확인) → `INSERT OR IGNORE ...
        SELECT`(조건부 삽입)를 **하나의 SQLite 트랜잭션**으로 실행한다 —
        `DELETE`가 먼저 쓰기 트랜잭션을 열어 이후 문장까지 같은 트랜잭션에
        묶이므로, 같은 DB 파일을 쓰는 다른 프로세스가 동시에 같은 `digest`로
        들어와도 SQLite의 파일 잠금이 둘을 직렬화한다 — 두 호출 중 정확히
        하나만 `INSERT`에 성공한다(`cursor.rowcount == 1`). `self._lock`은
        같은 프로세스 내 스레드 간 경합만 줄일 뿐, 이 원자성 자체는 SQLite
        트랜잭션이 보장한다(다중 프로세스에서도 유지되는 이유).
        """
        with self._lock:
            self._conn.execute("DELETE FROM dpop_replay WHERE expires_at <= ?", (now,))
            total = self._conn.execute(
                "SELECT COUNT(*) FROM dpop_replay"
            ).fetchone()[0]
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO dpop_replay (digest, expires_at) "
                "SELECT ?, ? WHERE ? < ?",
                (digest, expires_at, total, max_entries),
            )
            self._conn.commit()
            if cursor.rowcount == 1:
                return "NEW"
            exists = self._conn.execute(
                "SELECT 1 FROM dpop_replay WHERE digest=?", (digest,)
            ).fetchone()
            return "DUPLICATE" if exists else "FULL"

    def clear_replay_keys(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM dpop_replay")
            self._conn.commit()

    # -- 회사 AI Agent 접근 기준선 / API 호출 판정 ----------------------
    def upsert_agent_access_profile(
        self, agent_id: str, data: Dict[str, Any]
    ) -> None:
        payload = dict(data)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agent_access_profiles
                    (agent_id, status, owner, updated_at, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    status=excluded.status,
                    owner=excluded.owner,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (
                    agent_id,
                    str(payload.get("status") or "UNKNOWN"),
                    payload.get("owner"),
                    str(payload.get("updated_at") or datetime.now(timezone.utc).isoformat()),
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def get_agent_access_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM agent_access_profiles WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return json.loads(row["data"]) if row is not None else None

    def list_agent_access_profiles(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT data FROM agent_access_profiles
                ORDER BY updated_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def save_agent_access_decision(self, data: Dict[str, Any]) -> str:
        payload = dict(data)
        decision_id = str(payload["decision_id"])
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO agent_access_decisions
                    (decision_id, event_id, agent_id, outcome, severity, occurred_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    str(payload["event_id"]),
                    str(payload["agent_id"]),
                    str(payload["outcome"]),
                    payload.get("overall_severity"),
                    str(payload.get("evaluated_at") or datetime.now(timezone.utc).isoformat()),
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return decision_id

    def list_agent_access_decisions(
        self,
        *,
        agent_id: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        values: List[Any] = []
        if agent_id:
            clauses.append("agent_id=?")
            values.append(agent_id)
        if outcome:
            clauses.append("outcome=?")
            values.append(outcome)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        values.append(limit)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT data FROM agent_access_decisions
                """
                + where
                + " ORDER BY occurred_at DESC LIMIT ?",
                tuple(values),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def dashboard_summary(self) -> Dict[str, Any]:
        with self._lock:
            project_count = self._conn.execute(
                "SELECT COUNT(*) AS count FROM projects"
            ).fetchone()["count"]
            nhi_count = self._conn.execute(
                "SELECT COUNT(*) AS count FROM nhi_identities"
            ).fetchone()["count"]
            credential_count = self._conn.execute(
                "SELECT COUNT(DISTINCT fingerprint) AS count FROM finding_records"
            ).fetchone()["count"]
            agent_profile_count = self._conn.execute(
                "SELECT COUNT(*) AS count FROM agent_access_profiles"
            ).fetchone()["count"]
            denied_agent_access_count = self._conn.execute(
                """
                SELECT COUNT(*) AS count FROM agent_access_decisions
                WHERE outcome='DENY'
                """
            ).fetchone()["count"]
            review_agent_access_count = self._conn.execute(
                """
                SELECT COUNT(*) AS count FROM agent_access_decisions
                WHERE outcome='REVIEW'
                """
            ).fetchone()["count"]
            risk_rows = self._conn.execute(
                """
                SELECT COALESCE(risk_level, 'UNKNOWN') AS level, COUNT(*) AS count
                FROM finding_records GROUP BY COALESCE(risk_level, 'UNKNOWN')
                """
            ).fetchall()
            status_rows = self._conn.execute(
                "SELECT status, COUNT(*) AS count FROM finding_records GROUP BY status"
            ).fetchall()
            ownerless = self._conn.execute(
                """
                SELECT COUNT(*) AS count FROM nhi_identities
                WHERE json_extract(data, '$.owner') IS NULL
                   OR json_extract(data, '$.owner') = ''
                """
            ).fetchone()["count"]
            rotation = self._conn.execute(
                """
                SELECT COUNT(DISTINCT fingerprint) AS count FROM analysis_runs
                WHERE data LIKE '%ROTATION_PERIOD%'
                """
            ).fetchone()["count"]
            trends = self._conn.execute(
                """
                SELECT substr(first_detected_at, 1, 10) AS day, COUNT(*) AS count
                FROM finding_records
                GROUP BY substr(first_detected_at, 1, 10)
                ORDER BY day DESC LIMIT 14
                """
            ).fetchall()
            mean_resolution = self._conn.execute(
                """
                SELECT AVG((julianday(resolved_at) - julianday(first_detected_at)) * 24)
                    AS hours
                FROM finding_records WHERE resolved_at IS NOT NULL
                """
            ).fetchone()["hours"]
            mean_detection = self._conn.execute(
                """
                SELECT AVG(
                    (julianday(f.first_detected_at) - julianday((
                        SELECT MIN(s.started_at) FROM scans s
                        WHERE s.full_name=f.repository
                          AND s.started_at <= f.first_detected_at
                    ))) * 24
                ) AS hours
                FROM finding_records f
                """
            ).fetchone()["hours"]

        risk_distribution = {row["level"]: row["count"] for row in risk_rows}
        statuses = {row["status"]: row["count"] for row in status_rows}
        return {
            "project_count": project_count,
            "nhi_count": nhi_count,
            "credential_count": credential_count,
            "agent_access_profile_count": agent_profile_count,
            "denied_agent_access_count": denied_agent_access_count,
            "review_agent_access_count": review_agent_access_count,
            "critical_high_findings": (
                risk_distribution.get("CRITICAL", 0) + risk_distribution.get("HIGH", 0)
            ),
            "ownerless_nhi_count": ownerless,
            "long_unrotated_token_count": rotation,
            "finding_status": statuses,
            "new_findings": statuses.get("NEW", 0),
            "resolved_findings": statuses.get("RESOLVED", 0),
            "recurrence_findings": statuses.get("RECURRENCE", 0),
            "mean_detection_hours": (
                round(max(0.0, float(mean_detection)), 2)
                if mean_detection is not None
                else None
            ),
            "mean_resolution_hours": (
                round(float(mean_resolution), 1) if mean_resolution is not None else None
            ),
            "risk_distribution": risk_distribution,
            "recent_finding_trend": [
                {"date": row["day"], "count": row["count"]}
                for row in reversed(trends)
            ],
        }

    def list_audit_events(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT event_id, event_type, actor, target, occurred_at, detail
                FROM audit_events ORDER BY occurred_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in (
                    "event_id", "event_type", "actor", "target", "occurred_at"
                )},
                "detail": json.loads(row["detail"]),
            }
            for row in rows
        ]

    def clear_demo_workspace(self, workspace_id: str) -> Dict[str, int]:
        """명시적으로 표시된 데모 workspace만 연결 순서에 맞춰 삭제한다."""
        with self._lock:
            project_rows = self._conn.execute(
                """
                SELECT project_id, repository FROM projects
                WHERE json_extract(data, '$.metadata.demo_workspace')=?
                """,
                (workspace_id,),
            ).fetchall()
            project_ids = [row["project_id"] for row in project_rows]
            repositories = [row["repository"] for row in project_rows]
            if not repositories:
                return {
                    "projects": 0,
                    "findings": 0,
                    "nhi": 0,
                    "analyses": 0,
                    "actions": 0,
                    "audit_events": 0,
                }

            repo_marks = ",".join("?" for _ in repositories)
            project_marks = ",".join("?" for _ in project_ids)
            fingerprint_rows = self._conn.execute(
                f"""
                SELECT DISTINCT fingerprint FROM finding_records
                WHERE repository IN ({repo_marks})
                """,
                tuple(repositories),
            ).fetchall()
            fingerprints = [row["fingerprint"] for row in fingerprint_rows]
            analysis_rows = self._conn.execute(
                f"""
                SELECT analysis_id FROM analysis_runs
                WHERE repository IN ({repo_marks})
                   OR json_extract(data, '$.demo_workspace')=?
                """,
                (*repositories, workspace_id),
            ).fetchall()
            analysis_ids = [row["analysis_id"] for row in analysis_rows]
            action_rows = self._conn.execute(
                """
                SELECT action_id FROM action_requests
                WHERE json_extract(data, '$.demo_workspace')=1
                """
            ).fetchall()
            action_ids = [row["action_id"] for row in action_rows]
            finding_rows = self._conn.execute(
                f"""
                SELECT finding_id FROM finding_records
                WHERE repository IN ({repo_marks})
                """,
                tuple(repositories),
            ).fetchall()
            finding_ids = [row["finding_id"] for row in finding_rows]
            nhi_rows = self._conn.execute(
                """
                SELECT nhi_id FROM nhi_identities
                WHERE json_extract(data, '$.demo_workspace')=?
                """,
                (workspace_id,),
            ).fetchall()
            nhi_ids = [row["nhi_id"] for row in nhi_rows]

            def delete_in(table: str, column: str, values: List[str]) -> int:
                if not values:
                    return 0
                marks = ",".join("?" for _ in values)
                cursor = self._conn.execute(
                    f"DELETE FROM {table} WHERE {column} IN ({marks})",
                    tuple(values),
                )
                return max(cursor.rowcount, 0)

            counts = {
                "projects": len(project_ids),
                "findings": len(finding_ids),
                "nhi": len(nhi_ids),
                "analyses": len(analysis_ids),
                "actions": 0,
                "audit_events": 0,
            }
            counts["actions"] = delete_in("action_requests", "action_id", action_ids)
            delete_in("finding_status_history", "finding_id", finding_ids)
            delete_in("credential_nhi_bindings", "nhi_id", nhi_ids)
            delete_in("nhi_lifecycle_history", "nhi_id", nhi_ids)
            delete_in("nhi_lifecycle_state", "nhi_id", nhi_ids)
            if fingerprints:
                delete_in("credential_nhi_bindings", "fingerprint", fingerprints)
                delete_in("encrypted_secret_material", "fingerprint", fingerprints)
                delete_in("resolutions", "fingerprint", fingerprints)
            delete_in("analysis_runs", "analysis_id", analysis_ids)
            delete_in("finding_records", "finding_id", finding_ids)
            self._conn.execute(
                f"DELETE FROM findings WHERE full_name IN ({repo_marks})",
                tuple(repositories),
            )
            self._conn.execute(
                f"DELETE FROM scans WHERE full_name IN ({repo_marks})",
                tuple(repositories),
            )
            self._conn.execute(
                f"DELETE FROM observations WHERE repository IN ({repo_marks})",
                tuple(repositories),
            )
            delete_in("nhi_identities", "nhi_id", nhi_ids)
            self._conn.execute(
                f"DELETE FROM connectors WHERE project_id IN ({project_marks})",
                tuple(project_ids),
            )
            counts["audit_events"] = max(
                self._conn.execute(
                    """
                    DELETE FROM audit_events
                    WHERE json_extract(detail, '$.demo_workspace')=?
                    """,
                    (workspace_id,),
                ).rowcount,
                0,
            )
            audit_targets = [
                workspace_id,
                *project_ids,
                *repositories,
                *finding_ids,
                *nhi_ids,
                *action_ids,
            ]
            counts["audit_events"] += delete_in(
                "audit_events", "target", audit_targets
            )
            delete_in("projects", "project_id", project_ids)
            self._conn.commit()
        return counts

    # -- 수명주기 --------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            self._conn.close()


_default_storage: Optional[SQLiteStorage] = None


def get_default_storage() -> SQLiteStorage:
    """프로세스 전역 기본 저장소 (환경변수 NHI_DB_PATH 로 경로 지정)."""
    global _default_storage
    if _default_storage is None:
        import os

        _default_storage = SQLiteStorage(os.getenv("NHI_DB_PATH", "nhi_scanner.db"))
    return _default_storage


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_record_kwargs(data: Dict[str, Any]) -> Dict[str, Any]:
    values = dict(data)
    values["status"] = FindingStatus(values.get("status", FindingStatus.NEW.value))
    return values


def _sla_due_at(detected_at: str, severity: str) -> str:
    try:
        detected = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        detected = datetime.now(timezone.utc)
    if detected.tzinfo is None:
        detected = detected.replace(tzinfo=timezone.utc)
    days = {"critical": 1, "high": 3, "medium": 7, "low": 30}.get(
        severity.lower(), 14
    )
    return (detected + timedelta(days=days)).isoformat()
