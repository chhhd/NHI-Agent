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
from typing import Any, Dict, List, Optional, Sequence, Set
from uuid import uuid4

from connectors.github_connector import Repository
from backend.models.entities import (
    ConnectorRecord,
    FindingRecord,
    FindingStatus,
    ProjectRecord,
)
from backend.services.finding_lifecycle import validate_transition
from core.action_models import ActionRequest, ActionStatus
from core.governance_models import (
    ChangeRequest,
    ChangeStatus,
    ControlEvent,
    LifecycleEvent,
)
from core.models import (
    CodeContext,
    DetectorType,
    ResolutionStatus,
    ScanResult,
    ScanTrigger,
    SecretFinding,
    Severity,
)
from core.observation_models import CredentialObservation
from core.nhi_models import parse_dt
from core.usage_models import UsageEvent
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

CREATE TABLE IF NOT EXISTS usage_events (
    event_id      TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    principal_id  TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_principal ON usage_events(principal_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_usage_expiry ON usage_events(expires_at);

CREATE TABLE IF NOT EXISTS collection_checkpoints (
    provider      TEXT NOT NULL,
    source        TEXT NOT NULL,
    scope         TEXT NOT NULL,
    cursor        TEXT,
    collected_at  TEXT NOT NULL,
    detail        TEXT NOT NULL,
    PRIMARY KEY (provider, source, scope)
);

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

CREATE TABLE IF NOT EXISTS lifecycle_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    nhi_id      TEXT NOT NULL,
    stage       TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_nhi ON lifecycle_events(nhi_id, occurred_at);

CREATE TABLE IF NOT EXISTS change_requests (
    change_id   TEXT PRIMARY KEY,
    nhi_id      TEXT NOT NULL,
    change_type TEXT NOT NULL,
    status      TEXT NOT NULL,
    tier        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_nhi ON change_requests(nhi_id, created_at);
CREATE INDEX IF NOT EXISTS idx_changes_status ON change_requests(status);

CREATE TABLE IF NOT EXISTS control_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    nhi_id      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_nhi ON control_events(nhi_id, occurred_at);

CREATE TABLE IF NOT EXISTS dpop_replay (
    digest      TEXT PRIMARY KEY,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dpop_replay_expiry ON dpop_replay(expires_at);

CREATE TABLE IF NOT EXISTS control_approvals (
    decision_id TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_approvals_status ON control_approvals(status, requested_at);

CREATE TABLE IF NOT EXISTS agent_access_profiles (
    agent_id    TEXT PRIMARY KEY,
    updated_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);

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
        with self._lock:
            self._conn.executescript(_SCHEMA)
            # 기존 5단계 인벤토리를 4단계 표준으로 옮긴다. 이력 원문은 보존한다.
            from core.governance_models import LifecycleStage
            for row in self._conn.execute("SELECT nhi_id, data FROM nhi_identities").fetchall():
                record = json.loads(row["data"])
                old = record.get("lifecycle_stage")
                if old:
                    stage = LifecycleStage(old).value
                    if stage != old:
                        record["lifecycle_stage"] = stage
                        self._conn.execute(
                            "UPDATE nhi_identities SET data=? WHERE nhi_id=?",
                            (json.dumps(record, ensure_ascii=False), row["nhi_id"]),
                        )
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

    # -- 개인정보 최소화된 사용 이벤트 / 수집 checkpoint --------------
    def save_usage_events(
        self, events: Sequence[UsageEvent], *, retention_days: int
    ) -> Dict[str, int]:
        retention_days = min(max(int(retention_days), 1), 365)
        reference = datetime.now(timezone.utc)
        counts = {
            "inserted": 0,
            "duplicates": 0,
            "expired_skipped": 0,
            "invalid_skipped": 0,
            "purged": 0,
        }
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM usage_events WHERE expires_at <= ?", (reference.isoformat(),)
            )
            counts["purged"] = max(int(cur.rowcount or 0), 0)
            for event in events:
                occurred = parse_dt(event.occurred_at)
                if occurred is None:
                    counts["invalid_skipped"] += 1
                    continue
                expires_at = occurred + timedelta(days=retention_days)
                if expires_at <= reference:
                    counts["expired_skipped"] += 1
                    continue
                cur = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO usage_events
                        (event_id, provider, principal_id, occurred_at, expires_at, data)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.provider,
                        event.principal_id,
                        event.occurred_at,
                        expires_at.isoformat(),
                        json.dumps(event.to_dict(), ensure_ascii=False),
                    ),
                )
                if int(cur.rowcount or 0) == 1:
                    counts["inserted"] += 1
                else:
                    counts["duplicates"] += 1
            self._conn.commit()
        return counts

    def list_usage_events(
        self,
        *,
        principal_id: Optional[str] = None,
        provider: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 1000,
    ) -> List[UsageEvent]:
        clauses = ["expires_at > ?"]
        args: List[Any] = [datetime.now(timezone.utc).isoformat()]
        if principal_id is not None:
            clauses.append("principal_id = ?")
            args.append(principal_id)
        if provider is not None:
            clauses.append("provider = ?")
            args.append(provider)
        if since is not None:
            clauses.append("occurred_at >= ?")
            args.append(since)
        args.append(min(max(int(limit), 1), 10001))
        sql = (
            "SELECT data FROM usage_events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY occurred_at ASC LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, tuple(args)).fetchall()
        return [UsageEvent.from_dict(json.loads(row["data"])) for row in rows]

    def purge_expired_usage_events(self, *, now: Optional[str] = None) -> int:
        reference = parse_dt(now) or datetime.now(timezone.utc)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM usage_events WHERE expires_at <= ?", (reference.isoformat(),)
            )
            self._conn.commit()
        return max(int(cur.rowcount or 0), 0)

    def save_collection_checkpoint(
        self,
        *,
        provider: str,
        source: str,
        scope: str,
        cursor: Optional[str],
        detail: Dict[str, Any],
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO collection_checkpoints
                    (provider, source, scope, cursor, collected_at, detail)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, source, scope) DO UPDATE SET
                    cursor=excluded.cursor,
                    collected_at=excluded.collected_at,
                    detail=excluded.detail
                """,
                (
                    provider,
                    source,
                    scope,
                    cursor,
                    _utcnow(),
                    json.dumps(detail, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def get_collection_checkpoint(
        self, *, provider: str, source: str, scope: str
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT cursor, collected_at, detail FROM collection_checkpoints
                WHERE provider=? AND source=? AND scope=?
                """,
                (provider, source, scope),
            ).fetchone()
        if row is None:
            return None
        return {
            "provider": provider,
            "source": source,
            "scope": scope,
            "cursor": row["cursor"],
            "collected_at": row["collected_at"],
            "detail": json.loads(row["detail"]),
        }

    # -- NHI / 분석 스냅샷 ----------------------------------------------
    def upsert_nhi(self, nhi_id: str, data: Dict[str, Any]) -> None:
        from core.governance_models import LifecycleStage
        data = dict(data)
        if data.get("lifecycle_stage"):
            data["lifecycle_stage"] = LifecycleStage(data["lifecycle_stage"]).value
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
            sql = (
                "SELECT data FROM analysis_runs "
                "ORDER BY analyzed_at DESC, rowid DESC LIMIT ?"
            )
            args = (limit,)
        else:
            sql = (
                "SELECT data FROM analysis_runs WHERE repository=? "
                "ORDER BY analyzed_at DESC, rowid DESC LIMIT ?"
            )
            args = (repository, limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def list_nhi_analyses(
        self, nhi_id: str, *, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Credential↔NHI binding 을 기준으로 분석 이력을 최신순 조회한다."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT ar.data
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

    def list_encrypted_secret_ids(self, fingerprint: str) -> List[str]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT secret_id FROM encrypted_secret_material
                WHERE fingerprint=? AND destroyed_at IS NULL
                """,
                (fingerprint,),
            ).fetchall()
        return [row["secret_id"] for row in rows]

    # -- 거버넌스: 생명주기 / 변경 승인 / 실시간 통제 -------------------
    def append_lifecycle_event(self, event: LifecycleEvent) -> LifecycleEvent:
        from core.governance_models import LifecycleStage
        event.stage = LifecycleStage(event.stage).value
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO lifecycle_events
                    (event_id, nhi_id, stage, event_type, occurred_at, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.nhi_id,
                    event.stage,
                    event.event_type,
                    event.occurred_at,
                    json.dumps(event.to_dict(), ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return event

    def list_lifecycle_events(
        self, *, nhi_id: Optional[str] = None, limit: int = 200
    ) -> List[Dict[str, Any]]:
        sql = "SELECT data FROM lifecycle_events"
        args: tuple = ()
        if nhi_id:
            sql += " WHERE nhi_id=?"
            args = (nhi_id,)
        sql += " ORDER BY occurred_at DESC, seq DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (*args, limit)).fetchall()
        from core.governance_models import LifecycleStage
        events = [json.loads(row["data"]) for row in rows]
        for event in events:
            original = event["stage"]
            event["stage"] = LifecycleStage(original).value
            if event["stage"] != original:
                event["legacy_stage"] = original
        return events

    def save_change_request(self, change: ChangeRequest) -> ChangeRequest:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO change_requests
                    (change_id, nhi_id, change_type, status, tier,
                     created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(change_id) DO UPDATE SET
                    status=excluded.status,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (
                    change.change_id,
                    change.nhi_id,
                    change.change_type.value,
                    change.status.value,
                    change.tier.value,
                    change.created_at,
                    change.updated_at,
                    json.dumps(change.to_dict(), ensure_ascii=False),
                ),
            )
            self._conn.commit()
        return change

    def get_change_request(self, change_id: str) -> Optional[ChangeRequest]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM change_requests WHERE change_id=?", (change_id,)
            ).fetchone()
        return ChangeRequest.from_dict(json.loads(row["data"])) if row else None

    def list_change_requests(
        self,
        *,
        status: Optional[ChangeStatus] = None,
        nhi_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ChangeRequest]:
        clauses, args = [], []
        if status is not None:
            clauses.append("status=?")
            args.append(status.value)
        if nhi_id:
            clauses.append("nhi_id=?")
            args.append(nhi_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT data FROM change_requests{where} "
                "ORDER BY created_at DESC LIMIT ?",
                (*args, limit),
            ).fetchall()
        return [ChangeRequest.from_dict(json.loads(row["data"])) for row in rows]

    def append_control_event(self, event: ControlEvent) -> ControlEvent:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO control_events
                    (event_id, nhi_id, event_type, verdict, severity, occurred_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.nhi_id,
                    event.event_type,
                    event.verdict,
                    event.severity,
                    event.occurred_at,
                    json.dumps(event.to_dict(), ensure_ascii=False),
                ),
            )
            event.seq = int(cursor.lastrowid)
            self._conn.execute(
                "UPDATE control_events SET data=? WHERE seq=?",
                (json.dumps(event.to_dict(), ensure_ascii=False), event.seq),
            )
            self._conn.commit()
        return event

    def list_control_events(
        self,
        *,
        after_seq: Optional[int] = None,
        nhi_id: Optional[str] = None,
        since: Optional[str] = None,
        verdict: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses, args = [], []
        if after_seq is not None:
            clauses.append("seq>?")
            args.append(after_seq)
        if nhi_id:
            clauses.append("nhi_id=?")
            args.append(nhi_id)
        if since:
            clauses.append("occurred_at>=?")
            args.append(since)
        if verdict:
            clauses.append("verdict=?")
            args.append(verdict)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if after_seq is not None else "DESC"
        with self._lock:
            rows = self._conn.execute(
                f"SELECT data FROM control_events{where} ORDER BY seq {order} LIMIT ?",
                (*args, limit),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # -- DPoP replay 방지 -----------------------------------------------
    def consume_replay_key(
        self, digest: str, *, expires_at: float, now: float, max_entries: int
    ) -> str:
        with self._lock:
            self._conn.execute("DELETE FROM dpop_replay WHERE expires_at <= ?", (now,))
            total = self._conn.execute("SELECT COUNT(*) FROM dpop_replay").fetchone()[0]
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

    # -- 실시간 통제 승인 대기 -------------------------------------------
    def save_control_approval(self, approval: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO control_approvals (decision_id, status, requested_at, data)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(decision_id) DO NOTHING
                """,
                (
                    approval["decision_id"],
                    approval["status"],
                    approval["requested_at"],
                    json.dumps(approval, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def get_control_approval(self, decision_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM control_approvals WHERE decision_id=?", (decision_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_control_approvals(
        self, *, status: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        where, args = ("WHERE status=?", (status,)) if status else ("", ())
        with self._lock:
            rows = self._conn.execute(
                f"SELECT data FROM control_approvals {where} "
                "ORDER BY requested_at DESC LIMIT ?",
                (*args, limit),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def compare_and_set_control_approval(
        self, decision_id: str, *, expected_status: str, approval: Dict[str, Any]
    ) -> bool:
        """상태가 `expected_status` 일 때만 갱신한다. 동시 결정·허가 중복 사용을 막는 원자 연산."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE control_approvals SET status=?, data=? WHERE decision_id=? AND status=?",
                (
                    approval["status"],
                    json.dumps(approval, ensure_ascii=False),
                    decision_id,
                    expected_status,
                ),
            )
            self._conn.commit()
            return cursor.rowcount == 1

    # -- Agent 접근 기준선 ----------------------------------------------
    def save_agent_access_profile(self, profile: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agent_access_profiles (agent_id, updated_at, data)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    updated_at=excluded.updated_at, data=excluded.data
                """,
                (
                    profile["agent_id"],
                    profile["updated_at"],
                    json.dumps(profile, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def get_agent_access_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM agent_access_profiles WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_agent_access_profiles(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM agent_access_profiles ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

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

    def list_nhi_records(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM nhi_identities ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
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
                ) ORDER BY analyzed_at DESC, rowid DESC LIMIT 10
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
                    "change_requests": 0,
                    "lifecycle_events": 0,
                    "control_events": 0,
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
                "change_requests": 0,
                "lifecycle_events": 0,
                "control_events": 0,
            }
            counts["actions"] = delete_in("action_requests", "action_id", action_ids)
            change_ids = [
                row["change_id"]
                for row in self._conn.execute(
                    """
                    SELECT change_id FROM change_requests
                    WHERE json_extract(data, '$.demo_workspace')=1
                    """
                ).fetchall()
            ]
            counts["change_requests"] = delete_in(
                "change_requests", "change_id", change_ids
            )
            counts["lifecycle_events"] = delete_in(
                "lifecycle_events", "nhi_id", nhi_ids
            )
            counts["control_events"] = delete_in("control_events", "nhi_id", nhi_ids)
            delete_in("finding_status_history", "finding_id", finding_ids)
            delete_in("credential_nhi_bindings", "nhi_id", nhi_ids)
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
                *change_ids,
                *nhi_ids,
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
