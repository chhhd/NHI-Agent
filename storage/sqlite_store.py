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
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from connectors.github_connector import Repository
from core.models import (
    CodeContext,
    DetectorType,
    ResolutionStatus,
    ScanResult,
    ScanTrigger,
    SecretFinding,
    Severity,
)
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
            self._conn.commit()
        return scan_id

    def list_scan_results(self, full_name: str, *, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM scans WHERE full_name=? ORDER BY id DESC LIMIT ?",
                (full_name, limit),
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

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
