"""SQLite 저장소 테스트."""

from __future__ import annotations

import pytest

from connectors.github_connector import Repository
from core.models import ScanTarget
from scanner.scan_service import SecretScanService
from storage.sqlite_store import SQLiteStorage

SLACK_BOT_TOKEN = "xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d"


@pytest.fixture
def store():
    s = SQLiteStorage(":memory:")
    yield s
    s.close()


def _scan(repo="org/repo", content=f"TOKEN={SLACK_BOT_TOKEN}"):
    return SecretScanService().scan_targets(
        [ScanTarget(path="config/slack.env", content=content)], repository=repo
    )


def test_repository_upsert_and_list(store):
    repo = Repository(full_name="org/repo", default_branch="main", private=True)
    store.upsert_repository(repo)
    store.upsert_repository(repo)  # 중복 등록해도 1건

    repos = store.list_repositories()
    assert len(repos) == 1
    assert repos[0]["full_name"] == "org/repo"
    assert store.get_repository("org/repo")["default_branch"] == "main"


def test_save_and_read_scan_result(store):
    result = _scan()
    scan_id = store.save_scan_result(result)
    assert scan_id > 0

    history = store.list_scan_results("org/repo")
    assert len(history) == 1
    assert history[0]["finding_count"] == len(result.findings)


def test_known_fingerprints_roundtrip(store):
    result = _scan()
    store.save_scan_result(result)

    fingerprints = store.known_fingerprints("org/repo")
    assert result.findings[0].fingerprint in fingerprints


def test_stored_finding_has_no_raw_value(store):
    """DB 저장/복원 후에도 원문은 남지 않아야 한다."""
    store.save_scan_result(_scan())
    findings = store.latest_findings("org/repo")

    assert findings
    for f in findings:
        assert f.raw_value == ""
        assert SLACK_BOT_TOKEN not in f.masked_value
        assert SLACK_BOT_TOKEN not in str(f.to_dict())


def test_latest_findings_returns_most_recent_scan(store):
    store.save_scan_result(_scan(content=f"A={SLACK_BOT_TOKEN}"))
    store.save_scan_result(_scan(content="B=nothing-here"))

    # 두 번째 스캔에는 finding 이 없다
    assert store.latest_findings("org/repo") == []
    # 하지만 누적 fingerprint 에는 첫 스캔 것이 남아 있다
    assert len(store.known_fingerprints("org/repo")) == 1


def test_resolution_tracking(store):
    fp = "sha256:abc123"
    store.mark_resolved("org/repo", fp)
    store.mark_resolved("org/repo", fp)  # 중복 허용

    resolved = store.resolved_fingerprints("org/repo")
    assert resolved == {fp}
    assert store.resolved_fingerprints("org/other") == set()


def test_all_findings_dedupes_by_fingerprint(store):
    # 같은 secret 을 두 번 스캔 저장 → all_findings 는 1건
    store.save_scan_result(_scan())
    store.save_scan_result(_scan())

    all_f = store.all_findings("org/repo")
    fingerprints = [f.fingerprint for f in all_f]
    assert len(fingerprints) == len(set(fingerprints)) == 1
