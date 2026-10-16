"""DPoP replay 영속화 — storage.consume_replay_key() + security/replay_store.py.

팀원의 StorageReplayCache 설계(저장소에 digest만 남기고, INSERT OR IGNORE +
UNIQUE 제약으로 원자적 중복 방지)를 그대로 가져와 검증한다:

- 동일 (jkt, method, htu, jti) 조합의 동시 요청 중 정확히 하나만 통과(원자성)
- TTL 만료 정리
- 저장 한도 초과 시 fail-closed("FULL")
- 원문 key(jti 등)는 저장되지 않고 SHA-256 digest만 남음(민감정보 저장 방지)
- 저장소 장애 시 예외를 삼키지 않고 TokenBindingError로 fail-closed
- 멀티 워커(별도 프로세스를 흉내낸 별도 SQLiteStorage 커넥션 + 공유 파일)에서도
  원자성이 유지됨
"""

from __future__ import annotations

import hashlib
import threading

import pytest

from security.dpop import TokenBindingError
from security.replay_store import StorageReplayCache
from storage.sqlite_store import SQLiteStorage


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


# ---------------------------------------------------------------------------
# storage.consume_replay_key() — 기본 동작
# ---------------------------------------------------------------------------
def test_first_call_is_new(store):
    assert store.consume_replay_key("digest-a", expires_at=100.0, now=1.0, max_entries=10) == "NEW"


def test_second_call_with_same_digest_before_expiry_is_duplicate(store):
    store.consume_replay_key("digest-a", expires_at=100.0, now=1.0, max_entries=10)
    assert (
        store.consume_replay_key("digest-a", expires_at=100.0, now=2.0, max_entries=10)
        == "DUPLICATE"
    )


def test_expired_entry_is_cleaned_up_and_digest_can_be_reused(store):
    store.consume_replay_key("digest-a", expires_at=10.0, now=1.0, max_entries=10)
    # now(=11.0) > expires_at(=10.0) → 다음 호출에서 청소되고 다시 NEW 가 된다.
    assert (
        store.consume_replay_key("digest-a", expires_at=50.0, now=11.0, max_entries=10)
        == "NEW"
    )


def test_different_digests_are_independent(store):
    assert store.consume_replay_key("digest-a", expires_at=100.0, now=1.0, max_entries=10) == "NEW"
    assert store.consume_replay_key("digest-b", expires_at=100.0, now=1.0, max_entries=10) == "NEW"


def test_cache_full_returns_full_not_new_or_duplicate(store):
    store.consume_replay_key("digest-a", expires_at=100.0, now=1.0, max_entries=1)
    result = store.consume_replay_key("digest-b", expires_at=100.0, now=1.0, max_entries=1)
    assert result == "FULL"


def test_clear_replay_keys_removes_all_entries(store):
    store.consume_replay_key("digest-a", expires_at=100.0, now=1.0, max_entries=10)
    store.clear_replay_keys()
    assert store.consume_replay_key("digest-a", expires_at=100.0, now=1.0, max_entries=10) == "NEW"


# ---------------------------------------------------------------------------
# 동시 요청 — 원자적 중복 방지 (같은 프로세스 내 스레드 경합)
# ---------------------------------------------------------------------------
def test_concurrent_same_digest_only_one_thread_gets_new(store):
    """같은 digest로 동시에 들어온 20개 스레드 중 정확히 1개만 NEW 다."""
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def _attempt():
        barrier.wait()
        outcome = store.consume_replay_key(
            "same-digest", expires_at=100.0, now=1.0, max_entries=1000
        )
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=_attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("NEW") == 1
    assert results.count("DUPLICATE") == 19


# ---------------------------------------------------------------------------
# 멀티 워커 흉내 — 같은 DB 파일을 공유하는 "별도" SQLiteStorage(별도 커넥션)
# ---------------------------------------------------------------------------
def test_concurrent_same_digest_across_separate_connections_to_same_file(tmp_path):
    """두 개의 독립된 SQLiteStorage(별도 프로세스를 흉내)가 같은 파일을 공유해도
    같은 digest에 대해 정확히 하나만 NEW 를 받는다 — SQLite 파일 잠금이 보장한다."""
    db_path = str(tmp_path / "replay.db")
    store_a = SQLiteStorage(db_path)
    store_b = SQLiteStorage(db_path)
    try:
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def _attempt(worker_store):
            barrier.wait()
            outcome = worker_store.consume_replay_key(
                "shared-digest", expires_at=100.0, now=1.0, max_entries=1000
            )
            with lock:
                results.append(outcome)

        threads = [
            threading.Thread(target=_attempt, args=(store_a,)),
            threading.Thread(target=_attempt, args=(store_b,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sorted(results) == ["DUPLICATE", "NEW"]
    finally:
        store_a.close()
        store_b.close()


# ---------------------------------------------------------------------------
# 민감정보 저장 방지 — 원문 key(jti 등)는 DB에 남지 않는다
# ---------------------------------------------------------------------------
def test_only_sha256_digest_is_persisted_not_the_raw_replay_key(store):
    cache = StorageReplayCache(store)
    raw_key = "jkt-abc123|GET|https://api.example.com/runtime/protected|jti-secret-456"

    assert cache.consume(raw_key, expires_at=100.0, now=1.0) is True

    with store._lock:
        rows = store._conn.execute("SELECT digest FROM dpop_replay").fetchall()
    stored_digests = {row["digest"] for row in rows}

    assert raw_key not in stored_digests
    assert "jti-secret-456" not in str(stored_digests)
    assert hashlib.sha256(raw_key.encode("utf-8")).hexdigest() in stored_digests


# ---------------------------------------------------------------------------
# StorageReplayCache — InMemoryReplayCache 와 동일한 인터페이스 + fail-closed
# ---------------------------------------------------------------------------
def test_storage_replay_cache_matches_in_memory_cache_interface(store):
    cache = StorageReplayCache(store)
    assert cache.consume("key-1", expires_at=100.0, now=1.0) is True
    assert cache.consume("key-1", expires_at=100.0, now=2.0) is False


def test_storage_replay_cache_full_raises_token_binding_error_503(store):
    cache = StorageReplayCache(store, max_entries=1)
    cache.consume("key-1", expires_at=100.0, now=1.0)

    with pytest.raises(TokenBindingError) as exc_info:
        cache.consume("key-2", expires_at=100.0, now=1.0)

    assert exc_info.value.code == "dpop_replay_cache_full"
    assert exc_info.value.status_code == 503


def test_storage_replay_cache_wraps_unexpected_storage_exception_as_fail_closed(store, monkeypatch):
    """저장소가 예상치 못한 예외를 던지면 통과시키지 않고 fail-closed 한다."""
    cache = StorageReplayCache(store)

    def _boom(*args, **kwargs):
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr(store, "consume_replay_key", _boom)

    with pytest.raises(TokenBindingError) as exc_info:
        cache.consume("key-1", expires_at=100.0, now=1.0)

    assert exc_info.value.code == "dpop_replay_store_unavailable"
    assert exc_info.value.status_code == 503


def test_storage_replay_cache_clear_resets_state(store):
    cache = StorageReplayCache(store)
    cache.consume("key-1", expires_at=100.0, now=1.0)
    cache.clear()

    assert cache.consume("key-1", expires_at=100.0, now=1.0) is True
