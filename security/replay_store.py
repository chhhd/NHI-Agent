"""저장소 기반 DPoP proof ``jti`` 단일 사용 캐시 — 다중 워커/재시작 간 영속.

``security.dpop.InMemoryReplayCache``는 프로세스가 재시작되거나 워커가
둘 이상이면 이미 쓴 proof의 재전송을 막지 못한다(프로세스별로 메모리가
분리돼 있으므로). 이 구현은 같은 DB 파일을 공유하는 모든 워커·재시작
사이에서 단일 사용을 보장한다(단일 호스트의 SQLite 기준 — 호스트가
여러 대면 Redis 같은 공유 TTL 저장소로 ``Storage.consume_replay_key``를
구현해야 한다, `storage/sqlite_store.py` 의 docstring 참고).

``InMemoryReplayCache``와 완전히 같은 인터페이스(``consume(key, *,
expires_at, now) -> bool``, ``clear()``)를 구현한다 — `security/dpop.py`
의 `RuntimeTokenService`는 이 둘 중 어느 것을 받아도 코드를 바꿀 필요가
없다. 저장하는 값은 ``key``(jkt|method|htu|jti 조합) 원문이 아니라 그
SHA-256 digest뿐이다 — 저장소에 proof 식별자 원문이나 서명이 남지 않는다.
"""

from __future__ import annotations

import hashlib

from security.dpop import TokenBindingError
from storage.base import Storage


class StorageReplayCache:
    """``Storage.consume_replay_key()``로 proof 재사용을 원자적으로 막는다.

    DB 호출 자체가 예상치 못한 예외(연결 끊김, 디스크 I/O 오류 등)를 던지면
    "통과시켰는지 알 수 없음"을 "통과시킴"으로 착각하지 않도록 `TokenBindingError`
    로 변환해 fail-closed 한다 — 저장소 장애가 재전송 방지를 무력화하면 안 된다.
    """

    def __init__(self, storage: Storage, *, max_entries: int = 100_000) -> None:
        self.storage = storage
        self.max_entries = max(1, int(max_entries))

    def consume(self, key: str, *, expires_at: float, now: float) -> bool:
        """처음 본 key면 True, 유효한 중복이면 False. 저장소 한도·장애는 fail-closed."""
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        try:
            outcome = self.storage.consume_replay_key(
                digest, expires_at=expires_at, now=now, max_entries=self.max_entries
            )
        except TokenBindingError:
            raise
        except Exception as exc:
            raise TokenBindingError(
                "dpop_replay_store_unavailable",
                "DPoP replay 저장소 조회에 실패해 fail-closed 처리했습니다.",
                status_code=503,
            ) from exc
        if outcome == "FULL":
            raise TokenBindingError(
                "dpop_replay_cache_full",
                "DPoP replay cache가 가득 차 fail-closed 처리했습니다.",
                status_code=503,
            )
        return outcome == "NEW"

    def clear(self) -> None:
        """테스트/운영 리셋용 — 저장된 replay 키를 전부 지운다."""
        self.storage.clear_replay_keys()


__all__ = ["StorageReplayCache"]
