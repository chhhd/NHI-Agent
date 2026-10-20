"""저장소 기반 DPoP proof ``jti`` 단일 사용 캐시.

``InMemoryReplayCache`` 는 프로세스가 재시작되거나 워커가 둘 이상이면 이미 쓴 proof 의
재전송을 막지 못한다. 이 구현은 같은 DB 를 공유하는 모든 워커·재시작 사이에서 단일 사용을
보장한다(단일 호스트의 SQLite 기준). 호스트가 여러 대이면 Redis 같은 공유 TTL 저장소로
``Storage.consume_replay_key`` 를 구현하면 된다.
"""

from __future__ import annotations

import hashlib

from security.dpop import TokenBindingError
from storage.base import Storage


class StorageReplayCache:
    def __init__(self, storage: Storage, *, max_entries: int = 100_000) -> None:
        self.storage = storage
        self.max_entries = max(1, int(max_entries))

    def consume(self, key: str, *, expires_at: float, now: float) -> bool:
        """처음 본 key 면 True, 유효한 중복이면 False. 저장 한도를 넘으면 fail-closed."""
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        outcome = self.storage.consume_replay_key(
            digest, expires_at=expires_at, now=now, max_entries=self.max_entries
        )
        if outcome == "FULL":
            raise TokenBindingError(
                "dpop_replay_cache_full",
                "DPoP replay cache가 가득 차 fail-closed 처리했습니다.",
                status_code=503,
            )
        return outcome == "NEW"


__all__ = ["StorageReplayCache"]
