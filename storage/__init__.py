"""영속화 계층.

인메모리 임시 저장소를 대체한다. 기본 구현은 SQLite(표준 라이브러리)이며,
PostgreSQL 등 공용 DB 로 교체할 때는 `Storage` 인터페이스만 맞추면 된다.
"""

from storage.base import Storage
from storage.sqlite_store import SQLiteStorage, get_default_storage

__all__ = ["Storage", "SQLiteStorage", "get_default_storage"]
