"""PostgreSQL 스키마 초기화와 상태 확인.

현재 애플리케이션 기본 저장소는 개발 편의를 위해 SQLite 다. 이 클래스는 운영
PostgreSQL의 초기화/연결 검증 포트이며, 다음 단계에서 SQLAlchemy/Postgres
Storage 구현을 붙일 때 동일 ``DATABASE_URL`` 을 사용한다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


class PostgresDatabase:
    def __init__(self, database_url: str) -> None:
        if not database_url.startswith(("postgresql://", "postgres://")):
            raise ValueError("PostgreSQL DATABASE_URL 이 필요합니다.")
        self.database_url = database_url

    def connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PostgreSQL 사용을 위해 psycopg 패키지가 필요합니다.") from exc
        return psycopg.connect(self.database_url)

    def initialize(self) -> None:
        schema_path = Path(__file__).with_name("postgres_schema.sql")
        schema = schema_path.read_text(encoding="utf-8")
        with self.connect() as connection:
            connection.execute(schema)
            connection.commit()

    def health(self) -> Dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT current_database(), current_user, version()"
            ).fetchone()
        return {
            "status": "ok",
            "database": row[0],
            "user": row[1],
            "version": row[2],
        }
