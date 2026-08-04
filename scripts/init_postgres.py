"""DATABASE_URL 의 PostgreSQL 스키마를 초기화한다."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.database import PostgresDatabase


def main() -> int:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        print("DATABASE_URL 이 설정되지 않았습니다.", file=sys.stderr)
        return 2
    database = PostgresDatabase(database_url)
    database.initialize()
    print(database.health())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
