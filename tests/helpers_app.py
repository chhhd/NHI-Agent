"""`api.app` 의 비공개 복사본을 임시 DB 로 로드하는 테스트 헬퍼.

공용 모듈(`sys.modules['api.app']`)을 건드리지 않으므로, 다른 API 테스트가 자기 NHI_DB_PATH 로
처음 import 할 때 오염되지 않고 프로젝트의 실제 DB 도 열리지 않는다.
"""

from __future__ import annotations

import importlib.util
import itertools
import sys
from pathlib import Path

from core.config import reset_settings

_APP_PATH = Path(__file__).resolve().parent.parent / "api" / "app.py"
_counter = itertools.count()


def load_private_app(tmp_path, monkeypatch):
    """(module, private_name) 을 돌려준다. 호출자는 끝나면 `unload_private_app` 을 부른다."""
    name = f"api_app_private_{next(_counter)}"
    monkeypatch.setenv("NHI_DB_PATH", str(tmp_path / f"{name}.db"))
    reset_settings()
    spec = importlib.util.spec_from_file_location(name, _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    # pydantic 이 `from __future__ import annotations` 타입 주석을 해석하려면 sys.modules 에 있어야 한다.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module, name


def unload_private_app(module, name) -> None:
    sys.modules.pop(name, None)
    reset_settings()
    module.storage = None
