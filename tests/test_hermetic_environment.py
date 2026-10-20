"""테스트 격리 장치(conftest)가 실제로 동작하는지 고정한다.

이 장치가 조용히 깨지면 테스트가 개발자의 `.env` 실토큰으로 외부 API 를 호출할 수 있다.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import httpx
import pytest

from core.config import get_settings, reset_settings
from tests.conftest import ExternalNetworkBlocked


def test_real_credentials_from_dotenv_are_not_visible_to_tests():
    reset_settings()
    settings = get_settings()
    assert settings.github.token == ""
    assert settings.github.inventory_token == ""
    assert settings.slack.bot_token == ""
    assert settings.secret_storage.admin_api_key == ""


def test_default_database_is_a_temp_file_not_the_project_database():
    project_db = (Path(__file__).resolve().parent.parent / "nhi_scanner.db").resolve()
    configured = Path(os.environ["NHI_DB_PATH"]).resolve()
    assert configured != project_db
    assert project_db.parent not in configured.parents or "nhi-pytest-" in str(configured)


def test_external_hosts_cannot_be_reached():
    with pytest.raises(ExternalNetworkBlocked):
        socket.getaddrinfo("api.github.com", 443)
    with pytest.raises(ExternalNetworkBlocked):
        httpx.get("https://api.github.com/user", timeout=2)
    with pytest.raises(ExternalNetworkBlocked):
        socket.create_connection(("203.0.113.9", 443), timeout=2)


def test_loopback_is_still_allowed():
    # TestClient 와 로컬 서버를 쓰는 테스트가 막히지 않아야 한다
    assert socket.getaddrinfo("127.0.0.1", 80)
