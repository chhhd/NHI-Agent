"""GitHubAppSettings — App ID / 개인키 로딩 및 노출 방지 검증.

기존 GitHubSettings(PAT) 경로에는 영향이 없어야 한다.
"""

from __future__ import annotations

from core.config import get_settings, reset_settings


def test_github_app_settings_default_empty_when_unset(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)
    reset_settings()
    try:
        settings = get_settings().github_app
        assert settings.app_id == ""
        assert settings.private_key == ""
        assert settings.is_configured is False
    finally:
        reset_settings()


def test_github_app_settings_reads_app_id_and_inline_key(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    # CI/환경변수에서 흔한 이스케이프된 개행 형태
    monkeypatch.setenv(
        "GITHUB_APP_PRIVATE_KEY",
        "-----BEGIN RSA PRIVATE KEY-----\\nZmFrZS1rZXk=\\n-----END RSA PRIVATE KEY-----\\n",
    )
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)
    reset_settings()
    try:
        settings = get_settings().github_app
        assert settings.app_id == "123456"
        assert settings.private_key == (
            "-----BEGIN RSA PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END RSA PRIVATE KEY-----\n"
        )
        assert settings.is_configured is True
    finally:
        reset_settings()


def test_github_app_settings_reads_private_key_from_file(monkeypatch, tmp_path):
    key_path = tmp_path / "app-private-key.pem"
    key_path.write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")

    monkeypatch.setenv("GITHUB_APP_ID", "999")
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", str(key_path))
    reset_settings()
    try:
        settings = get_settings().github_app
        assert settings.private_key == key_path.read_text()
        assert settings.is_configured is True
    finally:
        reset_settings()


def test_github_app_settings_inline_key_takes_priority_over_path(monkeypatch, tmp_path):
    key_path = tmp_path / "unused-key.pem"
    key_path.write_text("should-not-be-read")

    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "inline-key-content")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", str(key_path))
    reset_settings()
    try:
        settings = get_settings().github_app
        assert settings.private_key == "inline-key-content"
    finally:
        reset_settings()


def test_github_app_settings_missing_key_file_does_not_raise(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "/nonexistent/path/does-not-exist.pem")
    reset_settings()
    try:
        settings = get_settings().github_app
        assert settings.private_key == ""
        assert settings.is_configured is False
    finally:
        reset_settings()


def test_github_app_settings_repr_never_exposes_private_key(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_ID", "42")
    secret_key_content = "-----BEGIN RSA PRIVATE KEY-----\nSUPER-SECRET-MATERIAL\n-----END RSA PRIVATE KEY-----\n"
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", secret_key_content)
    reset_settings()
    try:
        settings = get_settings().github_app
        text = repr(settings)
        assert "SUPER-SECRET-MATERIAL" not in text
        assert "<set>" in text
    finally:
        reset_settings()


def test_github_settings_pat_path_is_unaffected_by_app_settings(monkeypatch):
    """GitHubAppSettings 추가가 기존 GitHubSettings(PAT) 동작을 바꾸지 않는지 확인."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-existing-pat")
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "irrelevant-to-pat")
    reset_settings()
    try:
        settings = get_settings()
        assert settings.github.token == "ghp-existing-pat"
        assert settings.github.api_base == "https://api.github.com"
    finally:
        reset_settings()
