"""환경 설정.

`.env` 또는 환경변수에서 값을 읽는다. (전 계층 공통)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

try:  # python-dotenv 는 선택 의존성
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

logger = logging.getLogger(__name__)


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


@dataclass
class GitHubSettings:
    token: str = field(default_factory=lambda: _env("GITHUB_TOKEN"))
    api_base: str = field(default_factory=lambda: _env("GITHUB_API_BASE", "https://api.github.com"))
    webhook_secret: str = field(default_factory=lambda: _env("GITHUB_WEBHOOK_SECRET"))
    # Rate Limit 여유분: 남은 호출이 이 값 이하이면 reset 까지 대기
    rate_limit_buffer: int = field(default_factory=lambda: _env_int("GITHUB_RATE_LIMIT_BUFFER", 5))
    max_wait_seconds: int = field(default_factory=lambda: _env_int("GITHUB_MAX_WAIT_SECONDS", 60))


def _load_github_app_private_key() -> str:
    """GitHub App 개인키를 환경변수 또는 파일에서 안전하게 읽는다.

    우선순위:
      1. ``GITHUB_APP_PRIVATE_KEY`` — PEM 내용을 직접 담은 값.
         환경변수/CI Secret 에는 개행이 이스케이프된 ``\\n`` 로 들어오는 경우가
         많아 실제 개행으로 복원한다.
      2. ``GITHUB_APP_PRIVATE_KEY_PATH`` — PEM 파일 경로.

    두 값 모두 없거나 파일을 읽을 수 없으면 빈 문자열을 반환한다. PAT 의
    `token` 이 비어 있을 때와 동일하게, 실제 사용 시점(JWT 서명)에서 인증
    오류로 드러나게 하고 여기서는 예외를 던지지 않는다. 이 함수는 키 내용을
    로그에 남기지 않는다.
    """
    inline = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    if inline.strip():
        return inline.replace("\\n", "\n")

    path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
    if not path.strip():
        return ""

    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        logger.warning(
            "GitHub App private key 파일을 읽을 수 없습니다: %s (%s)",
            path,
            exc.__class__.__name__,
        )
        return ""


@dataclass
class GitHubAppSettings:
    """GitHub App 인증 설정 (Installation 기반 권한 수집용).

    기존 `GitHubSettings` (PAT) 와는 완전히 별도 경로다. 여기 값이 비어
    있어도 PAT 경로 동작에는 아무 영향이 없다.
    """

    app_id: str = field(default_factory=lambda: _env("GITHUB_APP_ID"))
    #: PEM 형식 개인키 원문. 절대 로그·예외 메시지·repr 에 노출하지 않는다.
    private_key: str = field(default_factory=_load_github_app_private_key)
    api_base: str = field(default_factory=lambda: _env("GITHUB_API_BASE", "https://api.github.com"))

    @property
    def is_configured(self) -> bool:
        """App ID 와 개인키가 모두 있어야 App 인증을 시도할 수 있다."""
        return bool(self.app_id.strip()) and bool(self.private_key.strip())

    def __repr__(self) -> str:  # pragma: no cover - 키 노출 방지가 목적
        return (
            f"GitHubAppSettings(app_id={self.app_id!r}, "
            f"private_key={'<set>' if self.private_key.strip() else '<empty>'}, "
            f"api_base={self.api_base!r})"
        )


@dataclass
class SlackSettings:
    bot_token: str = field(default_factory=lambda: _env("SLACK_BOT_TOKEN"))
    api_base: str = field(default_factory=lambda: _env("SLACK_API_BASE", "https://slack.com/api"))


@dataclass
class ScannerSettings:
    # 검사 대상 최대 파일 크기 (byte)
    max_file_size: int = field(default_factory=lambda: _env_int("SCANNER_MAX_FILE_SIZE", 1_048_576))
    # 탐지 결과 앞뒤로 추출할 문맥 라인 수
    context_lines: int = field(default_factory=lambda: _env_int("SCANNER_CONTEXT_LINES", 2))
    # Entropy 임계값
    base64_entropy_threshold: float = field(
        default_factory=lambda: _env_float("SCANNER_BASE64_ENTROPY", 4.5)
    )
    hex_entropy_threshold: float = field(
        default_factory=lambda: _env_float("SCANNER_HEX_ENTROPY", 3.0)
    )
    # Fingerprint 생성 시 사용할 salt (조직별로 다르게 두면 값 역추적 난이도 상승)
    fingerprint_salt: str = field(default_factory=lambda: _env("FINGERPRINT_SALT", ""))


@dataclass
class SecretStorageSettings:
    #: URL-safe base64 로 인코딩된 32-byte 로컬 개발 키.
    #: 운영에서는 KMS/Vault 어댑터로 교체하고 이 값을 사용하지 않는다.
    master_key: str = field(default_factory=lambda: _env("NHI_MASTER_KEY", ""))
    key_id: str = field(default_factory=lambda: _env("NHI_MASTER_KEY_ID", "local-v1"))
    ttl_seconds: int = field(
        default_factory=lambda: _env_int("NHI_SECRET_TTL_SECONDS", 3600)
    )
    #: Secret 복호화·조치 승인 API 보호용 키. 미설정 시 해당 API 는 비활성화된다.
    admin_api_key: str = field(default_factory=lambda: _env("NHI_ADMIN_API_KEY", ""))


@dataclass
class DatabaseSettings:
    #: PostgreSQL 운영 저장소 연결 문자열. 비어 있으면 기존 SQLite 를 사용한다.
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", ""))


@dataclass
class Settings:
    github: GitHubSettings = field(default_factory=GitHubSettings)
    github_app: GitHubAppSettings = field(default_factory=GitHubAppSettings)
    slack: SlackSettings = field(default_factory=SlackSettings)
    scanner: ScannerSettings = field(default_factory=ScannerSettings)
    secret_storage: SecretStorageSettings = field(default_factory=SecretStorageSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    http_timeout: float = field(default_factory=lambda: _env_float("HTTP_TIMEOUT", 15.0))
    max_retries: int = field(default_factory=lambda: _env_int("HTTP_MAX_RETRIES", 3))


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """프로세스 전역 설정 (지연 초기화)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """테스트에서 환경변수를 바꾼 뒤 재로딩할 때 사용."""
    global _settings
    _settings = None
