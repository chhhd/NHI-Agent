"""환경 설정.

`.env` 또는 환경변수에서 값을 읽는다. (전 계층 공통)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

try:  # python-dotenv 는 선택 의존성
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass


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
    #: 조직 App installation 인벤토리 조회 전용 토큰. 저장소 스캔 토큰과 분리한다.
    inventory_token: str = field(
        default_factory=lambda: _env("GITHUB_INVENTORY_TOKEN")
    )
    #: 조직 Audit Log 읽기 전용 토큰. 저장소 스캔·조치 토큰과 권한 경계를 분리한다.
    audit_token: str = field(default_factory=lambda: _env("GITHUB_AUDIT_TOKEN"))
    api_base: str = field(default_factory=lambda: _env("GITHUB_API_BASE", "https://api.github.com"))
    api_version: str = field(
        default_factory=lambda: _env("GITHUB_API_VERSION", "2022-11-28")
    )
    webhook_secret: str = field(default_factory=lambda: _env("GITHUB_WEBHOOK_SECRET"))
    # Rate Limit 여유분: 남은 호출이 이 값 이하이면 reset 까지 대기
    rate_limit_buffer: int = field(default_factory=lambda: _env_int("GITHUB_RATE_LIMIT_BUFFER", 5))
    max_wait_seconds: int = field(default_factory=lambda: _env_int("GITHUB_MAX_WAIT_SECONDS", 60))


@dataclass
class SlackSettings:
    bot_token: str = field(default_factory=lambda: _env("SLACK_BOT_TOKEN"))
    api_base: str = field(default_factory=lambda: _env("SLACK_API_BASE", "https://slack.com/api"))


@dataclass
class MicrosoftGraphSettings:
    tenant_id: str = field(default_factory=lambda: _env("MICROSOFT_TENANT_ID"))
    client_id: str = field(default_factory=lambda: _env("MICROSOFT_CLIENT_ID"))
    client_secret: str = field(default_factory=lambda: _env("MICROSOFT_CLIENT_SECRET"))
    access_token: str = field(default_factory=lambda: _env("MICROSOFT_GRAPH_ACCESS_TOKEN"))
    api_base: str = field(
        default_factory=lambda: _env("MICROSOFT_GRAPH_API_BASE", "https://graph.microsoft.com/v1.0")
    )
    login_base: str = field(
        default_factory=lambda: _env("MICROSOFT_LOGIN_BASE", "https://login.microsoftonline.com")
    )


@dataclass
class GoogleWorkspaceSettings:
    access_token: str = field(default_factory=lambda: _env("GOOGLE_WORKSPACE_ACCESS_TOKEN"))
    api_base: str = field(
        default_factory=lambda: _env("GOOGLE_WORKSPACE_API_BASE", "https://admin.googleapis.com")
    )


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
class RuntimeSecuritySettings:
    """AI Agent -> 내부 API 호출의 sender-constrained token 설정."""

    #: 내부 access token HMAC key. 관리자 API key와 분리하며 최소 32 bytes를 요구한다.
    token_signing_key: str = field(
        default_factory=lambda: _env("NHI_RUNTIME_TOKEN_SIGNING_KEY", "")
    )
    issuer: str = field(default_factory=lambda: _env("NHI_RUNTIME_TOKEN_ISSUER", "nhi-agent"))
    audience: str = field(
        default_factory=lambda: _env("NHI_RUNTIME_TOKEN_AUDIENCE", "nhi-runtime-api")
    )
    token_ttl_seconds: int = field(
        default_factory=lambda: _env_int("NHI_RUNTIME_TOKEN_TTL_SECONDS", 300)
    )
    dpop_proof_max_age_seconds: int = field(
        default_factory=lambda: _env_int("NHI_DPOP_PROOF_MAX_AGE_SECONDS", 120)
    )
    dpop_clock_skew_seconds: int = field(
        default_factory=lambda: _env_int("NHI_DPOP_CLOCK_SKEW_SECONDS", 30)
    )
    #: 외부 reverse proxy 뒤에서 보이는 정규 public origin. X-Forwarded-*를 직접 신뢰하지 않는다.
    public_base_url: str = field(
        default_factory=lambda: _env("NHI_RUNTIME_PUBLIC_BASE_URL", "")
    )


@dataclass
class GovernanceSettings:
    """NHI 거버넌스(실시간 통제 · 변경 승인 · 생명주기) 설정."""

    #: DENY는 모든 모드 차단. REVIEW는 enforce 차단 / monitor 허용 / human_in_the_loop 보류.
    #: human_in_the_loop: enforce + Agent 호출의 REVIEW 판정을 보류하고 관리자 승인 후 재시도.
    control_mode: str = field(default_factory=lambda: _env("NHI_CONTROL_MODE", "enforce"))
    #: true 면 승인·변경 같은 `actor` 가 필요한 작업에 개인 관리자 키를 반드시 요구한다.
    #: (설정과 무관하게 활성 개인 계정이 하나라도 있으면 자동으로 strict)
    require_verified_admin: bool = field(
        default_factory=lambda: _env("NHI_REQUIRE_VERIFIED_ADMIN", "false").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    #: 승인 대기 요청이 결정 없이 이 시간이 지나면 자동 거부(EXPIRED)된다.
    approval_ttl_seconds: int = field(
        default_factory=lambda: _env_int("NHI_CONTROL_APPROVAL_TTL_SECONDS", 900)
    )
    #: 승인 후 발급된 1회용 허가의 유효 시간.
    grant_ttl_seconds: int = field(
        default_factory=lambda: _env_int("NHI_CONTROL_GRANT_TTL_SECONDS", 300)
    )
    #: 같은 NHI 의 DENY 가 이 횟수에 도달하면 자동 격리한다.
    deny_quarantine_threshold: int = field(
        default_factory=lambda: _env_int("NHI_DENY_QUARANTINE_THRESHOLD", 3)
    )
    deny_window_seconds: int = field(
        default_factory=lambda: _env_int("NHI_DENY_WINDOW_SECONDS", 600)
    )
    #: 종료(TERMINATION) 후 파기 승인을 요청해야 하는 보존 기간(일).
    retention_days: int = field(default_factory=lambda: _env_int("NHI_RETENTION_DAYS", 30))
    stale_days: int = field(default_factory=lambda: _env_int("NHI_STALE_DAYS", 90))
    rotation_days: int = field(default_factory=lambda: _env_int("NHI_ROTATION_DAYS", 90))
    expiry_warning_days: int = field(
        default_factory=lambda: _env_int("NHI_EXPIRY_WARNING_DAYS", 14)
    )
    #: 권한 변경 후 이 기간 안에 안정화(ACTIVE 복귀)를 확인해야 한다.
    permission_observation_days: int = field(
        default_factory=lambda: _env_int("NHI_PERMISSION_OBSERVATION_DAYS", 7)
    )
    rotation_grace_hours: int = field(
        default_factory=lambda: _env_int("NHI_ROTATION_GRACE_HOURS", 24)
    )


@dataclass
class PrivacySettings:
    """Audit Log 개인정보 최소화·가명처리 설정."""

    #: 현재 지원 모드는 strict이며 사용자 식별자와 네트워크를 항상 HMAC 가명처리한다.
    mode: str = field(default_factory=lambda: _env("NHI_PRIVACY_MODE", "strict"))
    #: 가명값을 재시작 후에도 동일하게 유지하려면 32바이트 이상의 별도 키를 설정한다.
    pseudonymization_key: str = field(
        default_factory=lambda: _env("NHI_PRIVACY_PSEUDONYMIZATION_KEY", "")
    )
    #: 최소 수집된 사용 이벤트의 자동 보존 기간. 원본 Audit Log는 저장하지 않는다.
    usage_retention_days: int = field(
        default_factory=lambda: _env_int("NHI_USAGE_EVENT_RETENTION_DAYS", 30)
    )
    #: 이 기간 이상 연속 수집되어야만 "미사용 권한" 같은 부재 기반 판정을 허용한다.
    usage_min_coverage_days: int = field(
        default_factory=lambda: _env_int("NHI_USAGE_MIN_COVERAGE_DAYS", 30)
    )


@dataclass
class Settings:
    github: GitHubSettings = field(default_factory=GitHubSettings)
    slack: SlackSettings = field(default_factory=SlackSettings)
    microsoft: MicrosoftGraphSettings = field(default_factory=MicrosoftGraphSettings)
    runtime_security: RuntimeSecuritySettings = field(default_factory=RuntimeSecuritySettings)
    google_workspace: GoogleWorkspaceSettings = field(default_factory=GoogleWorkspaceSettings)
    scanner: ScannerSettings = field(default_factory=ScannerSettings)
    secret_storage: SecretStorageSettings = field(default_factory=SecretStorageSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    governance: GovernanceSettings = field(default_factory=GovernanceSettings)
    privacy: PrivacySettings = field(default_factory=PrivacySettings)
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
