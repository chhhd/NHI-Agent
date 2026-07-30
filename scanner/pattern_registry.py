"""Secret 패턴 레지스트리.

`SecretPattern` 하나가 "API Key 유형 분류"의 한 단위이며,
regex_scanner 가 이 레지스트리를 순회하며 탐지한다.
새 SaaS 를 추가할 때는 이 파일에만 패턴을 추가하면 된다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern

from core.models import Severity


@dataclass(frozen=True)
class SecretPattern:
    """단일 Secret 유형 정의."""

    id: str                       # 예: SLACK_BOT_TOKEN
    name: str                     # 사람이 읽는 이름
    provider: str                 # slack / github / aws ...
    regex: Pattern[str]
    severity: Severity = Severity.HIGH
    # 정규식 그룹 중 실제 secret 값을 담고 있는 그룹 번호 (0 = 전체 매치)
    value_group: int = 0
    # 마스킹 시 앞에서 보존할 접두 길이 (예: "xoxb-" = 5). None 이면 자동 판단.
    keep_prefix: Optional[int] = None
    # 매치 결과에 추가로 요구되는 최소 엔트로피 (오탐 억제용). None 이면 검사 안 함.
    min_entropy: Optional[float] = None
    # 외부 API 로 유효성 검증이 가능한 provider 인지
    verifiable: bool = False
    description: str = ""
    tags: List[str] = field(default_factory=list)


def _p(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# 패턴 정의
# ---------------------------------------------------------------------------

_PATTERNS: List[SecretPattern] = [
    # ---------------- Slack ----------------
    SecretPattern(
        id="SLACK_BOT_TOKEN",
        name="Slack Bot Token",
        provider="slack",
        regex=_p(r"xoxb-[0-9]{10,15}-[0-9]{10,15}-[A-Za-z0-9]{24,34}"),
        severity=Severity.CRITICAL,
        keep_prefix=5,
        verifiable=True,
        description="Slack Bot User OAuth Token. 워크스페이스 봇 권한 전체를 위임한다.",
        tags=["saas", "messaging"],
    ),
    SecretPattern(
        id="SLACK_USER_TOKEN",
        name="Slack User Token",
        provider="slack",
        regex=_p(r"xoxp-[0-9]{10,15}-[0-9]{10,15}-[0-9]{10,15}-[A-Za-z0-9]{32,64}"),
        severity=Severity.CRITICAL,
        keep_prefix=5,
        verifiable=True,
        description="Slack User OAuth Token. 사용자 권한으로 동작한다.",
        tags=["saas", "messaging"],
    ),
    SecretPattern(
        id="SLACK_APP_TOKEN",
        name="Slack App-Level Token",
        provider="slack",
        regex=_p(r"xapp-[0-9]-[A-Z0-9]{9,12}-[0-9]{10,15}-[A-Za-z0-9]{32,80}"),
        severity=Severity.HIGH,
        keep_prefix=5,
        verifiable=True,
        description="Slack App-Level Token (Socket Mode).",
        tags=["saas", "messaging"],
    ),
    SecretPattern(
        id="SLACK_WEBHOOK_URL",
        name="Slack Incoming Webhook URL",
        provider="slack",
        regex=_p(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]{20,}"),
        severity=Severity.MEDIUM,
        keep_prefix=33,
        description="Slack Incoming Webhook. 임의 채널 메시지 발송이 가능하다.",
        tags=["saas", "messaging", "url"],
    ),
    SecretPattern(
        id="SLACK_SIGNING_SECRET",
        name="Slack Signing Secret",
        provider="slack",
        regex=_p(
            r"(?i)slack[_-]?signing[_-]?secret['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})",
        ),
        value_group=1,
        severity=Severity.HIGH,
        description="Slack 요청 서명 검증용 secret.",
        tags=["saas", "messaging"],
    ),
    # ---------------- GitHub ----------------
    SecretPattern(
        id="GITHUB_PAT",
        name="GitHub Personal Access Token",
        provider="github",
        regex=_p(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        severity=Severity.CRITICAL,
        keep_prefix=4,
        verifiable=True,
        description="GitHub classic PAT / OAuth / App / Refresh Token.",
        tags=["vcs"],
    ),
    SecretPattern(
        id="GITHUB_FINE_GRAINED_PAT",
        name="GitHub Fine-grained PAT",
        provider="github",
        regex=_p(r"github_pat_[A-Za-z0-9_]{60,255}"),
        severity=Severity.CRITICAL,
        keep_prefix=11,
        verifiable=True,
        description="GitHub fine-grained personal access token.",
        tags=["vcs"],
    ),
    # ---------------- GitLab ----------------
    SecretPattern(
        id="GITLAB_PAT",
        name="GitLab Personal Access Token",
        provider="gitlab",
        regex=_p(r"glpat-[A-Za-z0-9\-_]{20,50}"),
        severity=Severity.CRITICAL,
        keep_prefix=6,
        verifiable=True,
        description="GitLab PAT.",
        tags=["vcs"],
    ),
    # ---------------- AWS ----------------
    SecretPattern(
        id="AWS_ACCESS_KEY_ID",
        name="AWS Access Key ID",
        provider="aws",
        regex=_p(r"\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16})\b"),
        value_group=1,
        severity=Severity.CRITICAL,
        keep_prefix=4,
        description="AWS Access Key ID. Secret Access Key 와 쌍으로 사용된다.",
        tags=["cloud"],
    ),
    SecretPattern(
        id="AWS_SECRET_ACCESS_KEY",
        name="AWS Secret Access Key",
        provider="aws",
        regex=_p(
            r"(?i)aws[_-]?(?:secret[_-]?)?access[_-]?key(?:[_-]?id)?['\"]?\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{40})",
        ),
        value_group=1,
        severity=Severity.CRITICAL,
        min_entropy=4.0,
        description="AWS Secret Access Key.",
        tags=["cloud"],
    ),
    # ---------------- Google ----------------
    SecretPattern(
        id="GOOGLE_API_KEY",
        name="Google API Key",
        provider="google",
        regex=_p(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity=Severity.HIGH,
        keep_prefix=4,
        description="Google Cloud / Firebase API Key.",
        tags=["cloud"],
    ),
    SecretPattern(
        id="GCP_SERVICE_ACCOUNT_KEY",
        name="GCP Service Account Private Key",
        provider="google",
        regex=_p(r'"type"\s*:\s*"service_account"'),
        severity=Severity.CRITICAL,
        description="GCP 서비스 계정 키 JSON 파일.",
        tags=["cloud", "file"],
    ),
    # ---------------- AI / ML ----------------
    SecretPattern(
        id="ANTHROPIC_API_KEY",
        name="Anthropic API Key",
        provider="anthropic",
        regex=_p(r"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9\-_]{80,120}"),
        severity=Severity.CRITICAL,
        keep_prefix=10,
        description="Anthropic Claude API Key.",
        tags=["ai"],
    ),
    SecretPattern(
        id="OPENAI_API_KEY",
        name="OpenAI API Key",
        provider="openai",
        regex=_p(r"sk-(?:proj-)?[A-Za-z0-9\-_]{32,200}"),
        severity=Severity.CRITICAL,
        keep_prefix=3,
        min_entropy=3.5,
        description="OpenAI API Key.",
        tags=["ai"],
    ),
    SecretPattern(
        id="HUGGINGFACE_TOKEN",
        name="Hugging Face Access Token",
        provider="huggingface",
        regex=_p(r"\bhf_[A-Za-z0-9]{34,40}\b"),
        severity=Severity.HIGH,
        keep_prefix=3,
        verifiable=True,
        description="Hugging Face User Access Token.",
        tags=["ai"],
    ),
    # ---------------- SaaS ----------------
    SecretPattern(
        id="NOTION_INTEGRATION_TOKEN",
        name="Notion Integration Token",
        provider="notion",
        regex=_p(r"(?:secret_|ntn_)[A-Za-z0-9]{35,50}"),
        severity=Severity.HIGH,
        keep_prefix=7,
        verifiable=True,
        description="Notion Internal Integration Token.",
        tags=["saas"],
    ),
    SecretPattern(
        id="STRIPE_SECRET_KEY",
        name="Stripe Secret Key",
        provider="stripe",
        regex=_p(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,120}\b"),
        severity=Severity.CRITICAL,
        keep_prefix=8,
        description="Stripe Secret / Restricted Key.",
        tags=["payment"],
    ),
    SecretPattern(
        id="SENDGRID_API_KEY",
        name="SendGrid API Key",
        provider="sendgrid",
        regex=_p(r"\bSG\.[A-Za-z0-9\-_]{20,25}\.[A-Za-z0-9\-_]{35,45}\b"),
        severity=Severity.HIGH,
        keep_prefix=3,
        description="SendGrid API Key.",
        tags=["saas", "email"],
    ),
    SecretPattern(
        id="NPM_ACCESS_TOKEN",
        name="npm Access Token",
        provider="npm",
        regex=_p(r"\bnpm_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        keep_prefix=4,
        description="npm registry access token.",
        tags=["registry"],
    ),
    # ---------------- 범용 ----------------
    SecretPattern(
        id="PRIVATE_KEY_BLOCK",
        name="Private Key Block",
        provider="generic",
        regex=_p(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        severity=Severity.CRITICAL,
        description="PEM 형식 개인키.",
        tags=["key"],
    ),
    SecretPattern(
        id="JWT_TOKEN",
        name="JSON Web Token",
        provider="generic",
        regex=_p(r"\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"),
        severity=Severity.MEDIUM,
        keep_prefix=6,
        description="JWT. 만료 전까지 유효한 자격 증명일 수 있다.",
        tags=["token"],
    ),
    SecretPattern(
        id="BASIC_AUTH_URL",
        name="URL Embedded Credential",
        provider="generic",
        regex=_p(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]{1,64}:([^/\s:@]{3,64})@[^\s/]+"),
        value_group=1,
        severity=Severity.HIGH,
        description="URL 에 포함된 사용자명/비밀번호.",
        tags=["credential"],
    ),
    SecretPattern(
        id="GENERIC_API_KEY",
        name="Generic API Key Assignment",
        provider="generic",
        regex=_p(
            r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|private[_-]?token|password)['\"]?\s*[:=]\s*"
            r"['\"]([A-Za-z0-9/+=_\-\.]{16,120})['\"]",
        ),
        value_group=1,
        severity=Severity.MEDIUM,
        min_entropy=3.2,
        description="키워드 기반 범용 자격 증명 할당. 오탐 가능성이 있어 엔트로피로 한 번 더 거른다.",
        tags=["generic"],
    ),
]


PATTERN_REGISTRY: Dict[str, SecretPattern] = {p.id: p for p in _PATTERNS}


def all_patterns() -> List[SecretPattern]:
    """등록된 전체 패턴."""
    return list(_PATTERNS)


def get_pattern(pattern_id: str) -> Optional[SecretPattern]:
    return PATTERN_REGISTRY.get(pattern_id)


def patterns_by_provider(provider: str) -> List[SecretPattern]:
    return [p for p in _PATTERNS if p.provider == provider]


def register_pattern(pattern: SecretPattern, *, override: bool = False) -> None:
    """런타임에 패턴 추가 (추가 SaaS 연동 시 사용)."""
    if pattern.id in PATTERN_REGISTRY and not override:
        raise ValueError(f"이미 등록된 패턴 ID: {pattern.id}")
    if pattern.id in PATTERN_REGISTRY:
        _PATTERNS[:] = [p for p in _PATTERNS if p.id != pattern.id]
    _PATTERNS.append(pattern)
    PATTERN_REGISTRY[pattern.id] = pattern


# ---------------------------------------------------------------------------
# 검사 대상 / 제외 규칙
# ---------------------------------------------------------------------------

#: 기본 검사 대상 확장자 (.env, JSON, YAML, Python, JavaScript + 자주 쓰이는 설정 파일)
SCANNABLE_EXTENSIONS = {
    ".env", ".json", ".yaml", ".yml", ".py", ".js", ".jsx", ".ts", ".tsx",
    ".sh", ".bash", ".zsh", ".ini", ".cfg", ".conf", ".toml", ".properties",
    ".xml", ".tf", ".tfvars", ".txt", ".md", ".rb", ".go", ".java", ".php",
}

#: 확장자가 없어도 검사할 파일명
SCANNABLE_FILENAMES = {
    ".env", ".env.local", ".env.dev", ".env.development", ".env.prod",
    ".env.production", ".env.test", ".npmrc", ".netrc", "dockerfile",
    "docker-compose.yml", "credentials", "config",
}

#: 경로에 포함되면 건너뛰는 디렉터리
EXCLUDED_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".nuxt", "vendor", "site-packages", ".mypy_cache", ".pytest_cache",
    "coverage", ".terraform",
}

#: 파일명에 포함되면 건너뛰는 패턴 (lock/minified/테스트 픽스처)
EXCLUDED_FILE_PATTERNS = (
    "package-lock.json", "yarn.lock", "poetry.lock", "pnpm-lock.yaml",
    "go.sum", "composer.lock", ".min.js", ".min.css", ".map",
)

#: 값에 이 토큰이 포함되면 예제/더미로 간주 (오탐 억제)
PLACEHOLDER_TOKENS = (
    "example", "sample", "dummy", "placeholder", "your-", "yourkey", "changeme",
    "todo", "xxxxx", "<your", "insert", "redacted", "masked", "fake", "test-key",
    "abcdef123456", "000000", "111111", "notreal", "dummykey",
)
