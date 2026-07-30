"""Secret 원문 마스킹.

원칙
  1. 저장/전송되는 모든 결과에는 원문이 포함되지 않는다.
  2. 관리자가 "어떤 키인지" 식별할 수 있도록 접두(prefix)와 말미 4자리는 남긴다.
  3. 짧은 값은 식별 정보를 남기지 않고 전량 마스킹한다.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

MASK_CHAR = "*"
_MASK_BLOCK = MASK_CHAR * 4
_MIN_MASKABLE_LEN = 8

#: 마스킹 시 보존할 알려진 접두사 (긴 것부터 매칭)
_KNOWN_PREFIXES = (
    "github_pat_", "sk-ant-api", "sk-ant-admin", "sk-proj-", "secret_",
    "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-", "xoxe-",
    "sk_live_", "sk_test_", "rk_live_", "rk_test_", "npm_", "ntn_",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "AKIA", "ASIA", "AIza",
    "hf_", "SG.", "sk-", "eyJ",
)


def _detect_prefix(value: str) -> str:
    for prefix in sorted(_KNOWN_PREFIXES, key=len, reverse=True):
        if value.startswith(prefix):
            return prefix
    return ""


def mask_secret(
    value: str,
    *,
    keep_prefix: Optional[int] = None,
    keep_suffix: int = 4,
) -> str:
    """Secret 원문을 마스킹한다.

    >>> mask_secret("xoxb-1111111111-2222222222-abcdefghijklmnop1234", keep_prefix=5)
    'xoxb-****-1234'
    >>> mask_secret("short")
    '*****'
    """
    if not value:
        return ""

    value = value.strip()

    # 너무 짧으면 식별 정보 없이 전량 마스킹
    if len(value) < _MIN_MASKABLE_LEN:
        return MASK_CHAR * len(value)

    prefix = value[:keep_prefix] if keep_prefix else _detect_prefix(value)

    # 접두 + 말미가 원문 절반을 넘으면 노출이 과하므로 축소
    max_reveal = max(len(value) // 2, 4)
    if len(prefix) + keep_suffix > max_reveal:
        keep_suffix = max(0, max_reveal - len(prefix))

    suffix = value[-keep_suffix:] if keep_suffix > 0 else ""
    if suffix:
        return f"{prefix}{_MASK_BLOCK}-{suffix}"
    return f"{prefix}{_MASK_BLOCK}"


def mask_line(line: str, secrets: Iterable[str], *, keep_prefix: Optional[int] = None) -> str:
    """한 줄 안의 secret 원문을 모두 마스킹된 값으로 치환한다.

    문맥(context) 추출 시 원문이 그대로 실려나가는 것을 막기 위해 사용한다.
    """
    masked = line
    for secret in secrets:
        if not secret or len(secret) < 4:
            continue
        masked = masked.replace(secret, mask_secret(secret, keep_prefix=keep_prefix))
    return masked


_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9/+=_\-\.]{20,}")


def redact_unknown_tokens(line: str, *, min_length: int = 32) -> str:
    """문맥 라인에 남아있을 수 있는 미탐지 장문 토큰을 보수적으로 가린다."""

    def _sub(m: re.Match) -> str:
        token = m.group(0)
        if len(token) < min_length:
            return token
        return mask_secret(token)

    return _LONG_TOKEN_RE.sub(_sub, line)
