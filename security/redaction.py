"""보안 이벤트·감사 로그 문자열의 방어적 비밀정보 제거.

외부 감사 로그의 action/source/user-agent 필드는 신뢰할 수 없는 입력이다. URL
query나 Authorization 헤더가 섞여 들어와도 분석 API와 영속 스냅샷에 원문
Credential이 다시 실리지 않도록 직렬화 전에 한 번 더 정리한다.
"""

from __future__ import annotations

import re
from typing import Any

from scanner.masking import redact_unknown_tokens


_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|api[_-]?key|client[_-]?secret|private[_-]?key|secret|token)"
    r"(\s*[:=]\s*)(?:bearer\s+|dpop\s+|basic\s+)?([^\s&,;\"']+)"
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(bearer|dpop|basic)\s+[A-Za-z0-9._~+/=-]{6,}"
)
_KNOWN_SECRET_RE = re.compile(
    r"(?i)\b(?:github_pat_|gh[pousr]_|xox[bapser]-|sk-(?:proj-)?|"
    r"sk-ant-(?:api|admin)|glpat-|npm_|ntn_|hf_|AIza)[A-Za-z0-9._~+/=-]{6,}"
)


def sanitize_security_text(value: object, *, max_length: int = 500) -> str:
    """감사 문자열에서 credential-like 값을 제거하고 길이를 제한한다."""
    text = str(value or "")
    text = _SENSITIVE_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)
    text = _AUTH_SCHEME_RE.sub(lambda m: f"{m.group(1)} <redacted>", text)
    text = _KNOWN_SECRET_RE.sub("<redacted>", text)
    text = redact_unknown_tokens(text, min_length=20)
    return text[:max_length]


def sanitize_security_value(value: Any, *, depth: int = 0) -> Any:
    """event attributes처럼 중첩된 값을 안전한 JSON 호환 값으로 정리한다."""
    if depth >= 4:
        return "<truncated>"
    if isinstance(value, str):
        return sanitize_security_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        return {
            sanitize_security_text(key, max_length=100): sanitize_security_value(
                item, depth=depth + 1
            )
            for key, item in list(value.items())[:50]
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_security_value(item, depth=depth + 1) for item in list(value)[:50]]
    return sanitize_security_text(value)


__all__ = ["sanitize_security_text", "sanitize_security_value"]
