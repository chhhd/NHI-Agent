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


def sanitize_security_value(
    value: Any, *, depth: int = 0, preserve_top_level_keys: bool = False
) -> Any:
    """event attributes처럼 중첩된 값을 안전한 JSON 호환 값으로 정리한다.

    기본적으로(`preserve_top_level_keys=False`) 키 이름도 `sanitize_security_text()`로
    정리한다 — 감사 로그 attributes/HTTP 헤더처럼 키 이름 자체가 신뢰할 수
    없는 데이터일 수 있기 때문이다. `redact_unknown_tokens(min_length=20)`가
    20자 이상의 토큰형 문자열을 마스킹하므로, 이 경로로 넘어오는 dict가
    **우리가 정의한 고정 스키마**(dataclass 필드명 등)를 직렬화한 것이면
    `token_used_after_revocation`처럼 긴 필드명이 토큰처럼 보여 마스킹돼
    버린다 — 값이 아니라 필드 자체를 잃는 것이므로 더 위험하다.

    `preserve_top_level_keys=True`를 주면 **가장 바깥 depth(0)의 키만**
    원문 그대로 둔다. 중첩된 dict(예: `AnalysisSignals.extra`처럼 호출부가
    직접 정의하지 않은 동적 키를 담는 필드)는 depth가 올라가면서 다시 기본
    동작(키 정리)으로 돌아간다 — 꼭 필요한 최상위 필드명만 보존하고, 그 외
    모든 값과 더 깊은 단계의 키는 기존과 동일하게 보호한다.
    """
    if depth >= 4:
        return "<truncated>"
    if isinstance(value, str):
        return sanitize_security_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        skip_key_sanitize = preserve_top_level_keys and depth == 0
        return {
            (key if skip_key_sanitize else sanitize_security_text(key, max_length=100)):
                sanitize_security_value(item, depth=depth + 1)
            for key, item in list(value.items())[:50]
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_security_value(item, depth=depth + 1) for item in list(value)[:50]]
    return sanitize_security_text(value)


__all__ = ["sanitize_security_text", "sanitize_security_value"]
