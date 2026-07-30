"""Agent 공용 텍스트/경로 휴리스틱.

Discovery / Context Analysis 가 함께 쓰는 문자열 신호 추출기를 모아둔다.
입력은 항상 **마스킹된** 코드 문맥이므로 원문 Secret 은 다루지 않는다.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence

from core.models import SecretFinding
from scanner.pattern_registry import PLACEHOLDER_TOKENS

#: `NAME = value` / `"name": value` / `NAME: value` / `export NAME=value`
_ASSIGN_PATTERNS = (
    re.compile(r"(?:export\s+|set\s+)?([A-Za-z_][A-Za-z0-9_.\-]{2,60})\s*[:=]\s*\S"),
    re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_.\-]{2,60})['\"]\s*:\s*\S"),
    re.compile(r"(?:getenv|environ\.get|env\[)\s*\(?\s*['\"]([A-Za-z_][A-Za-z0-9_]{2,60})['\"]"),
)

#: 경로 구분자 정규화
_SPLIT_PATH = re.compile(r"[\\/]+")

#: 소유자 표기 주석. 예: `# owner: platform-team`, `// Owner - @data-eng`
_OWNER_COMMENT = re.compile(
    r"(?i)(?:owner|maintainer|team|contact|responsible)\s*[:=\-]\s*@?([A-Za-z0-9_.\-/ ]{2,60})"
)

#: `@org/team` 형태 멘션
_TEAM_MENTION = re.compile(r"@([A-Za-z0-9_\-]{2,40}(?:/[A-Za-z0-9_\-]{2,40})?)")


def path_parts(file_path: str) -> List[str]:
    """경로를 소문자 조각으로 분해한다."""
    return [p.lower() for p in _SPLIT_PATH.split(file_path or "") if p]


def path_text(file_path: str) -> str:
    return (file_path or "").replace("\\", "/").lower()


def context_lines(finding: SecretFinding) -> List[str]:
    """탐지 라인 + 앞뒤 문맥 (마스킹된 상태)."""
    ctx = finding.context
    return [*ctx.before, ctx.line, *ctx.after]


def context_text(finding: SecretFinding) -> str:
    return "\n".join(context_lines(finding)).lower()


def extract_variable_name(finding: SecretFinding) -> Optional[str]:
    """탐지 라인에서 Secret 이 담긴 변수/키 이름을 뽑는다."""
    line = finding.context.line or ""
    for pattern in _ASSIGN_PATTERNS:
        match = pattern.search(line)
        if match:
            name = match.group(1).strip()
            # `https`, `http` 같은 URL 스킴 오인 방지
            if name.lower() in {"http", "https", "url", "uri"}:
                continue
            return name
    return None


def contains_any(text: str, keywords: Iterable[str]) -> List[str]:
    """text 안에 등장한 키워드 목록."""
    lowered = text.lower()
    return [k for k in keywords if k in lowered]


def looks_like_placeholder(finding: SecretFinding) -> bool:
    """예제/더미 값으로 보이는가.

    원문이 없으므로 마스킹된 값과 주변 문맥, 변수명으로 판단한다.
    """
    haystack = " ".join(
        [
            finding.masked_value or "",
            finding.context.line or "",
            path_text(finding.file_path),
        ]
    ).lower()
    if any(token in haystack for token in PLACEHOLDER_TOKENS):
        return True
    # `<...>` / `${...}` / `{{...}}` 자리표시자
    return bool(re.search(r"<[^>]{2,40}>|\$\{[^}]{2,40}\}|\{\{[^}]{2,40}\}\}", finding.context.line or ""))


def owner_candidates_from_text(lines: Sequence[str]) -> List[str]:
    """주석·문맥에서 소유자 후보를 뽑는다."""
    found: List[str] = []
    for line in lines:
        for match in _OWNER_COMMENT.finditer(line):
            value = match.group(1).strip().strip("-").strip()
            if value and value not in found:
                found.append(value)
        for match in _TEAM_MENTION.finditer(line):
            value = match.group(1).strip()
            if value and value not in found:
                found.append(value)
    return found


def humanize(token: str) -> str:
    """`customer_support_bot` / `CustomerSupportBot` → `customer-support-bot`."""
    text = re.sub(r"(?<!^)(?=[A-Z][a-z])", "-", token or "")
    text = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return text
