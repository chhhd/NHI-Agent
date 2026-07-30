"""Regex 기반 Secret 탐지.

`pattern_registry` 에 등록된 패턴을 파일 내용에 적용해 후보를 만든다.
파일 유형 필터링, 예제/더미 값 제외, 인라인 무시 주석(`# nhi:ignore`) 처리를 담당한다.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

from core.models import DetectorType, Severity
from scanner.entropy_scanner import shannon_entropy
from scanner.pattern_registry import (
    EXCLUDED_DIRS,
    EXCLUDED_FILE_PATTERNS,
    PLACEHOLDER_TOKENS,
    SCANNABLE_EXTENSIONS,
    SCANNABLE_FILENAMES,
    SecretPattern,
    all_patterns,
)

#: 이 주석이 있는 줄은 탐지에서 제외 (오탐 확정 시 개발자가 표시)
IGNORE_MARKERS = ("nhi:ignore", "nhi-ignore", "secret-scan:ignore", "gitleaks:allow")


@dataclass
class RegexCandidate:
    """Regex 탐지 후보."""

    pattern: SecretPattern
    value: str
    line_number: int
    start: int
    end: int
    entropy: float

    @property
    def secret_type(self) -> str:
        return self.pattern.id

    @property
    def provider(self) -> str:
        return self.pattern.provider

    @property
    def severity(self) -> Severity:
        return self.pattern.severity


def is_scannable_path(path: str) -> bool:
    """검사 대상 파일 경로인지 판정."""
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")

    if any(part in EXCLUDED_DIRS for part in parts[:-1]):
        return False

    filename = parts[-1]
    lowered = filename.lower()

    if any(pat in lowered for pat in EXCLUDED_FILE_PATTERNS):
        return False

    if lowered in SCANNABLE_FILENAMES:
        return True
    # `.env.staging` 처럼 접미가 붙은 형태
    if lowered.startswith(".env"):
        return True

    ext = os.path.splitext(lowered)[1]
    return ext in SCANNABLE_EXTENSIONS


def is_placeholder(value: str) -> bool:
    """예제/더미 값 여부."""
    lowered = value.lower()
    if any(token in lowered for token in PLACEHOLDER_TOKENS):
        return True
    # 반복 문자로만 이루어진 값
    if len(set(lowered.replace("-", "").replace("_", ""))) <= 2:
        return True
    return False


def has_ignore_marker(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in IGNORE_MARKERS)


class RegexScanner:
    """패턴 레지스트리 기반 스캐너."""

    detector = DetectorType.REGEX

    def __init__(self, patterns: Optional[Sequence[SecretPattern]] = None) -> None:
        self.patterns: List[SecretPattern] = list(patterns) if patterns else all_patterns()

    # ------------------------------------------------------------------
    def scan_text(self, text: str) -> List[RegexCandidate]:
        """텍스트 전체를 검사한다."""
        candidates: List[RegexCandidate] = []
        lines = text.splitlines()

        for line_number, line in enumerate(lines, start=1):
            if has_ignore_marker(line):
                continue
            candidates.extend(self.scan_line(line, line_number))

        return self._deduplicate(candidates)

    def scan_line(self, line: str, line_number: int) -> List[RegexCandidate]:
        results: List[RegexCandidate] = []

        for pattern in self.patterns:
            for match in pattern.regex.finditer(line):
                value = self._extract_value(pattern, match)
                if not value or is_placeholder(value):
                    continue

                entropy = shannon_entropy(value)
                if pattern.min_entropy is not None and entropy < pattern.min_entropy:
                    continue

                start, end = self._value_span(pattern, match)
                results.append(
                    RegexCandidate(
                        pattern=pattern,
                        value=value,
                        line_number=line_number,
                        start=start,
                        end=end,
                        entropy=round(entropy, 3),
                    )
                )
        return results

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_value(pattern: SecretPattern, match: re.Match) -> str:
        try:
            value = match.group(pattern.value_group)
        except IndexError:  # pragma: no cover - 패턴 정의 오류 방어
            value = match.group(0)
        return (value or "").strip().strip("'\"")

    @staticmethod
    def _value_span(pattern: SecretPattern, match: re.Match) -> tuple:
        try:
            return match.span(pattern.value_group)
        except IndexError:  # pragma: no cover
            return match.span(0)

    @staticmethod
    def _deduplicate(candidates: List[RegexCandidate]) -> List[RegexCandidate]:
        """같은 위치를 여러 패턴이 잡은 경우 더 구체적인(=심각한) 패턴만 남긴다.

        예) `sk-ant-api03-...` 은 ANTHROPIC_API_KEY 와 OPENAI_API_KEY 양쪽에 걸린다.
        더 긴 매치를 우선한다.
        """
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        ordered = sorted(
            candidates,
            key=lambda c: (
                c.line_number,
                -(c.end - c.start),
                severity_rank.get(c.severity, 9),
                c.pattern.id,
            ),
        )

        kept: List[RegexCandidate] = []
        for cand in ordered:
            overlaps = any(
                k.line_number == cand.line_number
                and not (cand.end <= k.start or cand.start >= k.end)
                for k in kept
            )
            if not overlaps:
                kept.append(cand)
        return sorted(kept, key=lambda c: (c.line_number, c.start))
