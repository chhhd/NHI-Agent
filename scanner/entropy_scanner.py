"""Entropy 기반 무작위 문자열 탐지.

Regex 로 잡히지 않는 사내 발급 키 / 미등록 SaaS 키를 찾기 위해
Shannon Entropy 가 높은 토큰을 후보로 올린다.

오탐이 많은 기법이므로 다음 조건으로 좁힌다.
  1. base64 / hex 문자 집합으로만 이루어진 토큰
  2. 길이 임계값 이상
  3. 엔트로피 임계값 이상
  4. 경로 / URL / UUID / 해시 상수 등 알려진 형태 제외
  5. 주변에 자격 증명 키워드가 있으면 severity 상향
"""

from __future__ import annotations

import math
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from core.config import get_settings
from core.models import DetectorType, Severity
from scanner.pattern_registry import PLACEHOLDER_TOKENS

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
HEX_CHARS = set("abcdefABCDEF0123456789")

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ALL_DIGITS_RE = re.compile(r"^\d+$")
_SNAKE_OR_KEBAB_RE = re.compile(r"^[a-z0-9]+([_-][a-z0-9]+){2,}$")

#: Git commit SHA(40) / SHA-256 digest(64) — 소문자 hex 고정 길이.
#: 자격 증명이 아니라 버전 고정·무결성 값으로 쓰이는 형태다.
_DIGEST_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")

#: 자격 증명 관련 키워드 (같은 줄에 있으면 신뢰도 상승)
_CREDENTIAL_KEYWORDS = (
    "key", "token", "secret", "password", "passwd", "pwd", "credential",
    "auth", "api", "access", "private", "signature", "session", "bearer",
)

#: 자격 증명이 아닐 확률이 높은 키워드 (같은 줄에 있으면 제외)
_NEGATIVE_KEYWORDS = (
    "sha256:", "sha1:", "md5:", "integrity", "checksum", "hash",
    "commit", "revision", "digest", "base64,", "data:image", "font-face",
    # GitHub Actions 는 `uses: owner/action@<commit sha>` 로 버전을 고정한다.
    "uses:", "image:", "resolved\"", "\"version\"",
)


def shannon_entropy(data: str, charset: Optional[Iterable[str]] = None) -> float:
    """문자열의 Shannon Entropy (bit/char)."""
    if not data:
        return 0.0
    if charset is None:
        counts: Dict[str, int] = {}
        for ch in data:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    entropy = 0.0
    length = len(data)
    for ch in set(charset):
        p_x = float(data.count(ch)) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


class EntropyCandidate:
    """엔트로피 탐지 후보."""

    __slots__ = ("value", "line_number", "start", "end", "entropy", "charset", "severity")

    def __init__(
        self,
        value: str,
        line_number: int,
        start: int,
        end: int,
        entropy: float,
        charset: str,
        severity: Severity,
    ) -> None:
        self.value = value
        self.line_number = line_number
        self.start = start
        self.end = end
        self.entropy = entropy
        self.charset = charset
        self.severity = severity

    def __repr__(self) -> str:  # pragma: no cover
        return f"<EntropyCandidate line={self.line_number} entropy={self.entropy:.2f}>"


class EntropyScanner:
    """무작위 문자열 탐지기."""

    detector = DetectorType.ENTROPY

    def __init__(
        self,
        *,
        base64_threshold: Optional[float] = None,
        hex_threshold: Optional[float] = None,
        min_length: int = 20,
        max_length: int = 512,
    ) -> None:
        settings = get_settings().scanner
        self.base64_threshold = (
            base64_threshold if base64_threshold is not None else settings.base64_entropy_threshold
        )
        self.hex_threshold = (
            hex_threshold if hex_threshold is not None else settings.hex_entropy_threshold
        )
        self.min_length = min_length
        self.max_length = max_length

    # ------------------------------------------------------------------
    def scan_line(self, line: str, line_number: int) -> List[EntropyCandidate]:
        lowered = line.lower()
        if any(neg in lowered for neg in _NEGATIVE_KEYWORDS):
            return []

        has_keyword = any(kw in lowered for kw in _CREDENTIAL_KEYWORDS)
        results: List[EntropyCandidate] = []

        for match in _TOKEN_RE.finditer(line):
            token = match.group(0)
            if not self._is_candidate(token):
                continue

            # 고정 길이 hex digest 는 커밋 SHA·무결성 값일 가능성이 높다.
            # 같은 줄에 자격 증명 키워드가 있을 때만 후보로 남긴다.
            if _DIGEST_RE.match(token) and not has_keyword:
                continue

            charset, threshold = self._charset_of(token)
            if charset is None:
                continue

            # 키워드가 함께 있으면 임계값을 약간 낮춰 민감도를 올린다.
            effective_threshold = threshold - 0.3 if has_keyword else threshold
            entropy = shannon_entropy(
                token, BASE64_CHARS if charset == "base64" else HEX_CHARS
            )
            if entropy < effective_threshold:
                continue

            results.append(
                EntropyCandidate(
                    value=token,
                    line_number=line_number,
                    start=match.start(),
                    end=match.end(),
                    entropy=round(entropy, 3),
                    charset=charset,
                    severity=Severity.MEDIUM if has_keyword else Severity.LOW,
                )
            )
        return results

    def scan_text(self, text: str) -> List[EntropyCandidate]:
        candidates: List[EntropyCandidate] = []
        for idx, line in enumerate(text.splitlines(), start=1):
            if len(line) > 4096:  # minified 등 초장문 라인은 건너뛴다
                continue
            candidates.extend(self.scan_line(line, idx))
        return candidates

    # ------------------------------------------------------------------
    def _is_candidate(self, token: str) -> bool:
        if not (self.min_length <= len(token) <= self.max_length):
            return False
        if _ALL_DIGITS_RE.match(token) or _UUID_RE.match(token):
            return False
        if _SNAKE_OR_KEBAB_RE.match(token):  # some_long_variable_name
            return False
        lowered = token.lower()
        if any(ph in lowered for ph in PLACEHOLDER_TOKENS):
            return False
        # 한 종류 문자만 반복되는 값 (aaaa..., 0000...)
        if len(set(token)) <= 3:
            return False
        return True

    def _charset_of(self, token: str) -> Tuple[Optional[str], float]:
        chars: Set[str] = set(token)
        if chars <= HEX_CHARS and len(token) >= 32:
            return "hex", self.hex_threshold
        if chars <= BASE64_CHARS:
            return "base64", self.base64_threshold
        return None, 0.0
