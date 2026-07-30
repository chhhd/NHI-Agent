"""Secret Scan 오케스트레이션.

Regex / Entropy 탐지 → 유형 분류 → 문맥 추출 → 마스킹 → Fingerprint → 중복 병합
까지의 전체 파이프라인을 담당한다.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set

from core.config import get_settings
from core.models import (
    CodeContext,
    DetectorType,
    ResolutionStatus,
    ScanResult,
    ScanTarget,
    ScanTrigger,
    SecretFinding,
    Severity,
)
from scanner.entropy_scanner import EntropyCandidate, EntropyScanner
from scanner.fingerprint import build_fingerprint, build_location_fingerprint
from scanner.masking import mask_line, mask_secret, redact_unknown_tokens
from scanner.pattern_registry import PATTERN_REGISTRY
from scanner.regex_scanner import RegexCandidate, RegexScanner, is_scannable_path

logger = logging.getLogger(__name__)

#: Entropy 단독 탐지 결과에 부여하는 유형
UNCLASSIFIED_TYPE = "UNCLASSIFIED_HIGH_ENTROPY"


class SecretScanService:
    """파일 목록을 받아 `ScanResult` 를 만든다."""

    def __init__(
        self,
        *,
        regex_scanner: Optional[RegexScanner] = None,
        entropy_scanner: Optional[EntropyScanner] = None,
        enable_entropy: bool = True,
        context_lines: Optional[int] = None,
        max_file_size: Optional[int] = None,
    ) -> None:
        settings = get_settings().scanner
        self.regex_scanner = regex_scanner or RegexScanner()
        self.entropy_scanner = entropy_scanner or EntropyScanner()
        self.enable_entropy = enable_entropy
        self.context_lines = context_lines if context_lines is not None else settings.context_lines
        self.max_file_size = max_file_size if max_file_size is not None else settings.max_file_size

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------
    def scan_targets(
        self,
        targets: Iterable[ScanTarget],
        *,
        repository: str = "",
        trigger: ScanTrigger = ScanTrigger.MANUAL,
        ref: Optional[str] = None,
        commit_sha: Optional[str] = None,
        pull_request: Optional[int] = None,
        known_fingerprints: Optional[Set[str]] = None,
    ) -> ScanResult:
        """여러 파일을 검사해 하나의 스캔 결과로 묶는다.

        known_fingerprints 를 주면 이전 스캔에 없던 항목만 NEW 로 표시한다.
        """
        result = ScanResult(
            repository=repository,
            trigger=trigger,
            ref=ref,
            commit_sha=commit_sha,
            pull_request=pull_request,
        )

        all_findings: List[SecretFinding] = []
        for target in targets:
            skip_reason = self._skip_reason(target)
            if skip_reason:
                result.skipped_files.append({"path": target.path, "reason": skip_reason})
                continue

            result.scanned_files += 1
            all_findings.extend(self.scan_file(target))

        merged = self.merge_duplicates(all_findings)
        if known_fingerprints:
            for finding in merged:
                if finding.fingerprint in known_fingerprints:
                    finding.status = ResolutionStatus.UNRESOLVED

        result.findings = merged
        result.finished_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "scan finished repo=%s files=%d findings=%d",
            repository,
            result.scanned_files,
            len(result.findings),
        )
        return result

    def scan_file(self, target: ScanTarget) -> List[SecretFinding]:
        """파일 1건 검사."""
        lines = target.content.splitlines()
        findings: List[SecretFinding] = []
        covered: Set[tuple] = set()

        # 1) Regex 탐지 (우선순위 높음 — 유형이 확정됨)
        for candidate in self.regex_scanner.scan_text(target.content):
            findings.append(self._build_regex_finding(candidate, target, lines))
            covered.add((candidate.line_number, candidate.value))

        # 2) Entropy 탐지 (Regex 로 이미 잡힌 값은 제외)
        if self.enable_entropy:
            for candidate in self.entropy_scanner.scan_text(target.content):
                if (candidate.line_number, candidate.value) in covered:
                    continue
                if self._overlaps_regex(candidate, findings):
                    continue
                findings.append(self._build_entropy_finding(candidate, target, lines))

        return findings

    def merge_duplicates(self, findings: Sequence[SecretFinding]) -> List[SecretFinding]:
        """동일 Fingerprint(=동일 Secret)를 하나로 병합한다.

        대표 1건만 남기고 나머지 발생 위치는 `duplicate_locations` 에 모은다.
        """
        merged: Dict[str, SecretFinding] = {}
        for finding in findings:
            existing = merged.get(finding.fingerprint)
            if existing is None:
                merged[finding.fingerprint] = finding
                continue

            existing.occurrence_count += 1
            existing.duplicate_locations.append(
                {
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "location_fingerprint": build_location_fingerprint(
                        finding.secret_type, finding.raw_value, finding.file_path, finding.line_number
                    ),
                }
            )
            # 더 심각한 분류가 나중에 나오면 대표 정보를 갱신
            if _severity_rank(finding.severity) < _severity_rank(existing.severity):
                existing.severity = finding.severity
                existing.secret_type = finding.secret_type
                existing.provider = finding.provider

        return sorted(
            merged.values(),
            key=lambda f: (_severity_rank(f.severity), f.file_path, f.line_number),
        )

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------
    def _skip_reason(self, target: ScanTarget) -> Optional[str]:
        if target.content is None:
            return "content_unavailable"
        if not is_scannable_path(target.path):
            return "unsupported_file_type"
        size = len(target.content.encode("utf-8", errors="ignore"))
        if size > self.max_file_size:
            return f"file_too_large({size}B)"
        if "\x00" in target.content[:8192]:
            return "binary_file"
        return None

    def _build_regex_finding(
        self, candidate: RegexCandidate, target: ScanTarget, lines: List[str]
    ) -> SecretFinding:
        pattern = candidate.pattern
        return SecretFinding(
            secret_type=candidate.secret_type,
            provider=candidate.provider,
            masked_value=mask_secret(candidate.value, keep_prefix=pattern.keep_prefix),
            fingerprint=build_fingerprint(candidate.secret_type, candidate.value),
            file_path=target.path,
            line_number=candidate.line_number,
            detector=DetectorType.REGEX,
            severity=candidate.severity,
            entropy=candidate.entropy,
            match_start=candidate.start,
            match_end=candidate.end,
            context=self._extract_context(
                lines, candidate.line_number, [candidate.value], pattern.keep_prefix
            ),
            _raw_value=candidate.value,
        )

    def _build_entropy_finding(
        self, candidate: EntropyCandidate, target: ScanTarget, lines: List[str]
    ) -> SecretFinding:
        return SecretFinding(
            secret_type=UNCLASSIFIED_TYPE,
            provider="unknown",
            masked_value=mask_secret(candidate.value),
            fingerprint=build_fingerprint(UNCLASSIFIED_TYPE, candidate.value),
            file_path=target.path,
            line_number=candidate.line_number,
            detector=DetectorType.ENTROPY,
            severity=candidate.severity,
            entropy=candidate.entropy,
            match_start=candidate.start,
            match_end=candidate.end,
            context=self._extract_context(lines, candidate.line_number, [candidate.value], None),
            _raw_value=candidate.value,
        )

    def _extract_context(
        self,
        lines: List[str],
        line_number: int,
        secrets: Sequence[str],
        keep_prefix: Optional[int],
    ) -> CodeContext:
        """탐지 지점 앞뒤 문맥을 추출한다. 원문은 모두 마스킹된다."""
        idx = line_number - 1
        start = max(0, idx - self.context_lines)
        end = min(len(lines), idx + self.context_lines + 1)

        def _clean(raw: str) -> str:
            return redact_unknown_tokens(mask_line(raw, secrets, keep_prefix=keep_prefix))[:500]

        return CodeContext(
            before=[_clean(l) for l in lines[start:idx]],
            line=_clean(lines[idx]) if 0 <= idx < len(lines) else "",
            after=[_clean(l) for l in lines[idx + 1 : end]],
        )

    @staticmethod
    def _overlaps_regex(candidate: EntropyCandidate, findings: List[SecretFinding]) -> bool:
        for f in findings:
            if f.line_number != candidate.line_number:
                continue
            if not (candidate.end <= f.match_start or candidate.start >= f.match_end):
                return True
        return False


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }.get(severity, 9)


def classify_secret_type(secret_type: str) -> Dict[str, str]:
    """탐지 유형에 대한 부가 설명 (분석 계층 Context Agent 입력용)."""
    pattern = PATTERN_REGISTRY.get(secret_type)
    if pattern is None:
        return {
            "secret_type": secret_type,
            "provider": "unknown",
            "name": "Unclassified High Entropy String",
            "description": "알려진 패턴과 일치하지 않는 고엔트로피 문자열. 관리자 검토 대상.",
            "verifiable": "false",
        }
    return {
        "secret_type": pattern.id,
        "provider": pattern.provider,
        "name": pattern.name,
        "description": pattern.description,
        "verifiable": "true" if pattern.verifiable else "false",
    }
