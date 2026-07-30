"""조치 이후 재스캔 및 결과 판정.

절차
  1. Repository 전체(또는 지정 ref)를 다시 스캔한다.
  2. 이전 스캔 결과와 Fingerprint 를 대조해 해결/미해결/재발/신규를 나눈다.
  3. 남아있는 자격 증명은 외부 API 로 활성/폐기 여부와 Scope 변화를 재조회한다.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Sequence, Set

from connectors.github_connector import GitHubConnector
from core.models import (
    RescanReport,
    ResolutionStatus,
    ScanResult,
    ScanTrigger,
    SecretFinding,
)
from rescan.credential_verifier import CredentialVerifier
from scanner.scan_service import SecretScanService

logger = logging.getLogger(__name__)


class Revalidator:
    """재스캔 + 외부 API 재검증 오케스트레이터."""

    def __init__(
        self,
        connector: Optional[GitHubConnector] = None,
        scan_service: Optional[SecretScanService] = None,
        verifier: Optional[CredentialVerifier] = None,
    ) -> None:
        self.connector = connector or GitHubConnector()
        self.scan_service = scan_service or SecretScanService()
        self.verifier = verifier or CredentialVerifier()

    # ------------------------------------------------------------------
    def rescan_repository(
        self,
        full_name: str,
        *,
        ref: Optional[str] = None,
        previous_findings: Sequence[SecretFinding] = (),
        resolved_fingerprints: Optional[Set[str]] = None,
        verify_credentials: bool = True,
    ) -> RescanReport:
        """Repository 전체를 재스캔하고 조치 결과를 판정한다.

        Args:
            resolved_fingerprints: 관리자가 "해결됨" 처리한 Fingerprint 집합.
                여기 포함된 것이 다시 탐지되면 **재발(RECURRED)** 로 분류한다.
        """
        files = self.connector.list_files(full_name, ref=ref)
        targets = self.connector.build_scan_targets(
            full_name, [f["path"] for f in files], ref=ref
        )

        result = self.scan_service.scan_targets(
            targets,
            repository=full_name,
            trigger=ScanTrigger.RESCAN,
            ref=ref,
        )

        if verify_credentials:
            self.verifier.verify_all(result.findings)

        return self.diff(
            full_name,
            previous_findings=previous_findings,
            current=result.findings,
            resolved_fingerprints=resolved_fingerprints or set(),
        )

    # ------------------------------------------------------------------
    def diff(
        self,
        repository: str,
        *,
        previous_findings: Sequence[SecretFinding],
        current: Sequence[SecretFinding],
        resolved_fingerprints: Set[str],
    ) -> RescanReport:
        """이전/현재 탐지 결과를 Fingerprint 기준으로 대조한다."""
        previous_map: Dict[str, SecretFinding] = {f.fingerprint: f for f in previous_findings}
        current_map: Dict[str, SecretFinding] = {f.fingerprint: f for f in current}

        report = RescanReport(repository=repository)

        for fingerprint, finding in current_map.items():
            if fingerprint in resolved_fingerprints:
                finding.status = ResolutionStatus.RECURRED
                report.recurred.append(finding)
            elif fingerprint in previous_map:
                finding.status = ResolutionStatus.UNRESOLVED
                report.unresolved.append(finding)
            else:
                finding.status = ResolutionStatus.NEW
                report.new.append(finding)

        for fingerprint, finding in previous_map.items():
            if fingerprint not in current_map:
                finding.status = ResolutionStatus.RESOLVED
                report.resolved.append(finding)

        logger.info(
            "rescan diff repo=%s resolved=%d unresolved=%d recurred=%d new=%d",
            repository,
            len(report.resolved),
            len(report.unresolved),
            len(report.recurred),
            len(report.new),
        )
        return report

    # ------------------------------------------------------------------
    def recheck_credentials(self, findings: Iterable[SecretFinding]) -> List[SecretFinding]:
        """코드에서 제거됐더라도 토큰 자체가 살아있는지 다시 확인한다.

        "코드에서 지웠다" ≠ "토큰을 폐기했다" 이므로, 해결 처리 전에
        반드시 이 확인을 거쳐야 한다.
        """
        self.verifier.clear_cache()
        return self.verifier.verify_all(findings)

    @staticmethod
    def summarize(report: RescanReport) -> Dict[str, object]:
        """관리자 리포트용 요약.

        코드에서는 사라졌지만 토큰이 여전히 활성인 항목을 별도로 강조한다.
        """
        still_active = [
            f.to_dict()
            for f in report.resolved
            if f.credential_active is True
        ]
        return {
            "repository": report.repository,
            "resolved": len(report.resolved),
            "unresolved": len(report.unresolved),
            "recurred": len(report.recurred),
            "new": len(report.new),
            "removed_from_code_but_still_active": still_active,
            "generated_at": report.generated_at,
        }


def scan_result_to_fingerprints(result: ScanResult) -> Set[str]:
    """ScanResult → Fingerprint 집합 (다음 스캔의 비교 기준)."""
    return {f.fingerprint for f in result.findings}
