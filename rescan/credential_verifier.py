"""탐지된 Secret 의 외부 API 재검증.

탐지 결과(`SecretFinding`)에 다음을 채워 넣는다.
  * credential_active — 아직 살아있는 토큰인가
  * credential_revoked — 폐기되었는가
  * raw_scopes — 부여된 OAuth Scope 원본
  * credential_detail — 소속 워크스페이스/계정, 접근 가능 리소스

주의: 검증은 탐지된 **원문 토큰으로 외부 API 를 호출**하는 행위다.
  - 읽기 전용 메서드(auth.test, /user)만 호출한다.
  - 결과에는 원문을 남기지 않는다.
  - 동일 토큰은 fingerprint 기준으로 1회만 호출한다(캐시).
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, TYPE_CHECKING

from connectors import CONNECTOR_REGISTRY, ConnectorError, get_connector
from core.models import CredentialStatus, SecretFinding
from scanner.pattern_registry import PATTERN_REGISTRY

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from security.secret_store import SecretMaterialStore


class CredentialVerifier:
    """provider 별 Connector 를 이용한 자격 증명 검증기."""

    def __init__(
        self,
        *,
        enabled_providers: Optional[Iterable[str]] = None,
        material_store: Optional["SecretMaterialStore"] = None,
    ) -> None:
        #: 실제 외부 호출을 허용할 provider (기본: Connector 가 구현된 전체)
        self.enabled_providers = set(enabled_providers or CONNECTOR_REGISTRY.keys())
        self.material_store = material_store
        self._cache: Dict[str, CredentialStatus] = {}

    # ------------------------------------------------------------------
    def verify(self, finding: SecretFinding) -> SecretFinding:
        """단일 탐지 결과를 재검증해 상태를 채운다."""
        status = self.check_status(finding)
        if status is None:
            return finding

        finding.credential_active = status.active
        finding.credential_revoked = status.revoked
        finding.raw_scopes = status.raw_scopes
        finding.credential_detail = {
            "account": status.account,
            "accessible_resources": status.accessible_resources,
            "checked_at": status.checked_at,
            "error": status.error,
        }
        return finding

    def verify_all(self, findings: Iterable[SecretFinding]) -> List[SecretFinding]:
        return [self.verify(f) for f in findings]

    # ------------------------------------------------------------------
    def check_status(self, finding: SecretFinding) -> Optional[CredentialStatus]:
        """검증 가능 여부를 판단하고 상태를 조회한다 (fingerprint 캐시)."""
        provider = finding.provider
        if provider not in self.enabled_providers:
            logger.debug("검증 미지원 provider: %s", provider)
            return None

        pattern = PATTERN_REGISTRY.get(finding.secret_type)
        if pattern is not None and not pattern.verifiable:
            logger.debug("검증 대상이 아닌 유형: %s", finding.secret_type)
            return None

        cached = self._cache.get(finding.fingerprint)
        if cached is not None:
            return cached

        if finding.raw_value:
            status = self._call_connector(provider, finding.raw_value)
        elif finding.secret_ref and self.material_store is not None:
            with self.material_store.lease(
                finding.secret_ref,
                purpose="VERIFY",
                actor="credential_verifier",
            ) as lease:
                status = self._call_connector(provider, lease.text)
        else:
            # 재스캔이 아닌 DB 재조회 결과에는 원문 또는 암호화 참조가 필요하다.
            logger.debug("검증 가능한 Secret material 없음 (%s)", finding.fingerprint[:24])
            return None

        self._cache[finding.fingerprint] = status
        return status

    def _call_connector(self, provider: str, token: str) -> CredentialStatus:
        connector = get_connector(provider, token)
        if connector is None:
            return CredentialStatus(provider=provider, error="unsupported_provider")

        try:
            with connector:
                return connector.validate_credential(token)
        except ConnectorError as exc:
            logger.warning("%s 자격 증명 검증 실패: %s", provider, exc)
            return CredentialStatus(
                provider=provider,
                active=False if exc.status_code == 401 else None,
                revoked=exc.status_code == 401,
                error=exc.message,
            )
        except Exception as exc:  # 네트워크 등 예기치 못한 오류
            logger.exception("%s 검증 중 예외", provider)
            return CredentialStatus(provider=provider, error=str(exc))

    # ------------------------------------------------------------------
    def clear_cache(self) -> None:
        self._cache.clear()
