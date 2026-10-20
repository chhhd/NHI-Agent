"""감사 로그의 개인정보를 목적에 필요한 최소 수준으로 줄인다.

원본 actor login, IP 주소, User-Agent 문자열은 저장 계층으로 전달하지 않는다.
NHI 상관분석에 필요한 동일성은 HMAC 가명값으로 유지하고, User-Agent는 제품군만
남긴다. 설정 키가 없으면 프로세스 수명 동안만 안정적인 임시 키를 사용한다.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass
from typing import Optional

from core.config import PrivacySettings, get_settings


_EPHEMERAL_KEY = secrets.token_bytes(32)


@dataclass(frozen=True)
class PrivacySummary:
    mode: str
    pseudonymization_stable: bool
    raw_audit_payload_persisted: bool = False
    raw_actor_persisted: bool = False
    raw_ip_persisted: bool = False
    raw_user_agent_persisted: bool = False

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "pseudonymization_stable": self.pseudonymization_stable,
            "raw_audit_payload_persisted": self.raw_audit_payload_persisted,
            "raw_actor_persisted": self.raw_actor_persisted,
            "raw_ip_persisted": self.raw_ip_persisted,
            "raw_user_agent_persisted": self.raw_user_agent_persisted,
        }


class PrivacyProtector:
    """식별자 가명처리와 네트워크·클라이언트 정보 최소화."""

    def __init__(self, settings: Optional[PrivacySettings] = None) -> None:
        self.settings = settings or get_settings().privacy
        configured = self.settings.pseudonymization_key.encode("utf-8")
        if configured and len(configured) < 32:
            raise ValueError(
                "NHI_PRIVACY_PSEUDONYMIZATION_KEY는 32바이트 이상이어야 합니다."
            )
        self._key = configured or _EPHEMERAL_KEY
        self.stable = bool(configured)
        requested_mode = (self.settings.mode or "strict").strip().lower()
        self.mode = requested_mode if requested_mode == "strict" else "strict"

    def pseudonymize(self, value: object, *, namespace: str) -> str:
        text = str(value or "").strip()
        if not text:
            return f"{namespace}:unknown"
        digest = hmac.new(
            self._key,
            f"{namespace}\x00{text}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:24]
        return f"{namespace}:{digest}"

    def minimize_ip(self, value: object) -> Optional[str]:
        """원 IP 대신 축약 네트워크를 다시 가명처리해 저장한다."""
        text = str(value or "").strip()
        if not text:
            return None
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return self.pseudonymize(text, namespace="network")
        prefix = 24 if address.version == 4 else 48
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        return self.pseudonymize(str(network), namespace="network")

    @staticmethod
    def user_agent_family(value: object) -> Optional[str]:
        """상세 버전·OS 문자열을 버리고 보안 분석에 필요한 제품군만 남긴다."""
        text = str(value or "").strip().lower()
        if not text:
            return None
        if "github-actions" in text or "actions/runner" in text:
            return "github-actions"
        if "dependabot" in text:
            return "dependabot"
        if "curl/" in text:
            return "curl"
        if "python" in text or "octokit" in text or "github-api" in text:
            return "api-client"
        if any(name in text for name in ("mozilla/", "chrome/", "safari/", "firefox/")):
            return "browser"
        return "other"

    def summary(self) -> PrivacySummary:
        return PrivacySummary(
            mode=self.mode,
            pseudonymization_stable=self.stable,
        )


__all__ = ["PrivacyProtector", "PrivacySummary"]
