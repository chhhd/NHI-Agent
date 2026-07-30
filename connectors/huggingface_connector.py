"""Hugging Face Hub API Connector.

Access Token 유효성·권한(role)·접근 가능한 org 를 조회한다.
`GET /api/whoami-v2` 가 토큰 소유자와 권한 정보를 반환한다.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from connectors.base_connector import BaseConnector, ConnectorError
from core.config import _env
from core.models import CredentialStatus

logger = logging.getLogger(__name__)


class HuggingFaceConnector(BaseConnector):
    """Hugging Face Hub Connector."""

    provider = "huggingface"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        base = api_base or _env("HUGGINGFACE_API_BASE", "https://huggingface.co")
        super().__init__(
            base_url=base,
            token=token or _env("HUGGINGFACE_TOKEN"),
            client=client,
            **kwargs,
        )

    def default_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "nhi-secret-agent/1.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    # ------------------------------------------------------------------
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        status = CredentialStatus(provider=self.provider)

        try:
            who = self.get("/api/whoami-v2", headers=headers).json()
        except ConnectorError as exc:
            status.active = False if exc.status_code == 401 else None
            status.revoked = exc.status_code == 401
            status.error = exc.message
            return status

        auth = who.get("auth", {})
        access_token = auth.get("accessToken", {})
        # 토큰 역할(read/write/fineGrained)을 scope 로 노출
        role = access_token.get("role")
        fine_grained = access_token.get("fineGrained")

        status.active = True
        status.revoked = False
        status.raw_scopes = self._scopes(role, fine_grained)
        status.account = {
            "name": who.get("name"),
            "type": who.get("type"),
            "email": who.get("email"),
            "token_name": access_token.get("displayName"),
            "token_role": role,
        }
        status.accessible_resources = [
            {"name": org.get("name"), "role": (org.get("roleInOrg") or org.get("role"))}
            for org in who.get("orgs", [])
        ]
        return status

    @staticmethod
    def _scopes(role: Optional[str], fine_grained: Any) -> List[str]:
        if isinstance(fine_grained, dict):
            scopes: List[str] = []
            for scope in fine_grained.get("scoped", []):
                perms = scope.get("permissions", [])
                scopes.extend(perms)
            global_perms = fine_grained.get("global", [])
            scopes.extend(global_perms)
            if scopes:
                return sorted(set(scopes))
        return [role] if role else []
