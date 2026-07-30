"""Notion API Connector.

Integration Token 유효성과 접근 가능한 워크스페이스/리소스를 조회한다.
Notion 은 OAuth Scope 개념 대신 Integration 단위 권한을 쓰므로
`raw_scopes` 에는 봇 능력(bot capabilities)을 담는다.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from connectors.base_connector import BaseConnector, ConnectorError
from core.config import _env
from core.models import CredentialStatus

logger = logging.getLogger(__name__)

_NOTION_VERSION = "2022-06-28"


class NotionConnector(BaseConnector):
    """Notion API Connector."""

    provider = "notion"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        base = api_base or _env("NOTION_API_BASE", "https://api.notion.com/v1")
        super().__init__(
            base_url=base,
            token=token or _env("NOTION_TOKEN"),
            client=client,
            **kwargs,
        )

    def default_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Notion-Version": _NOTION_VERSION,
            "User-Agent": "nhi-secret-agent/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    # ------------------------------------------------------------------
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        status = CredentialStatus(provider=self.provider)

        # `GET /users/me` 는 토큰에 연결된 봇 정보를 반환한다.
        try:
            me = self.get("/users/me", headers=headers).json()
        except ConnectorError as exc:
            status.active = False if exc.status_code in (401, 403) else None
            status.revoked = exc.status_code == 401
            status.error = exc.message
            return status

        bot = me.get("bot", {})
        owner = bot.get("owner", {})
        status.active = True
        status.revoked = False
        # 봇 능력을 scope 유사 정보로 노출
        capabilities = bot.get("workspace_capabilities") or bot.get("capabilities") or {}
        status.raw_scopes = [k for k, v in capabilities.items() if v] if isinstance(capabilities, dict) else []
        status.account = {
            "bot_id": me.get("id"),
            "name": me.get("name"),
            "workspace_name": bot.get("workspace_name"),
            "owner_type": owner.get("type"),
        }
        status.accessible_resources = self._sample_shared_content(headers)
        return status

    def _sample_shared_content(self, headers: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Integration 에 공유된 페이지/DB 표본 (영향 범위 파악용)."""
        try:
            payload = self.post(
                "/search",
                headers=headers,
                json={"page_size": 20},
            ).json()
        except ConnectorError as exc:
            logger.info("notion search 생략: %s", exc)
            return []
        results = []
        for item in payload.get("results", []):
            results.append(
                {
                    "id": item.get("id"),
                    "object": item.get("object"),
                    "url": item.get("url"),
                }
            )
        return results
