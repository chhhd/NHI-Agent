"""GitLab API Connector.

토큰 유효성·Scope·프로젝트 접근 범위를 조회한다.
GitLab 은 PAT 검증을 위해 `GET /personal_access_tokens/self` 를 제공한다.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from connectors.base_connector import BaseConnector, ConnectorError
from core.config import _env
from core.models import CredentialStatus

logger = logging.getLogger(__name__)


class GitLabConnector(BaseConnector):
    """GitLab REST API v4 Connector."""

    provider = "gitlab"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        base = api_base or _env("GITLAB_API_BASE", "https://gitlab.com/api/v4")
        super().__init__(
            base_url=base,
            token=token or _env("GITLAB_TOKEN"),
            client=client,
            **kwargs,
        )

    def default_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "nhi-secret-agent/1.0"}
        if self.token:
            # GitLab 은 PRIVATE-TOKEN 헤더도 지원하지만 Bearer 로 통일
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    # ------------------------------------------------------------------
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        status = CredentialStatus(provider=self.provider)

        # 1) 토큰 자체 메타데이터 (Scope / 활성 / 만료)
        try:
            pat = self.get("/personal_access_tokens/self", headers=headers).json()
            status.active = pat.get("active", True) and not pat.get("revoked", False)
            status.revoked = pat.get("revoked", False)
            status.raw_scopes = pat.get("scopes", [])
            status.account = {
                "token_name": pat.get("name"),
                "user_id": pat.get("user_id"),
                "expires_at": pat.get("expires_at"),
            }
        except ConnectorError as exc:
            status.active = False if exc.status_code == 401 else None
            status.revoked = exc.status_code == 401
            status.error = exc.message
            return status

        # 2) 사용자 정보 및 접근 가능 프로젝트 표본
        try:
            user = self.get("/user", headers=headers).json()
            status.account.update(
                {"username": user.get("username"), "name": user.get("name"), "id": user.get("id")}
            )
        except ConnectorError as exc:
            logger.info("gitlab 사용자 조회 생략: %s", exc)

        status.accessible_resources = self._sample_projects(headers)
        return status

    def _sample_projects(self, headers: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        try:
            projects = self.get(
                "/projects",
                params={"membership": "true", "per_page": 20, "order_by": "last_activity_at"},
                headers=headers,
            ).json()
        except ConnectorError as exc:
            logger.info("gitlab 프로젝트 조회 생략: %s", exc)
            return []
        return [
            {
                "id": p.get("id"),
                "path_with_namespace": p.get("path_with_namespace"),
                "visibility": p.get("visibility"),
            }
            for p in projects
        ]
