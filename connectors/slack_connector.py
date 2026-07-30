"""Slack API Connector.

담당 기능
  * Slack Workspace 연동
  * Bot / App 정보 조회
  * OAuth Scope 조회
  * Token 유효성 확인 (폐기 여부 포함)
  * 접근 가능한 채널 정보 조회

Slack Web API 는 HTTP 200 을 주면서 body 의 `ok: false` 로 오류를 알리므로
`_check_slack_response()` 에서 별도로 예외 매핑을 한다.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from connectors.base_connector import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    PermissionDeniedError,
    RateLimitError,
)
from core.config import get_settings
from core.models import CredentialStatus

logger = logging.getLogger(__name__)

#: 토큰이 더 이상 유효하지 않음을 뜻하는 Slack 오류 코드
REVOKED_ERRORS = {
    "invalid_auth",
    "token_revoked",
    "token_expired",
    "account_inactive",
    "not_authed",
}

#: Scope 부족을 뜻하는 오류 코드
SCOPE_ERRORS = {"missing_scope", "not_allowed_token_type", "no_permission"}

#: 토큰 접두사 → 토큰 종류
TOKEN_KINDS = {
    "xoxb-": "bot",
    "xoxp-": "user",
    "xapp-": "app_level",
    "xoxa-": "workspace_app",
    "xoxe-": "refresh",
}


class SlackConnector(BaseConnector):
    """Slack Web API Connector."""

    provider = "slack"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        settings = get_settings().slack
        super().__init__(
            base_url=api_base or settings.api_base,
            token=token or settings.bot_token,
            client=client,
            **kwargs,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def token_kind(token: str) -> str:
        for prefix, kind in TOKEN_KINDS.items():
            if token.startswith(prefix):
                return kind
        return "unknown"

    def call(
        self,
        method: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Slack API 메서드 호출 (`ok` 검사 포함)."""
        headers = {"Authorization": f"Bearer {token}"} if token else None
        response = self.get(f"/{method}", params=params, headers=headers, raise_for_status=False)
        self._raise_for_status(response)
        payload = response.json()
        self._check_slack_response(method, payload, response)
        return payload

    # ------------------------------------------------------------------
    # Token 유효성 / 폐기 여부
    # ------------------------------------------------------------------
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        """`auth.test` 로 토큰 유효성·Workspace·Scope 를 한 번에 확인한다."""
        target = token or self.token
        status = CredentialStatus(provider=self.provider)

        headers = {"Authorization": f"Bearer {target}"}
        try:
            response = self.get("/auth.test", headers=headers, raise_for_status=False)
        except ConnectorError as exc:
            status.error = exc.message
            return status

        payload = self._safe_json(response) or {}

        if not payload.get("ok"):
            error = payload.get("error", "unknown_error")
            status.active = False
            status.revoked = error in REVOKED_ERRORS
            status.error = error
            logger.info("slack token 무효 (error=%s)", error)
            return status

        status.active = True
        status.revoked = False
        # 부여된 Scope 는 응답 헤더로 내려온다.
        status.raw_scopes = self._parse_scopes(response.headers.get("x-oauth-scopes", ""))
        status.account = {
            "token_kind": self.token_kind(target),
            "team": payload.get("team"),
            "team_id": payload.get("team_id"),
            "user": payload.get("user"),
            "user_id": payload.get("user_id"),
            "bot_id": payload.get("bot_id"),
            "app_id": payload.get("app_id"),
            "url": payload.get("url"),
            "is_enterprise_install": payload.get("is_enterprise_install", False),
        }
        status.accessible_resources = self._safe_channels(target)
        return status

    def is_revoked(self, token: Optional[str] = None) -> bool:
        """Token 폐기 여부 재확인 (조치 후 검증용)."""
        status = self.validate_credential(token)
        if status.revoked is not None:
            return status.revoked
        # 확인 불가한 경우 폐기되지 않은 것으로 간주하지 않는다 (보수적)
        raise ConnectorError(f"Slack Token 상태를 확인할 수 없습니다: {status.error}")

    # ------------------------------------------------------------------
    # 정보 조회
    # ------------------------------------------------------------------
    def get_workspace_info(self, token: Optional[str] = None) -> Dict[str, Any]:
        """Workspace(Team) 정보 조회."""
        payload = self.call("team.info", token=token)
        team = payload.get("team", {})
        return {
            "id": team.get("id"),
            "name": team.get("name"),
            "domain": team.get("domain"),
            "email_domain": team.get("email_domain"),
            "enterprise_id": team.get("enterprise_id"),
        }

    def get_bot_info(self, token: Optional[str] = None, bot_id: Optional[str] = None) -> Dict[str, Any]:
        """Bot 정보 조회. bot_id 를 주지 않으면 auth.test 로 알아낸다."""
        if bot_id is None:
            auth = self.call("auth.test", token=token)
            bot_id = auth.get("bot_id")
        if not bot_id:
            return {}
        payload = self.call("bots.info", params={"bot": bot_id}, token=token)
        bot = payload.get("bot", {})
        return {
            "id": bot.get("id"),
            "name": bot.get("name"),
            "app_id": bot.get("app_id"),
            "user_id": bot.get("user_id"),
            "deleted": bot.get("deleted", False),
            "updated": bot.get("updated"),
        }

    def get_app_info(self, token: Optional[str] = None) -> Dict[str, Any]:
        """App 정보 조회.

        `apps.info` 는 워크스페이스 관리자 토큰에서만 동작하므로,
        실패 시 auth.test 의 app_id 만 반환한다.
        """
        auth = self.call("auth.test", token=token)
        app_id = auth.get("app_id")
        info: Dict[str, Any] = {"app_id": app_id, "team_id": auth.get("team_id")}
        if not app_id:
            return info
        try:
            payload = self.call("apps.info", params={"app": app_id}, token=token)
            app = payload.get("app", {})
            info.update(
                {
                    "name": app.get("name"),
                    "description": app.get("description"),
                    "is_app_directory_approved": app.get("is_app_directory_approved"),
                }
            )
        except (PermissionDeniedError, ConnectorError) as exc:
            info["detail_error"] = str(exc)
        return info

    def get_scopes(self, token: Optional[str] = None) -> List[str]:
        """OAuth Scope 조회 (auth.test 응답 헤더 기반)."""
        return self.validate_credential(token).raw_scopes

    def list_channels(
        self,
        token: Optional[str] = None,
        *,
        types: str = "public_channel,private_channel",
        limit: int = 200,
        max_pages: int = 5,
    ) -> List[Dict[str, Any]]:
        """접근 가능한 채널 목록 조회 (영향 범위 분석용)."""
        channels: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        for _ in range(max_pages):
            params: Dict[str, Any] = {"types": types, "limit": limit, "exclude_archived": True}
            if cursor:
                params["cursor"] = cursor
            payload = self.call("conversations.list", params=params, token=token)

            for ch in payload.get("channels", []):
                channels.append(
                    {
                        "id": ch.get("id"),
                        "name": ch.get("name"),
                        "is_private": ch.get("is_private", False),
                        "is_member": ch.get("is_member", False),
                        "num_members": ch.get("num_members"),
                    }
                )
            cursor = (payload.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                break
        return channels

    def _safe_channels(self, token: str) -> List[Dict[str, Any]]:
        """Scope 부족 등으로 실패해도 전체 검증이 깨지지 않도록 감싼다."""
        try:
            return self.list_channels(token=token, limit=100, max_pages=1)
        except (PermissionDeniedError, ConnectorError) as exc:
            logger.info("채널 목록 조회 생략: %s", exc)
            return []

    # ------------------------------------------------------------------
    # 내부
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_scopes(header_value: str) -> List[str]:
        return [s.strip() for s in header_value.split(",") if s.strip()]

    def _check_slack_response(
        self, method: str, payload: Dict[str, Any], response: httpx.Response
    ) -> None:
        if payload.get("ok"):
            return
        error = payload.get("error", "unknown_error")

        if error in REVOKED_ERRORS:
            raise AuthenticationError(
                f"Slack 인증 실패 ({method}): {error}", status_code=401, payload=payload
            )
        if error in SCOPE_ERRORS:
            needed = payload.get("needed") or payload.get("response_metadata", {}).get("messages")
            raise PermissionDeniedError(
                f"Slack 권한 부족 ({method}): {error} (필요 scope: {needed})",
                status_code=403,
                payload=payload,
            )
        if error == "ratelimited":
            raise RateLimitError(f"Slack Rate Limit ({method})", status_code=429, payload=payload)
        raise ConnectorError(
            f"Slack API 오류 ({method}): {error}",
            status_code=response.status_code,
            payload=payload,
        )

    def _rate_limit_wait(self, response: httpx.Response) -> Optional[float]:
        """Slack 은 429 + Retry-After(초) 로 응답한다."""
        if response.status_code != 429:
            return None
        retry_after = response.headers.get("Retry-After", "1")
        try:
            return min(float(retry_after), 60.0)
        except ValueError:
            return 1.0
