"""Google Workspace OAuth Token 감사 로그 기반 NHI Discovery Connector."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

import httpx

from connectors.base_connector import AuthenticationError, BaseConnector, ConnectorError
from core.config import get_settings
from core.inventory_models import SaaSAccessResource, SaaSNHIInput
from core.models import CredentialStatus
from core.nhi_models import NHIType


class GoogleWorkspaceConnector(BaseConnector):
    """Admin Reports API의 최근 OAuth grant/activity를 읽기 전용으로 수집한다."""

    provider = "google_workspace"
    _TOKEN_ACTIVITY_PATH = "/admin/reports/v1/activity/users/all/applications/token"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        settings = get_settings().google_workspace
        super().__init__(
            base_url=api_base or settings.api_base,
            token=token or settings.access_token,
            client=client,
            **kwargs,
        )

    def _require_token(self, token: Optional[str] = None) -> str:
        value = token or self.token
        if not value:
            raise AuthenticationError(
                "GOOGLE_WORKSPACE_ACCESS_TOKEN이 설정되지 않았습니다.",
                status_code=401,
            )
        return value

    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        status = CredentialStatus(provider=self.provider)
        try:
            access_token = self._require_token(token)
            payload = self.get(
                self._TOKEN_ACTIVITY_PATH,
                params={"maxResults": 1},
                headers={"Authorization": f"Bearer {access_token}"},
            ).json()
        except ConnectorError as exc:
            status.active = False if exc.status_code == 401 else None
            status.revoked = exc.status_code == 401
            status.error = exc.message
            return status

        status.active = True
        status.revoked = False
        status.raw_scopes = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
        status.account = {"oauth_activity_visible": isinstance(payload.get("items", []), list)}
        return status

    def discover_oauth_clients(
        self,
        *,
        max_events: int = 200,
        start_time: Optional[str] = None,
    ) -> List[SaaSNHIInput]:
        """최근 OAuth 활동을 Client ID별로 집계한다.

        Reports API의 보존 기간 안에서 관측된 결과이므로 완전한 현재 인벤토리로
        단정하지 않고 ``account.discovery_source``에 근거를 남긴다.
        """
        self._require_token()
        capped = min(max(max_events, 1), 1000)
        params: Dict[str, Any] = {"maxResults": min(capped, 1000)}
        if start_time:
            params["startTime"] = start_time

        events: List[Dict[str, Any]] = []
        page_token: Optional[str] = None
        while len(events) < capped:
            if page_token:
                params["pageToken"] = page_token
            payload = self.get(self._TOKEN_ACTIVITY_PATH, params=params).json()
            events.extend(item for item in payload.get("items", []) if isinstance(item, dict))
            next_token = payload.get("nextPageToken")
            page_token = str(next_token) if next_token else None
            if not page_token:
                break

        aggregated: Dict[str, Dict[str, Any]] = {}
        for activity in events[:capped]:
            actor = activity.get("actor") if isinstance(activity.get("actor"), dict) else {}
            actor_email = str(actor.get("email") or "")
            event_time = str((activity.get("id") or {}).get("time") or "")
            for event in activity.get("events") or []:
                if not isinstance(event, dict):
                    continue
                params_map = self._event_parameters(event)
                client_id = str(params_map.get("client_id") or "")
                if not client_id:
                    continue
                row = aggregated.setdefault(
                    client_id,
                    {
                        "name": "",
                        "client_type": "",
                        "owners": set(),
                        "scopes": set(),
                        "api_names": set(),
                        "created_at": None,
                        "last_used_at": None,
                        "last_event": "",
                        "last_event_at": "",
                    },
                )
                row["name"] = str(params_map.get("app_name") or row["name"] or client_id)
                row["client_type"] = str(params_map.get("client_type") or row["client_type"])
                if actor_email:
                    row["owners"].add(actor_email)
                row["scopes"].update(self._split_scopes(params_map.get("scope")))
                api_name = str(params_map.get("api_name") or "")
                if api_name:
                    row["api_names"].add(api_name)

                event_name = str(event.get("name") or "").lower()
                if event_name == "authorize" and event_time:
                    if row["created_at"] is None or event_time < row["created_at"]:
                        row["created_at"] = event_time
                if event_name == "activity" and event_time:
                    if row["last_used_at"] is None or event_time > row["last_used_at"]:
                        row["last_used_at"] = event_time
                if event_time >= row["last_event_at"]:
                    row["last_event"] = event_name
                    row["last_event_at"] = event_time

        return [self._to_inventory(client_id, row) for client_id, row in aggregated.items()]

    @staticmethod
    def _event_parameters(event: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for item in event.get("parameters") or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            value: Any = item.get("value")
            if value is None:
                value = item.get("multiValue")
            if value is None:
                value = item.get("intValue")
            if value is None:
                value = item.get("boolValue")
            result[str(item["name"])] = value
        return result

    @staticmethod
    def _split_scopes(value: Any) -> Set[str]:
        if isinstance(value, list):
            values = [str(item) for item in value]
        elif isinstance(value, str):
            values = re.split(r"[\s,]+", value)
        else:
            values = []
        return {item.strip() for item in values if item and item.strip()}

    def _to_inventory(self, client_id: str, row: Dict[str, Any]) -> SaaSNHIInput:
        owners = sorted(str(owner) for owner in row["owners"])
        scopes = sorted(str(scope) for scope in row["scopes"])
        api_names = sorted(str(name) for name in row["api_names"])
        sensitive = any(self._sensitive_scope(scope) for scope in scopes)
        resources = [
            SaaSAccessResource(
                name=name,
                resource_type="google_workspace_api",
                is_sensitive=sensitive,
            )
            for name in (api_names or ["Google Workspace"])
        ]
        last_event = str(row.get("last_event") or "")
        active: Optional[bool]
        if last_event == "revoke":
            active = False
        elif last_event in {"authorize", "activity"}:
            active = True
        else:
            active = None

        return SaaSNHIInput(
            provider=self.provider,
            nhi_id=client_id,
            nhi_name=str(row.get("name") or client_id),
            nhi_type=NHIType.GOOGLE_OAUTH_CLIENT,
            owner=owners[0] if len(owners) == 1 else None,
            active=active,
            raw_scopes=scopes,
            resources=resources,
            connected_services=["Google Workspace"],
            account={
                "client_type": row.get("client_type"),
                "authorized_users": owners,
                "last_event": last_event,
                "last_event_at": row.get("last_event_at"),
                "discovery_source": "admin_reports_oauth_token_activity",
                "inventory_is_complete": False,
            },
            created_at=row.get("created_at"),
            last_used_at=row.get("last_used_at"),
        )

    @staticmethod
    def _sensitive_scope(scope: str) -> bool:
        lowered = scope.lower()
        return any(
            marker in lowered
            for marker in ("gmail", "drive", "directory", "cloud-platform", "admin")
        )

    @staticmethod
    def _error_message(payload: Any) -> Optional[str]:
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            message = payload["error"].get("message")
            if isinstance(message, str):
                return message
        return BaseConnector._error_message(payload)
