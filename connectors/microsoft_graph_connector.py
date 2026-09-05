"""Microsoft Graph 읽기 전용 NHI Discovery Connector.

서비스 주체, Owner, delegated OAuth grant, application role assignment를 수집해
공급자 중립 ``SaaSNHIInput`` 으로 정규화한다. Client secret이나 access token은
반환값과 로그에 절대 포함하지 않는다.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import httpx

from connectors.base_connector import AuthenticationError, BaseConnector, ConnectorError
from core.config import get_settings
from core.inventory_models import SaaSAccessResource, SaaSNHIInput
from core.models import CredentialStatus
from core.nhi_models import NHIType


_TENANT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class MicrosoftGraphConnector(BaseConnector):
    """Microsoft Entra service principal 인벤토리를 조회한다."""

    provider = "microsoft"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_base: Optional[str] = None,
        login_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        settings = get_settings().microsoft
        super().__init__(
            base_url=api_base or settings.api_base,
            token=token or settings.access_token,
            client=client,
            **kwargs,
        )
        self.tenant_id = tenant_id or settings.tenant_id
        self.client_id = client_id or settings.client_id
        self.client_secret = client_secret or settings.client_secret
        self.login_base = (login_base or settings.login_base).rstrip("/")

    def default_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "nhi-secret-agent/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _ensure_access_token(self) -> str:
        if self.token:
            return self.token
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise AuthenticationError(
                "Microsoft Graph 인증 설정이 없습니다. access token 또는 tenant/client 자격 증명이 필요합니다.",
                status_code=401,
            )
        if not _TENANT_RE.fullmatch(self.tenant_id):
            raise AuthenticationError("MICROSOFT_TENANT_ID 형식이 올바르지 않습니다.", status_code=401)

        url = f"{self.login_base}/{self.tenant_id}/oauth2/v2.0/token"
        try:
            response = self.client.post(
                url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise AuthenticationError(f"Microsoft OAuth token 요청 실패: {exc}") from exc

        if response.status_code >= 400:
            payload = self._safe_json(response)
            message = self._error_message(payload) or "token endpoint 오류"
            raise AuthenticationError(
                f"Microsoft OAuth 인증 실패: {message}",
                status_code=response.status_code,
            )
        payload = response.json()
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise AuthenticationError("Microsoft OAuth 응답에 access_token이 없습니다.")
        self.token = token
        return token

    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        status = CredentialStatus(provider=self.provider)
        try:
            access_token = token or self._ensure_access_token()
            payload = self.get(
                "/servicePrincipals",
                params={"$top": 1, "$select": "id"},
                headers={"Authorization": f"Bearer {access_token}"},
            ).json()
        except ConnectorError as exc:
            status.active = False if exc.status_code == 401 else None
            status.revoked = exc.status_code == 401
            status.error = exc.message
            return status

        status.active = True
        status.revoked = False
        status.account = {
            "tenant_id": self.tenant_id or None,
            "service_principal_visible": bool(payload.get("value")),
        }
        return status

    def discover_service_principals(self, *, limit: int = 25) -> List[SaaSNHIInput]:
        """서비스 주체와 권한을 수집한다. Graph 변경 작업은 수행하지 않는다."""
        self._ensure_access_token()
        capped = min(max(limit, 1), 100)
        principals = self._collect(
            "/servicePrincipals",
            params={
                "$top": min(capped, 100),
                "$select": (
                    "id,appId,displayName,servicePrincipalType,accountEnabled,"
                    "createdDateTime,keyCredentials,passwordCredentials,tags,appRoles"
                ),
            },
            limit=capped,
        )
        grants = self._collect(
            "/oauth2PermissionGrants",
            params={"$top": 999},
            limit=5000,
        )
        grants_by_client: Dict[str, List[Dict[str, Any]]] = {}
        for grant in grants:
            client_id = str(grant.get("clientId") or "")
            if client_id:
                grants_by_client.setdefault(client_id, []).append(grant)

        details = self._batch_details(principals)
        role_catalog = self._role_catalog(principals)
        resource_names = {
            str(item.get("id")): str(item.get("displayName") or item.get("appId") or item.get("id"))
            for item in principals
            if item.get("id")
        }
        return [
            self._to_inventory(
                principal,
                grants_by_client.get(str(principal.get("id")), []),
                details.get(str(principal.get("id")), {}),
                role_catalog,
                resource_names,
            )
            for principal in principals
        ]

    def _collect(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        limit: int,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        next_path: Optional[str] = path
        next_params = params
        while next_path and len(items) < limit:
            payload = self.get(next_path, params=next_params).json()
            items.extend(item for item in payload.get("value", []) if isinstance(item, dict))
            candidate = payload.get("@odata.nextLink")
            next_path = self._trusted_next_link(candidate)
            next_params = None
        return items[:limit]

    def _trusted_next_link(self, value: Any) -> Optional[str]:
        if not isinstance(value, str) or not value:
            return None
        if value.startswith("/") or value.startswith(f"{self.base_url}/"):
            return value
        raise ConnectorError("Microsoft Graph pagination URL의 호스트가 예상과 다릅니다.")

    def _batch_details(self, principals: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        rows = list(principals)
        details: Dict[str, Dict[str, Any]] = {
            str(item.get("id")): {"owners": [], "assignments": [], "errors": []}
            for item in rows
            if item.get("id")
        }
        for offset in range(0, len(rows), 10):
            requests: List[Dict[str, str]] = []
            request_map: Dict[str, Tuple[str, str]] = {}
            for index, principal in enumerate(rows[offset : offset + 10]):
                principal_id = str(principal.get("id") or "")
                if not principal_id:
                    continue
                encoded_id = quote(principal_id, safe="")
                owner_id = f"owner-{index}"
                role_id = f"role-{index}"
                requests.extend(
                    [
                        {
                            "id": owner_id,
                            "method": "GET",
                            "url": (
                                f"/servicePrincipals/{encoded_id}/owners"
                                "?$select=id,displayName,userPrincipalName"
                            ),
                        },
                        {
                            "id": role_id,
                            "method": "GET",
                            "url": f"/servicePrincipals/{encoded_id}/appRoleAssignments",
                        },
                    ]
                )
                request_map[owner_id] = (principal_id, "owners")
                request_map[role_id] = (principal_id, "assignments")
            if not requests:
                continue
            payload = self.post("/$batch", json={"requests": requests}).json()
            for response in payload.get("responses", []):
                mapping = request_map.get(str(response.get("id")))
                if mapping is None:
                    continue
                principal_id, field = mapping
                status = int(response.get("status") or 500)
                body = response.get("body") if isinstance(response.get("body"), dict) else {}
                if status < 400:
                    details[principal_id][field] = [
                        item for item in body.get("value", []) if isinstance(item, dict)
                    ]
                else:
                    details[principal_id]["errors"].append(
                        {"field": field, "status": status}
                    )
        return details

    @staticmethod
    def _role_catalog(principals: Iterable[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
        catalog: Dict[Tuple[str, str], str] = {}
        for principal in principals:
            resource_id = str(principal.get("id") or "")
            for role in principal.get("appRoles") or []:
                if not isinstance(role, dict):
                    continue
                role_id = str(role.get("id") or "")
                value = str(role.get("value") or "")
                if resource_id and role_id and value:
                    catalog[(resource_id, role_id)] = value
        return catalog

    @staticmethod
    def _credential_dates(principal: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        credentials = [
            item
            for key in ("keyCredentials", "passwordCredentials")
            for item in (principal.get(key) or [])
            if isinstance(item, dict)
        ]
        starts = sorted(str(item["startDateTime"]) for item in credentials if item.get("startDateTime"))
        ends = sorted(str(item["endDateTime"]) for item in credentials if item.get("endDateTime"))
        return (starts[-1] if starts else None, ends[-1] if ends else None)

    def _to_inventory(
        self,
        principal: Dict[str, Any],
        grants: List[Dict[str, Any]],
        details: Dict[str, Any],
        role_catalog: Dict[Tuple[str, str], str],
        resource_names: Dict[str, str],
    ) -> SaaSNHIInput:
        scopes: List[str] = []
        resources: Dict[str, SaaSAccessResource] = {}
        for grant in grants:
            scopes.extend(str(grant.get("scope") or "").split())
            resource_id = str(grant.get("resourceId") or "")
            if resource_id:
                name = resource_names.get(resource_id, resource_id)
                resources.setdefault(
                    resource_id,
                    SaaSAccessResource(
                        name=name,
                        resource_type="microsoft_api",
                        is_sensitive=self._sensitive_scope(str(grant.get("scope") or "")),
                    ),
                )

        for assignment in details.get("assignments") or []:
            resource_id = str(assignment.get("resourceId") or "")
            role_id = str(assignment.get("appRoleId") or "")
            scope = role_catalog.get((resource_id, role_id)) or f"appRole:{role_id}"
            scopes.append(scope)
            name = str(
                assignment.get("resourceDisplayName")
                or resource_names.get(resource_id)
                or resource_id
                or "Microsoft API"
            )
            resources.setdefault(
                resource_id or name,
                SaaSAccessResource(
                    name=name,
                    resource_type="microsoft_api",
                    is_sensitive=self._sensitive_scope(scope),
                ),
            )

        owners = details.get("owners") or []
        owner_names = [
            str(item.get("userPrincipalName") or item.get("displayName") or item.get("id"))
            for item in owners
            if isinstance(item, dict)
        ]
        rotated_at, expires_at = self._credential_dates(principal)
        raw_type = str(principal.get("@odata.type") or "").lower()
        tags = " ".join(str(tag) for tag in principal.get("tags") or []).lower()
        nhi_type = (
            NHIType.AI_AGENT_CREDENTIAL
            if "agentidentity" in raw_type or "agent" in tags
            else NHIType.MICROSOFT_SERVICE_PRINCIPAL
        )
        display_name = str(principal.get("displayName") or principal.get("appId") or principal["id"])
        return SaaSNHIInput(
            provider=self.provider,
            nhi_id=str(principal["id"]),
            nhi_name=display_name,
            nhi_type=nhi_type,
            owner=owner_names[0] if len(owner_names) == 1 else None,
            active=principal.get("accountEnabled"),
            raw_scopes=list(dict.fromkeys(scope for scope in scopes if scope)),
            resources=list(resources.values()),
            connected_services=["Microsoft 365"],
            account={
                "app_id": principal.get("appId"),
                "service_principal_type": principal.get("servicePrincipalType"),
                "owners": owner_names,
                "detail_errors": details.get("errors") or [],
            },
            created_at=principal.get("createdDateTime"),
            expires_at=expires_at,
            last_rotated_at=rotated_at,
        )

    @staticmethod
    def _sensitive_scope(scope: str) -> bool:
        lowered = scope.lower()
        return any(
            marker in lowered
            for marker in ("mail", "files", "sites", "directory", "user", "group", "role")
        )
