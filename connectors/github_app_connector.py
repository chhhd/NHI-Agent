"""GitHub App 인증 Connector.

담당 기능 (현재 단계)
  * App 레벨 JWT(RS256) 생성
  * `GET /app` 조회 — App 자체의 식별 정보와 선언된 권한 확인
  * `GET /app/installations` 조회 — 이 App 이 설치된 Installation 목록 (페이지네이션)
  * `POST /app/installations/{id}/access_tokens` — Installation Access Token 발급
    (만료 임박 전까지 installation_id 별로 캐싱)
  * `GET /installation/repositories` — Installation 에 실제 연결된 저장소 목록 (페이지네이션)

이 모듈은 아직 `agents/inventory_adapter.py`/`agents/pipeline.py` 등 분석 계층에
연결되어 있지 않다 — 순수 수집(Connector) 기능만 제공한다.

기존 `GitHubConnector` (PAT 경로) 와는 완전히 분리된 클래스다 — PAT 경로의
동작·인증 방식에는 영향을 주지 않는다. 다만 요청/재시도/Rate Limit/오류
분류(`AuthenticationError` 등)는 `BaseConnector` 를 상속해 그대로 재사용한다.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from connectors.base_connector import AuthenticationError, BaseConnector, ConnectorError
from core.config import GitHubAppSettings, get_settings
from core.models import CredentialStatus

logger = logging.getLogger(__name__)

#: GitHub 요구사항 — App JWT 는 발급 시각 기준 최대 10분(600초)까지만 유효할 수 있다.
_MAX_EXP_SECONDS = 600
#: 기기 간 시계 오차를 보정하기 위해 `iat` 를 과거로 당기는 여유값 (GitHub 권장값).
_CLOCK_DRIFT_LEEWAY_SECONDS = 60
#: `iat` 를 과거로 당긴 만큼을 제외하고도 10분 한도에 여유를 두기 위한 유효 구간.
#: (현재 시각 기준으로는 480초 뒤 만료 — 600초 한도 대비 120초 안전 여유)
_TOKEN_TTL_SECONDS = _MAX_EXP_SECONDS - _CLOCK_DRIFT_LEEWAY_SECONDS - 120

#: Installation Access Token 은 GitHub 에서 발급 후 1시간 유효하다.
#: 만료까지 이 시간(초) 이하로 남으면 캐시를 쓰지 않고 재발급한다.
_INSTALLATION_TOKEN_REFRESH_BUFFER_SECONDS = 60


def _b64url_encode(data: bytes) -> str:
    """JWT 규격의 base64url (패딩 없음) 인코딩."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_github_timestamp(value: Any) -> Optional[datetime]:
    """GitHub 의 ISO8601(`...Z`) 응답 필드를 tz-aware datetime 으로 변환한다.

    파싱할 수 없으면 `None` 을 반환한다 — 호출부는 이 경우 캐시를 신뢰하지
    않고 매번 재발급하도록 보수적으로 처리한다.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class GitHubAppConnector(BaseConnector):
    """GitHub App 인증 전용 Connector.

    현재는 App 레벨 JWT 생성, `GET /app`, `GET /app/installations` 조회,
    Installation Access Token 발급, `GET /installation/repositories` 조회만
    제공한다.
    """

    provider = "github_app"

    def __init__(
        self,
        settings: Optional[GitHubAppSettings] = None,
        *,
        client: Optional[httpx.Client] = None,
        **kwargs: Any,
    ) -> None:
        app_settings = settings or get_settings().github_app
        # App 인증은 고정 토큰이 아니라 요청마다 새로 서명하는 JWT 를 쓰므로,
        # BaseConnector 의 정적 `token` 대신 `default_headers()` 를 덮어써서 넣는다.
        super().__init__(base_url=app_settings.api_base, token=None, client=client, **kwargs)
        self.settings = app_settings
        # installation_id → {"result": {...}, "expires_at": datetime | None}
        # Installation 토큰 자체(문자열)는 `result["token"]` 안에만 존재한다.
        self._installation_tokens: Dict[int, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    def default_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "nhi-secret-agent/1.0",
            "Authorization": f"Bearer {self.generate_jwt()}",
        }
        return headers

    # ------------------------------------------------------------------
    def generate_jwt(self, *, now: Optional[int] = None) -> str:
        """GitHub App 인증용 JWT(RS256) 를 생성해 반환한다.

        Claim 구성
          * `iss` — App ID
          * `iat` — 현재 시각보다 60초 이전 (시계 오차 보정)
          * `exp` — `iat` 로부터 짧게 설정해 GitHub 의 10분 한도를 여유 있게 지킨다.

        설정이 비어 있거나 개인키 형식이 잘못된 경우 `AuthenticationError` 를
        던진다. 개인키 원문이나 생성된 토큰은 어떤 예외 메시지·로그에도
        포함하지 않는다.
        """
        app_id = self.settings.app_id.strip()
        if not app_id:
            raise AuthenticationError(
                "GitHub App ID가 설정되지 않았습니다 (GITHUB_APP_ID)",
                status_code=401,
            )

        private_key_pem = self.settings.private_key
        if not private_key_pem.strip():
            raise AuthenticationError(
                "GitHub App private key가 설정되지 않았습니다 "
                "(GITHUB_APP_PRIVATE_KEY 또는 GITHUB_APP_PRIVATE_KEY_PATH)",
                status_code=401,
            )

        private_key = self._load_private_key(private_key_pem)

        reference_time = int(time.time()) if now is None else int(now)
        issued_at = reference_time - _CLOCK_DRIFT_LEEWAY_SECONDS
        expires_at = issued_at + _TOKEN_TTL_SECONDS

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"iat": issued_at, "exp": expires_at, "iss": app_id}
        signing_input = ".".join(
            _b64url_encode(json.dumps(part, separators=(",", ":"), sort_keys=True).encode("utf-8"))
            for part in (header, payload)
        )

        try:
            signature = private_key.sign(
                signing_input.encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception as exc:
            # 서명 단계 실패는 키 자체가 유효해도 발생할 수 있다(예: 손상된 키 객체).
            # 원인 메시지에 키 내용이 섞여 있을 가능성을 차단하기 위해 고정 문구만 노출한다.
            raise AuthenticationError(
                "GitHub App JWT 서명에 실패했습니다", status_code=401
            ) from exc

        return f"{signing_input}.{_b64url_encode(signature)}"

    # ------------------------------------------------------------------
    @staticmethod
    def _load_private_key(pem_text: str) -> rsa.RSAPrivateKey:
        """PEM 텍스트를 RSA 개인키로 로드한다. 실패 시 `AuthenticationError`.

        `cryptography` 가 던지는 원본 예외 메시지는 키 내용을 담지 않지만,
        방어적으로 고정 문구의 새 예외로 감싸 노출 표면을 최소화한다.
        """
        try:
            key = serialization.load_pem_private_key(
                pem_text.encode("utf-8"), password=None
            )
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise AuthenticationError(
                "GitHub App private key 형식이 올바르지 않습니다", status_code=401
            ) from exc

        if not isinstance(key, rsa.RSAPrivateKey):
            raise AuthenticationError(
                "GitHub App private key는 RSA 키여야 합니다 (RS256)", status_code=401
            )
        return key

    # ------------------------------------------------------------------
    # GitHub API
    # ------------------------------------------------------------------
    def get_app_info(self) -> Dict[str, Any]:
        """`GET /app` — 이 GitHub App 자체의 식별 정보와 선언된 최대 권한을 조회한다.

        `generate_jwt()` 로 매 요청마다 새로 서명한 JWT 를 `Authorization` 헤더에
        실어 호출한다 (`default_headers()` 참고). 인증·권한·Rate Limit 오류는
        `BaseConnector.request()` 가 기존 Connector 들과 동일하게
        `AuthenticationError` / `PermissionDeniedError` / `RateLimitError` 로
        분류한다. 반환값에는 필요한 필드만 담고, 원본 응답 전체·요청 헤더(JWT
        포함)는 노출하지 않는다.
        """
        response = self.get("/app")
        payload = self._safe_json(response)
        if not isinstance(payload, dict):
            raise ConnectorError("GitHub App API 응답이 올바르지 않습니다", status_code=502)

        return {
            "id": payload.get("id"),
            "slug": payload.get("slug"),
            "name": payload.get("name"),
            "owner": payload.get("owner"),
            "permissions": payload.get("permissions", {}),
        }

    # ------------------------------------------------------------------
    def list_installations(
        self, *, per_page: int = 100, max_pages: int = 20
    ) -> List[Dict[str, Any]]:
        """`GET /app/installations` — 이 App 이 설치된 Installation 목록을 조회한다.

        `Link` 헤더(`rel="next"`)를 따라가며 페이지네이션을 처리한다
        (`GitHubConnector.list_accessible_repositories()` 와 동일한 방식).
        Installation 당 아래 필드만 남기고, `permissions` 는 GitHub 응답을
        그대로 보존한다 — 여기서는 추측·변환하지 않는다(Scope 해석은 별도 단계).
        """
        installations: List[Dict[str, Any]] = []
        next_url: Optional[str] = "/app/installations"

        for page in range(1, max_pages + 1):
            response = self.get(
                next_url,
                params={"per_page": per_page, "page": page}
                if next_url == "/app/installations"
                else None,
            )
            payload = self._safe_json(response)
            if not isinstance(payload, list):
                raise ConnectorError(
                    "GitHub App installations 응답이 올바르지 않습니다", status_code=502
                )
            installations.extend(self._minimal_installation(item) for item in payload)

            match = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link", ""))
            if not match or not payload:
                break
            next_url = match.group(1)

        return installations

    @staticmethod
    def _minimal_installation(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {
                "installation_id": None,
                "account_login": None,
                "account_type": None,
                "repository_selection": None,
                "permissions": {},
                "suspended": False,
            }
        account = payload.get("account")
        permissions = payload.get("permissions")
        return {
            "installation_id": payload.get("id"),
            "account_login": account.get("login") if isinstance(account, dict) else None,
            "account_type": account.get("type") if isinstance(account, dict) else None,
            "repository_selection": payload.get("repository_selection"),
            # GitHub 응답 그대로 — 해석/변환 없음. dict 가 아니면 안전하게 빈 dict.
            "permissions": permissions if isinstance(permissions, dict) else {},
            # GitHub API 는 boolean 대신 `suspended_at`(nullable timestamp) 로 표현한다.
            "suspended": payload.get("suspended_at") is not None,
        }

    # ------------------------------------------------------------------
    def get_installation_access_token(
        self, installation_id: int, *, now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """`POST /app/installations/{installation_id}/access_tokens`.

        `installation_id` 별로 발급받은 토큰을 캐싱하고, 만료까지
        `_INSTALLATION_TOKEN_REFRESH_BUFFER_SECONDS` 이하로 남았을 때만
        재발급한다 (만료 시각을 알 수 없는 경우는 안전하게 매번 재발급).
        App 레벨 JWT 는 `default_headers()` 를 통해 요청마다 새로 서명되어 실린다.

        반환값에는 `token`, `expires_at`, `permissions`, `repository_selection`
        만 담는다. `token` 은 어떤 예외 메시지·로그에도 포함하지 않는다 — 캐시에
        보관되는 값도 이 딕셔너리 안에만 있고 별도로 노출되지 않는다.
        """
        reference = now or datetime.now(timezone.utc)

        cached = self._installation_tokens.get(installation_id)
        if cached is not None and cached["expires_at"] is not None:
            remaining = (cached["expires_at"] - reference).total_seconds()
            if remaining > _INSTALLATION_TOKEN_REFRESH_BUFFER_SECONDS:
                return dict(cached["result"])

        response = self.post(f"/app/installations/{installation_id}/access_tokens")
        payload = self._safe_json(response)
        if not isinstance(payload, dict) or not payload.get("token"):
            raise ConnectorError(
                "GitHub App installation access token 응답이 올바르지 않습니다",
                status_code=502,
            )

        permissions = payload.get("permissions")
        result = {
            "token": payload["token"],
            "expires_at": payload.get("expires_at"),
            "permissions": permissions if isinstance(permissions, dict) else {},
            "repository_selection": payload.get("repository_selection"),
        }
        self._installation_tokens[installation_id] = {
            "result": result,
            "expires_at": _parse_github_timestamp(result["expires_at"]),
        }
        return dict(result)

    # ------------------------------------------------------------------
    def list_installation_repositories(
        self,
        installation_id: int,
        *,
        per_page: int = 100,
        max_pages: int = 20,
        now: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """`GET /installation/repositories` — Installation 에 실제 연결된 저장소 목록.

        `get_installation_access_token()` 으로 발급/캐싱된 Installation Token 을
        `Authorization` 헤더에 실어 호출한다 (App JWT 가 아니다 — `default_headers()`
        가 넣는 JWT 를 이 헤더로 덮어쓴다). 페이지네이션은 `list_installations()` 와
        동일하게 `Link` 헤더(`rel="next"`)를 따라간다. 저장소 당 `full_name`,
        `private`, `owner_login` 만 남긴다.
        """
        token_info = self.get_installation_access_token(installation_id, now=now)
        headers = {"Authorization": f"Bearer {token_info['token']}"}

        repositories: List[Dict[str, Any]] = []
        next_url: Optional[str] = "/installation/repositories"

        for page in range(1, max_pages + 1):
            response = self.get(
                next_url,
                params={"per_page": per_page, "page": page}
                if next_url == "/installation/repositories"
                else None,
                headers=headers,
            )
            payload = self._safe_json(response)
            repos = payload.get("repositories") if isinstance(payload, dict) else None
            if not isinstance(repos, list):
                raise ConnectorError(
                    "GitHub installation repositories 응답이 올바르지 않습니다",
                    status_code=502,
                )
            repositories.extend(self._minimal_installation_repository(item) for item in repos)

            match = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link", ""))
            if not match or not repos:
                break
            next_url = match.group(1)

        return repositories

    @staticmethod
    def _minimal_installation_repository(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {"full_name": None, "private": False, "owner_login": None}
        owner = payload.get("owner")
        return {
            "full_name": payload.get("full_name"),
            "private": payload.get("private", False),
            "owner_login": owner.get("login") if isinstance(owner, dict) else None,
        }

    # ------------------------------------------------------------------
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        """`BaseConnector` 추상 메서드 구현 — `GET /app` 성공 여부로 유효성을 판단한다.

        App 인증은 고정 토큰이 아닌 JWT 이므로 `token` 인자는 사용하지 않는다
        (인터페이스 호환을 위해서만 받는다).
        """
        status = CredentialStatus(provider=self.provider)
        try:
            app_info = self.get_app_info()
        except AuthenticationError as exc:
            status.active = False
            status.revoked = True
            status.error = exc.message
            return status
        except ConnectorError as exc:
            status.active = None
            status.error = exc.message
            return status

        status.active = True
        status.revoked = False
        status.account = {
            "id": app_info["id"],
            "login": app_info["slug"],
            "type": "App",
        }
        return status
