"""외부 API Connector 공통 기반.

모든 Connector 는 아래를 공통으로 제공한다.
  * HTTP 세션 / 타임아웃 / 재시도
  * Rate Limit 처리 (429, Retry-After, X-RateLimit-Reset)
  * 인증 오류(401) / 권한 부족(403) 예외 구분
  * `validate_credential()` — 토큰 유효성 및 폐기 여부 확인
  * `get_scopes()` — OAuth Scope 원본 조회
"""

from __future__ import annotations

import abc
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from core.config import get_settings
from core.models import CredentialStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 예외
# ---------------------------------------------------------------------------
class ConnectorError(Exception):
    """Connector 기본 예외."""

    def __init__(self, message: str, *, status_code: Optional[int] = None, payload: Any = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.payload = payload


class AuthenticationError(ConnectorError):
    """401 — 토큰이 없거나 유효하지 않음 (폐기 포함)."""


class PermissionDeniedError(ConnectorError):
    """403 — 인증은 됐으나 Scope/권한 부족."""


class NotFoundError(ConnectorError):
    """404 — 리소스 없음 또는 접근 불가."""


class RateLimitError(ConnectorError):
    """Rate Limit 초과 (대기 후에도 해소되지 않은 경우)."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class BaseConnector(abc.ABC):
    """외부 SaaS API Connector 추상 클래스."""

    provider: str = "base"

    def __init__(
        self,
        *,
        base_url: str,
        token: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        settings = get_settings()
        self.base_url = base_url.rstrip("/")
        self.token = token or ""
        self.timeout = timeout if timeout is not None else settings.http_timeout
        self.max_retries = max_retries if max_retries is not None else settings.max_retries
        self._client = client
        self._owns_client = client is None

    # -- 컨텍스트 매니저 -------------------------------------------------
    def __enter__(self) -> "BaseConnector":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)
            self._owns_client = True
        return self._client

    # -- 하위 클래스 구현부 ----------------------------------------------
    def default_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "nhi-secret-agent/1.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @abc.abstractmethod
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        """토큰 유효성 / 폐기 여부 / Scope 를 조회한다."""

    def get_scopes(self, token: Optional[str] = None) -> List[str]:
        """OAuth Scope 목록. 기본 구현은 validate_credential 결과를 사용."""
        return self.validate_credential(token).raw_scopes

    # -- 요청 ------------------------------------------------------------
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        """재시도 / Rate Limit 처리를 포함한 HTTP 요청."""
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        merged_headers = {**self.default_headers(), **(headers or {})}

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self.client.request(
                    method, url, params=params, json=json, data=data, headers=merged_headers
                )
            except httpx.TimeoutException as exc:
                last_error = exc
                self._backoff(attempt, reason="timeout")
                continue
            except httpx.HTTPError as exc:
                raise ConnectorError(f"{self.provider} 요청 실패: {exc}") from exc

            # Rate Limit 대응
            wait = self._rate_limit_wait(response)
            if wait is not None:
                if attempt >= self.max_retries:
                    raise RateLimitError(
                        f"{self.provider} Rate Limit 초과 (재시도 {attempt}회 후 실패)",
                        retry_after=wait,
                        status_code=response.status_code,
                    )
                logger.warning("%s rate limit — %.1fs 대기 후 재시도", self.provider, wait)
                time.sleep(wait)
                continue

            # 5xx 는 재시도
            if response.status_code >= 500 and attempt < self.max_retries:
                self._backoff(attempt, reason=f"status={response.status_code}")
                continue

            if raise_for_status:
                self._raise_for_status(response)
            return response

        raise ConnectorError(
            f"{self.provider} 요청이 {self.max_retries}회 재시도 후에도 실패했습니다: {last_error}"
        )

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    # -- 내부 ------------------------------------------------------------
    def _backoff(self, attempt: int, *, reason: str) -> None:
        delay = min(2.0 ** attempt, 30.0)
        logger.warning("%s 재시도 %d회 (%s) — %.1fs 대기", self.provider, attempt + 1, reason, delay)
        time.sleep(delay)

    def _rate_limit_wait(self, response: httpx.Response) -> Optional[float]:
        """Rate Limit 상태이면 대기해야 할 초를 반환, 아니면 None.

        하위 클래스에서 provider 별 헤더 규칙을 덮어쓴다.
        """
        if response.status_code != 429:
            return None
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass
        return 1.0

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return

        payload = self._safe_json(response)
        message = self._error_message(payload) or response.text[:200]

        if response.status_code == 401:
            raise AuthenticationError(
                f"{self.provider} 인증 실패 (토큰 없음/만료/폐기): {message}",
                status_code=401,
                payload=payload,
            )
        if response.status_code == 403:
            raise PermissionDeniedError(
                f"{self.provider} 권한 부족 또는 접근 거부: {message}",
                status_code=403,
                payload=payload,
            )
        if response.status_code == 404:
            raise NotFoundError(
                f"{self.provider} 리소스를 찾을 수 없음: {message}",
                status_code=404,
                payload=payload,
            )
        raise ConnectorError(
            f"{self.provider} API 오류({response.status_code}): {message}",
            status_code=response.status_code,
            payload=payload,
        )

    @staticmethod
    def _safe_json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except Exception:
            return None

    @staticmethod
    def _error_message(payload: Any) -> Optional[str]:
        if isinstance(payload, dict):
            for key in ("message", "error", "error_description", "detail"):
                value = payload.get(key)
                if isinstance(value, str):
                    return value
        return None
