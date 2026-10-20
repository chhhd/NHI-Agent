"""관리자 신원 · 역할.

기존에는 모든 관리자가 하나의 공유 API Key 를 쓰고 `actor` 이름을 요청 본문에 직접 적었다.
그러면 "요청자와 다른 관리자만 승인" 같은 직무 분리 규칙이 이름만 바꿔 쓰면 우회된다.
이 모듈은 관리자별 개인 키로 신원을 확정하고, 역할로 승인 권한을 제한한다.

- 개인 키: ``nhik.<admin_id>.<secret>``. 서버가 생성해 한 번만 보여 주고 SHA-256 digest 만 저장한다.
- 역할: ``ADMIN`` (일반 승인·거부·롤백·격리 해제), ``SECURITY`` (CRITICAL 변경 승인 가능).
- 공유 키(``NHI_ADMIN_API_KEY``)는 **bootstrap(break-glass)** 신원이다. 관리자 계정 관리에 쓰며,
  개인 계정이 하나라도 있거나 ``NHI_REQUIRE_VERIFIED_ADMIN=true`` 이면(strict) 승인 같은
  `actor` 가 필요한 작업에는 쓸 수 없다.

IdP(OIDC/SAML) 연동이 없는 환경을 위한 최소 구현이다. 운영에서는 같은 ``AdminIdentity`` 를
IdP 토큰에서 만들도록 ``AdminDirectory.authenticate`` 만 교체하면 된다.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from storage.base import Storage

ROLE_ADMIN = "ADMIN"
ROLE_SECURITY = "SECURITY"
VALID_ROLES = frozenset({ROLE_ADMIN, ROLE_SECURITY})
#: 일반 승인·거부·롤백·격리 해제를 할 수 있는 역할
OPERATOR_ROLES = frozenset({ROLE_ADMIN, ROLE_SECURITY})

KEY_PREFIX = "nhik"
BOOTSTRAP_ID = "bootstrap"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")


class AdminIdentityError(Exception):
    """인증·권한 실패. ``status`` 는 HTTP 상태 코드에 대응한다."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class AdminIdentity:
    admin_id: str
    roles: FrozenSet[str]
    #: True 면 개인 키로 확정된 신원. False 면 공유 키(bootstrap) 이거나 합성 데모 사용자.
    verified: bool
    via: str  # principal | bootstrap | demo

    def has_any(self, roles: Iterable[str]) -> bool:
        return bool(self.roles & set(roles))


def _digest(secret: str) -> str:
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AdminDirectory:
    def __init__(
        self,
        storage: Storage,
        *,
        bootstrap_key: str = "",
        require_verified: bool = False,
        clock: Callable[[], str] = _now,
    ) -> None:
        self.storage = storage
        self._bootstrap_key = bootstrap_key
        self._require_verified = require_verified
        self._clock = clock

    # -- 상태 ---------------------------------------------------------------
    @property
    def strict(self) -> bool:
        """개인 신원이 필수인가: 설정으로 강제했거나 활성 개인 계정이 하나라도 있다."""
        return self._require_verified or any(
            not item.get("disabled") for item in self.storage.list_admin_principals()
        )

    # -- 인증 ---------------------------------------------------------------
    def authenticate(self, provided: Optional[str]) -> AdminIdentity:
        if not self._bootstrap_key and not self.storage.list_admin_principals():
            raise AdminIdentityError(
                503, "NHI_ADMIN_API_KEY 가 설정되지 않아 민감 작업 API 가 비활성화되어 있습니다."
            )
        if not provided:
            raise AdminIdentityError(401, "올바른 관리자 API Key 가 필요합니다.")
        if self._bootstrap_key and hmac.compare_digest(provided, self._bootstrap_key):
            return AdminIdentity(
                BOOTSTRAP_ID, frozenset({ROLE_ADMIN, ROLE_SECURITY}), False, "bootstrap"
            )
        parts = provided.split(".", 2)
        if len(parts) == 3 and parts[0] == KEY_PREFIX:
            principal = self.storage.get_admin_principal(parts[1])
            expected = (principal or {}).get("key_digest", "")
            # 존재하지 않는 계정에도 같은 비교를 수행해 응답 시간 차이를 줄인다.
            matches = hmac.compare_digest(_digest(parts[2]), expected or _digest(""))
            if principal and matches and not principal.get("disabled"):
                return AdminIdentity(
                    principal["admin_id"], frozenset(principal["roles"]), True, "principal"
                )
        raise AdminIdentityError(401, "올바른 관리자 API Key 가 필요합니다.")

    # -- 계정 관리 (bootstrap 전용) -------------------------------------------
    def create(
        self, admin_id: str, roles: Iterable[str], *, display_name: str = ""
    ) -> Tuple[Dict[str, Any], str]:
        admin_id = (admin_id or "").strip().lower()
        if not _ID_RE.fullmatch(admin_id) or admin_id == BOOTSTRAP_ID:
            raise AdminIdentityError(
                422, "admin_id 는 영문 소문자·숫자·-_ 1~40자여야 하며 'bootstrap' 은 쓸 수 없습니다."
            )
        role_set = self._roles(roles)
        if self.storage.get_admin_principal(admin_id):
            raise AdminIdentityError(409, f"이미 등록된 관리자입니다: {admin_id}")
        key, digest = self._new_key(admin_id)
        principal = {
            "admin_id": admin_id,
            "display_name": display_name or admin_id,
            "roles": sorted(role_set),
            "key_digest": digest,
            "disabled": False,
            "created_at": self._clock(),
            "key_rotated_at": None,
        }
        self.storage.save_admin_principal(principal)
        return self._public(principal), key

    def rotate_key(self, admin_id: str) -> Tuple[Dict[str, Any], str]:
        principal = self._required(admin_id)
        key, digest = self._new_key(admin_id)
        principal.update(key_digest=digest, key_rotated_at=self._clock())
        self.storage.save_admin_principal(principal)
        return self._public(principal), key

    def set_disabled(self, admin_id: str, disabled: bool) -> Dict[str, Any]:
        principal = self._required(admin_id)
        principal["disabled"] = bool(disabled)
        self.storage.save_admin_principal(principal)
        return self._public(principal)

    def list(self) -> List[Dict[str, Any]]:
        return [self._public(item) for item in self.storage.list_admin_principals()]

    # -- 내부 -----------------------------------------------------------------
    @staticmethod
    def _roles(roles: Iterable[str]) -> set:
        role_set = {str(role).strip().upper() for role in roles if str(role).strip()}
        if not role_set:
            raise AdminIdentityError(422, "역할이 하나 이상 필요합니다: " + ", ".join(sorted(VALID_ROLES)))
        unknown = role_set - VALID_ROLES
        if unknown:
            raise AdminIdentityError(
                422, f"알 수 없는 역할: {', '.join(sorted(unknown))} (허용: {', '.join(sorted(VALID_ROLES))})"
            )
        return role_set

    @staticmethod
    def _new_key(admin_id: str) -> Tuple[str, str]:
        secret = secrets.token_urlsafe(32)
        # token_urlsafe 는 '.' 을 만들지 않으므로 파싱이 모호하지 않다.
        return f"{KEY_PREFIX}.{admin_id}.{secret}", _digest(secret)

    def _required(self, admin_id: str) -> Dict[str, Any]:
        principal = self.storage.get_admin_principal((admin_id or "").strip().lower())
        if principal is None:
            raise AdminIdentityError(404, "관리자 계정을 찾을 수 없습니다.")
        return principal

    @staticmethod
    def _public(principal: Dict[str, Any]) -> Dict[str, Any]:
        return {key: value for key, value in principal.items() if key != "key_digest"}


__all__ = [
    "AdminDirectory",
    "AdminIdentity",
    "AdminIdentityError",
    "BOOTSTRAP_ID",
    "KEY_PREFIX",
    "OPERATOR_ROLES",
    "ROLE_ADMIN",
    "ROLE_SECURITY",
    "VALID_ROLES",
]
