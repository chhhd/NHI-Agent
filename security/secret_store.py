"""AES-256-GCM 기반 Secret material 저장소.

분석 계층은 이 모듈에 의존하지 않는다. 원문이 필요한 자격 증명 검증·조치
실행기만 목적(purpose)과 호출자(actor)를 명시해 짧은 lease 를 얻는다.

현재 구현은 로컬/단일 서버용 필드 암호화다. 운영 환경에서는 동일 인터페이스
뒤에 KMS/Vault envelope-encryption 어댑터를 붙이는 것을 전제로 한다.
"""

from __future__ import annotations

import base64
import json
import os
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, Optional, Union
from uuid import uuid4

from storage.base import Storage


class SecretMaterialError(RuntimeError):
    """암호화 재료 저장·복호화 실패."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecretMaterialError("Secret 만료 시각이 올바르지 않습니다.") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class SecretReference:
    """외부로 노출해도 원문을 포함하지 않는 불투명 참조."""

    secret_id: str
    key_id: str

    def __str__(self) -> str:
        return f"sealed://{self.key_id}/{self.secret_id}"

    @classmethod
    def parse(cls, value: Union[str, "SecretReference"]) -> "SecretReference":
        if isinstance(value, cls):
            return value
        if not value.startswith("sealed://"):
            raise SecretMaterialError("지원하지 않는 Secret reference 형식입니다.")
        remainder = value[len("sealed://") :]
        key_id, separator, secret_id = remainder.partition("/")
        if not separator or not key_id or not secret_id:
            raise SecretMaterialError("잘못된 Secret reference 입니다.")
        return cls(secret_id=secret_id, key_id=key_id)


class SecretLease:
    """복호화된 bytes 를 짧게 보유하고 종료 시 메모리를 덮어쓴다."""

    def __init__(self, plaintext: bytes) -> None:
        self._buffer = bytearray(plaintext)
        self._closed = False

    @property
    def bytes(self) -> bytes:
        if self._closed:
            raise SecretMaterialError("종료된 Secret lease 입니다.")
        return bytes(self._buffer)

    @property
    def text(self) -> str:
        return self.bytes.decode("utf-8")

    def close(self) -> None:
        if self._closed:
            return
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._closed = True

    def __enter__(self) -> "SecretLease":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class SecretMaterialStore(ABC):
    """KMS/Vault 구현으로 교체할 수 있는 Secret material 포트."""

    @abstractmethod
    def seal(
        self,
        plaintext: Union[str, bytes],
        *,
        fingerprint: str,
        allowed_purposes: Iterable[str] = ("VERIFY", "REVOKE", "ROTATE"),
        ttl_seconds: Optional[int] = None,
    ) -> SecretReference:
        ...

    @abstractmethod
    def lease(
        self,
        reference: Union[str, SecretReference],
        *,
        purpose: str,
        actor: str,
    ) -> Iterator[SecretLease]:
        ...

    @abstractmethod
    def destroy(
        self, reference: Union[str, SecretReference], *, actor: str = "system"
    ) -> None:
        ...


class AESGCMSecretMaterialStore(SecretMaterialStore):
    """Storage 의 분리 테이블에 AES-GCM 암호문만 저장한다."""

    algorithm = "AES-256-GCM"
    aad_version = 1

    def __init__(
        self,
        storage: Storage,
        master_key: Union[str, bytes],
        *,
        key_id: str = "local-v1",
        default_ttl_seconds: int = 3600,
    ) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:  # pragma: no cover - 설치 오류 안내
            raise SecretMaterialError(
                "AES-GCM 사용을 위해 requirements.txt 의 cryptography 패키지가 필요합니다."
            ) from exc

        self.storage = storage
        self.key_id = key_id
        self.default_ttl_seconds = default_ttl_seconds
        self._key = self._decode_key(master_key)
        self._cipher = AESGCM(self._key)

    @staticmethod
    def generate_key() -> str:
        """32-byte 키를 URL-safe base64 로 반환한다."""
        return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

    @staticmethod
    def _decode_key(value: Union[str, bytes]) -> bytes:
        encoded = value.encode("ascii") if isinstance(value, str) else value
        try:
            decoded = base64.urlsafe_b64decode(encoded)
        except Exception as exc:
            raise SecretMaterialError("NHI_MASTER_KEY 는 URL-safe base64 여야 합니다.") from exc
        if len(decoded) != 32:
            raise SecretMaterialError("NHI_MASTER_KEY 는 디코딩 후 정확히 32 bytes 여야 합니다.")
        return decoded

    def seal(
        self,
        plaintext: Union[str, bytes],
        *,
        fingerprint: str,
        allowed_purposes: Iterable[str] = ("VERIFY", "REVOKE", "ROTATE"),
        ttl_seconds: Optional[int] = None,
    ) -> SecretReference:
        raw = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        if not raw:
            raise SecretMaterialError("빈 Secret 은 저장할 수 없습니다.")

        secret_id = str(uuid4())
        created_at = _utcnow()
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        expires_at = created_at + timedelta(seconds=ttl) if ttl > 0 else None
        aad_payload: Dict[str, Any] = {
            "version": self.aad_version,
            "secret_id": secret_id,
            "fingerprint": fingerprint,
            "key_id": self.key_id,
            "allowed_purposes": sorted({purpose.upper() for purpose in allowed_purposes}),
        }
        aad = json.dumps(aad_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, raw, aad)

        self.storage.put_encrypted_secret(
            {
                "secret_id": secret_id,
                "fingerprint": fingerprint,
                "key_id": self.key_id,
                "algorithm": self.algorithm,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "aad": aad.decode("utf-8"),
                "created_at": _iso(created_at),
                "expires_at": _iso(expires_at) if expires_at else None,
            }
        )
        self.storage.append_audit_event(
            "SECRET_SEALED",
            actor="secret_material_store",
            target=secret_id,
            detail={"fingerprint": fingerprint, "key_id": self.key_id},
        )
        return SecretReference(secret_id=secret_id, key_id=self.key_id)

    @contextmanager
    def lease(
        self,
        reference: Union[str, SecretReference],
        *,
        purpose: str,
        actor: str,
    ) -> Iterator[SecretLease]:
        ref = SecretReference.parse(reference)
        if ref.key_id != self.key_id:
            raise SecretMaterialError(
                f"현재 키로 복호화할 수 없는 key_id 입니다: {ref.key_id}"
            )
        record = self.storage.get_encrypted_secret(ref.secret_id)
        if record is None:
            raise SecretMaterialError("Secret material 이 없거나 이미 파기되었습니다.")

        expires_at = _parse_dt(record.get("expires_at"))
        if expires_at is not None and expires_at <= _utcnow():
            self.destroy(ref, actor="secret_material_store")
            raise SecretMaterialError("Secret material 의 보관 기한이 만료되었습니다.")

        aad_text = str(record["aad"])
        aad_payload = json.loads(aad_text)
        normalized_purpose = purpose.upper()
        if normalized_purpose not in set(aad_payload.get("allowed_purposes", [])):
            self.storage.append_audit_event(
                "SECRET_ACCESS_DENIED",
                actor=actor,
                target=ref.secret_id,
                detail={"purpose": normalized_purpose},
            )
            raise SecretMaterialError(f"허용되지 않은 Secret 사용 목적입니다: {purpose}")

        try:
            plaintext = self._cipher.decrypt(
                bytes(record["nonce"]),
                bytes(record["ciphertext"]),
                aad_text.encode("utf-8"),
            )
        except Exception as exc:
            raise SecretMaterialError("Secret material 인증 또는 복호화에 실패했습니다.") from exc

        self.storage.append_audit_event(
            "SECRET_UNSEALED",
            actor=actor,
            target=ref.secret_id,
            detail={"purpose": normalized_purpose},
        )
        lease = SecretLease(plaintext)
        try:
            yield lease
        finally:
            lease.close()

    def destroy(
        self, reference: Union[str, SecretReference], *, actor: str = "system"
    ) -> None:
        ref = SecretReference.parse(reference)
        self.storage.delete_encrypted_secret(ref.secret_id)
        self.storage.append_audit_event(
            "SECRET_DESTROYED",
            actor=actor,
            target=ref.secret_id,
            detail={"key_id": ref.key_id},
        )
