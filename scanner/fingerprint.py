"""Fingerprint 생성.

두 종류를 만든다.

* **value fingerprint** — `secret_type + 정규화된 원문` 해시.
  위치가 달라도 같은 Secret 이면 동일하다. → 중복 탐지 / 재발 판정에 사용.
* **location fingerprint** — value fingerprint + 파일 경로/라인.
  같은 Secret 이 여러 곳에 있을 때 개별 발생 지점을 구분한다.

원문은 절대 저장하지 않고 해시만 남긴다. 조직별 salt 를 섞어
레인보우 테이블 방식의 역추적을 어렵게 한다.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from core.config import get_settings

_ALGO = "sha256"


def _normalize(value: str) -> str:
    """앞뒤 공백/따옴표를 제거해 표기 차이로 인한 해시 불일치를 방지."""
    return value.strip().strip("'\"").strip()


def _digest(payload: str, salt: Optional[str]) -> str:
    salt = salt if salt is not None else get_settings().scanner.fingerprint_salt
    material = f"{salt}|{payload}".encode("utf-8")
    return f"{_ALGO}:{hashlib.sha256(material).hexdigest()}"


def build_fingerprint(secret_type: str, value: str, *, salt: Optional[str] = None) -> str:
    """Secret 값 기반 Fingerprint (위치 무관)."""
    return _digest(f"{secret_type}|{_normalize(value)}", salt)


def build_location_fingerprint(
    secret_type: str,
    value: str,
    file_path: str,
    line_number: int,
    *,
    salt: Optional[str] = None,
) -> str:
    """발생 지점까지 포함한 Fingerprint."""
    normalized_path = file_path.replace("\\", "/").lstrip("./")
    return _digest(
        f"{secret_type}|{_normalize(value)}|{normalized_path}|{line_number}", salt
    )


def build_credential_fingerprint(provider: str, value: str, *, salt: Optional[str] = None) -> str:
    """provider 단위 Fingerprint.

    같은 Token 이 서로 다른 유형으로 분류되더라도 외부 API 재검증 결과를
    공유할 수 있도록 provider 기준으로도 하나 만들어 둔다.
    """
    return _digest(f"provider:{provider}|{_normalize(value)}", salt)
