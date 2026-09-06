"""`core/aws_inventory_models.py::AWSNHIInput` 모델 검증.

Policy 수집·분석 파이프라인 연결은 아직 없으므로 다루지 않는다 — 이 테스트는
모델 자체(필드 기본값·필수값·타입 재사용)만 검증한다.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.aws_inventory_models import AWSNHIInput
from core.nhi_models import Environment, NHIType


def _minimal_kwargs(**overrides):
    defaults = dict(
        nhi_id="aws-123456789012-AKIAIOSFODNN7EXAMPLE",
        nhi_name="ci-deploy-user",
        nhi_type=NHIType.CLOUD_SERVICE_ACCOUNT,
        access_key_id="AKIAIOSFODNN7EXAMPLE",
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# 필수 필드 / 기본값
# ---------------------------------------------------------------------------
def test_minimal_construction_succeeds_with_only_required_fields():
    nhi = AWSNHIInput(**_minimal_kwargs())

    assert nhi.nhi_id == "aws-123456789012-AKIAIOSFODNN7EXAMPLE"
    assert nhi.nhi_name == "ci-deploy-user"
    assert nhi.nhi_type is NHIType.CLOUD_SERVICE_ACCOUNT
    assert nhi.access_key_id == "AKIAIOSFODNN7EXAMPLE"


def test_defaults_for_optional_fields():
    nhi = AWSNHIInput(**_minimal_kwargs())

    assert nhi.owner is None
    assert nhi.environment is Environment.UNKNOWN
    assert nhi.active is True
    assert nhi.created_at is None
    assert nhi.last_used_at is None
    assert nhi.raw_scopes == []


@pytest.mark.parametrize("missing_field", ["nhi_id", "nhi_name", "nhi_type", "access_key_id"])
def test_required_fields_are_enforced(missing_field):
    kwargs = _minimal_kwargs()
    del kwargs[missing_field]
    with pytest.raises(ValidationError):
        AWSNHIInput(**kwargs)


# ---------------------------------------------------------------------------
# nhi_type — 기존 NHIType 재사용 (별도 매핑 테이블 없음)
# ---------------------------------------------------------------------------
def test_nhi_type_accepts_existing_nhi_type_enum_directly():
    nhi = AWSNHIInput(**_minimal_kwargs(nhi_type=NHIType.CLOUD_SERVICE_ACCOUNT))
    assert nhi.nhi_type is NHIType.CLOUD_SERVICE_ACCOUNT


def test_nhi_type_accepts_raw_string_value_matching_nhi_type():
    """다른 provider 값을 굳이 배제하지 않는다 — 이 모델은 어떤 NHIType 이든
    그대로 받아들이고, "AWS 에는 이 유형이 맞다"는 판단은 조립 단계(다음 단계)
    의 책임이다."""
    nhi = AWSNHIInput(**_minimal_kwargs(nhi_type="CLOUD_SERVICE_ACCOUNT"))
    assert nhi.nhi_type is NHIType.CLOUD_SERVICE_ACCOUNT


def test_nhi_type_rejects_unknown_string_value():
    with pytest.raises(ValidationError):
        AWSNHIInput(**_minimal_kwargs(nhi_type="NOT_A_REAL_NHI_TYPE"))


# ---------------------------------------------------------------------------
# active / created_at / last_used_at — 실제 조회 값을 그대로 반영
# ---------------------------------------------------------------------------
def test_active_reflects_inactive_access_key_status():
    nhi = AWSNHIInput(**_minimal_kwargs(active=False))
    assert nhi.active is False


def test_created_at_and_last_used_at_accept_datetimes():
    created = datetime(2023, 1, 1, tzinfo=timezone.utc)
    last_used = datetime(2024, 6, 1, tzinfo=timezone.utc)
    nhi = AWSNHIInput(**_minimal_kwargs(created_at=created, last_used_at=last_used))

    assert nhi.created_at == created
    assert nhi.last_used_at == last_used


def test_last_used_at_none_means_never_used_not_an_error():
    """한 번도 안 쓰인 키를 표현하는 정상 상태 — GetAccessKeyLastUsed 결과와 일치."""
    nhi = AWSNHIInput(**_minimal_kwargs(last_used_at=None))
    assert nhi.last_used_at is None


# ---------------------------------------------------------------------------
# raw_scopes — Policy 수집 이전이므로 항상 비어 있고, 인스턴스 간 공유되지 않음
# ---------------------------------------------------------------------------
def test_raw_scopes_defaults_to_empty_list():
    nhi = AWSNHIInput(**_minimal_kwargs())
    assert nhi.raw_scopes == []


def test_raw_scopes_accepts_explicit_values():
    nhi = AWSNHIInput(**_minimal_kwargs(raw_scopes=["AdministratorAccess"]))
    assert nhi.raw_scopes == ["AdministratorAccess"]


def test_raw_scopes_default_is_not_shared_between_instances():
    """`default_factory=list` 가 아니라 가변 기본값을 공유하면 인스턴스 간에
    데이터가 섞인다 — 이걸 방지하고 있는지 확인."""
    first = AWSNHIInput(**_minimal_kwargs())
    second = AWSNHIInput(**_minimal_kwargs())

    first.raw_scopes.append("AdministratorAccess")

    assert first.raw_scopes == ["AdministratorAccess"]
    assert second.raw_scopes == []


# ---------------------------------------------------------------------------
# owner / environment
# ---------------------------------------------------------------------------
def test_owner_and_environment_accept_explicit_values():
    nhi = AWSNHIInput(
        **_minimal_kwargs(owner="platform-team", environment=Environment.PRODUCTION)
    )
    assert nhi.owner == "platform-team"
    assert nhi.environment is Environment.PRODUCTION
