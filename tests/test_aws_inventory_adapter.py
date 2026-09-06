"""AWS 전용 인벤토리 어댑터 함수 검증 (`agents/inventory_adapter.py`).

`build_aws_signals`/`build_aws_credential_record`/`build_aws_profile`/
`build_aws_context` 가 `AWSNHIInput.active`/`created_at`/`last_used_at` 를
기존 공통 모델(`SecretFinding`/`AnalysisSignals`/`ContextInsight`/
`EvaluationContext`)에 정확히 연결하는지 확인한다. Policy 수집·Scope
변환·pipeline 연결은 아직 없으므로 다루지 않는다. GitHub/Slack 어댑터
함수는 이 파일에서 전혀 건드리지 않는다 — 기존 회귀 스위트가 그대로 통과
하는지로 "변경 없음"을 확인한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agents.inventory_adapter import (
    build_aws_context,
    build_aws_credential_record,
    build_aws_profile,
    build_aws_signals,
)
from core.aws_inventory_models import AWSNHIInput
from core.nhi_models import (
    AnalysisSource,
    ContextInsight,
    DataSensitivity,
    Environment,
    NHIProfile,
    NHIType,
    PermissionProfile,
)
from policy.rules import EvaluationContext, PolicyConfig, evaluate_policies
from policy.scoring import RiskScorer

#: `days_since()` (policy/rules.py) 는 항상 실제 현재 시각과 비교하므로,
#: 고정된 과거 날짜가 아니라 실행 시점의 실제 현재 시각을 기준으로 삼아야
#: "N일 전"이라는 상대 계산이 의도대로 맞는다.
_NOW = datetime.now(timezone.utc)


def _nhi(**overrides) -> AWSNHIInput:
    defaults = dict(
        nhi_id="aws-123456789012-AKIAIOSFODNN7EXAMPLE",
        nhi_name="ci-deploy-user",
        nhi_type=NHIType.CLOUD_SERVICE_ACCOUNT,
        access_key_id="AKIAIOSFODNN7EXAMPLE",
    )
    defaults.update(overrides)
    return AWSNHIInput(**defaults)


# ---------------------------------------------------------------------------
# build_aws_signals()
# ---------------------------------------------------------------------------
def test_build_aws_signals_transfers_created_at_and_last_used_at():
    created = _NOW - timedelta(days=100)
    last_used = _NOW - timedelta(days=5)
    signals = build_aws_signals(_nhi(created_at=created, last_used_at=last_used))

    assert signals.created_at == created.isoformat()
    assert signals.last_used_at == last_used.isoformat()


def test_build_aws_signals_leaves_missing_timestamps_as_none():
    """값이 없으면 지어내지 않는다."""
    signals = build_aws_signals(_nhi(created_at=None, last_used_at=None))

    assert signals.created_at is None
    assert signals.last_used_at is None


def test_build_aws_signals_transfers_owner_and_environment():
    signals = build_aws_signals(
        _nhi(owner="platform-team", environment=Environment.PRODUCTION)
    )
    assert signals.owner == "platform-team"
    assert signals.extra["environment"] == "production"


def test_build_aws_signals_overrides_merge_like_slack_version():
    signals = build_aws_signals(_nhi(), overrides={"extra": {"anomalies": ["x"]}})
    assert signals.extra["anomalies"] == ["x"]
    assert "environment" in signals.extra  # 기존 값이 override 로 지워지지 않음


# ---------------------------------------------------------------------------
# build_aws_credential_record()
# ---------------------------------------------------------------------------
def test_build_aws_credential_record_reflects_active_status():
    active_record = build_aws_credential_record(_nhi(active=True))
    inactive_record = build_aws_credential_record(_nhi(active=False))

    assert active_record.credential_active is True
    assert inactive_record.credential_active is False


def test_build_aws_credential_record_never_sets_revoked():
    record = build_aws_credential_record(_nhi(active=False))
    assert record.credential_revoked is None


def test_build_aws_credential_record_provider_and_fingerprint():
    nhi = _nhi()
    record = build_aws_credential_record(nhi)

    assert record.provider == "aws"
    assert record.fingerprint == f"nhi:{nhi.nhi_id}"
    assert record.masked_value == ""


def test_build_aws_credential_record_raw_scopes_is_still_empty():
    """이번 단계에서는 Policy 수집을 하지 않으므로 항상 빈 값이어야 한다."""
    record = build_aws_credential_record(_nhi(raw_scopes=[]))
    assert record.raw_scopes == []


def test_build_aws_credential_record_account_type_is_bot_for_cloud_service_account():
    record = build_aws_credential_record(_nhi())
    assert record.credential_detail["account"]["type"] == "bot"


def test_build_aws_credential_record_has_no_accessible_resources_yet():
    record = build_aws_credential_record(_nhi())
    assert record.credential_detail["accessible_resources"] == []


# ---------------------------------------------------------------------------
# build_aws_profile()
# ---------------------------------------------------------------------------
def test_build_aws_profile_prefixes_nhi_id_and_sets_provider():
    nhi = _nhi()
    signals = build_aws_signals(nhi)
    profile = build_aws_profile(nhi, signals)

    assert profile.nhi_id == f"aws:{nhi.nhi_id}"
    assert profile.provider == "aws"
    assert profile.nhi_type is NHIType.CLOUD_SERVICE_ACCOUNT


def test_build_aws_profile_is_bot_true_for_cloud_service_account():
    nhi = _nhi()
    profile = build_aws_profile(nhi, build_aws_signals(nhi))
    assert profile.is_bot is True
    assert profile.is_service_account is True


def test_build_aws_profile_owner_missing_evidence():
    nhi = _nhi()
    profile = build_aws_profile(nhi, build_aws_signals(nhi))
    assert profile.owner is None
    assert any("Owner 미지정" in line for line in profile.evidence)


def test_build_aws_profile_owner_present_evidence():
    nhi = _nhi(owner="platform-team")
    profile = build_aws_profile(nhi, build_aws_signals(nhi))
    assert profile.owner == "platform-team"
    assert any("platform-team" in line for line in profile.evidence)


def test_build_aws_profile_no_scopes_evidence_says_assumed():
    nhi = _nhi(raw_scopes=[])
    profile = build_aws_profile(nhi, build_aws_signals(nhi))
    assert any("보수적으로 가정한다" in line for line in profile.evidence)


def test_build_aws_profile_includes_access_key_id_in_evidence():
    nhi = _nhi()
    profile = build_aws_profile(nhi, build_aws_signals(nhi))
    assert any(nhi.access_key_id in line for line in profile.evidence)


# ---------------------------------------------------------------------------
# build_aws_context()
# ---------------------------------------------------------------------------
def test_build_aws_context_in_use_reflects_active():
    active_nhi = _nhi(active=True)
    inactive_nhi = _nhi(active=False)

    assert build_aws_context(active_nhi, build_aws_signals(active_nhi)).in_use is True
    assert build_aws_context(inactive_nhi, build_aws_signals(inactive_nhi)).in_use is False


def test_build_aws_context_data_sensitivity_is_always_unknown():
    """Policy 수집 이전이라 접근 자원 기반 추정 근거가 없다."""
    nhi = _nhi()
    context = build_aws_context(nhi, build_aws_signals(nhi))
    assert context.data_sensitivity is DataSensitivity.UNKNOWN


def test_build_aws_context_environment_propagates():
    nhi = _nhi(environment=Environment.PRODUCTION)
    context = build_aws_context(nhi, build_aws_signals(nhi))
    assert context.environment is Environment.PRODUCTION
    assert not any("사용 환경 미지정" in note for note in context.notes)


def test_build_aws_context_unknown_environment_adds_conservative_note():
    nhi = _nhi(environment=Environment.UNKNOWN)
    context = build_aws_context(nhi, build_aws_signals(nhi))
    assert any("사용 환경 미지정" in note for note in context.notes)


# ---------------------------------------------------------------------------
# 핵심 확인 — active/created_at/last_used_at 가 EvaluationContext 를 거쳐
# 기존 정책/채점 로직에 실제로 정확히 연결되는지 (pipeline 미연결, 직접 조립)
# ---------------------------------------------------------------------------
def _ctx(nhi: AWSNHIInput) -> EvaluationContext:
    signals = build_aws_signals(nhi)
    record = build_aws_credential_record(nhi)
    profile = build_aws_profile(nhi, signals)
    context = build_aws_context(nhi, signals)
    return EvaluationContext(
        finding=record,
        profile=profile,
        context=context,
        permissions=PermissionProfile(),
        signals=signals,
        config=PolicyConfig(),
        source=AnalysisSource.INVENTORY,
    )


def test_active_connects_to_credential_active_and_is_active():
    active_ctx = _ctx(_nhi(active=True))
    inactive_ctx = _ctx(_nhi(active=False))

    assert active_ctx.finding.credential_active is True
    assert active_ctx.is_active is True
    assert inactive_ctx.finding.credential_active is False
    assert inactive_ctx.is_active is False


def test_created_at_connects_to_token_age_and_rotation_age():
    created = _NOW - timedelta(days=120)
    ctx = _ctx(_nhi(created_at=created))

    # days_since()/days_since_rotation() 는 호출 시점의 실제 now() 를 쓰므로
    # 대략적인 범위로 확인한다(테스트 실행 시각과 fixture 시각 차이 감안).
    assert ctx.token_age_days is not None
    assert ctx.token_age_days >= 119
    # last_rotated_at 이 없으므로 created_at 로 자동 대체된다 — Access Key 는
    # 새로 발급하는 것 자체가 회전이라 별도 신호가 필요 없다.
    assert ctx.days_since_rotation == ctx.token_age_days


def test_missing_created_at_does_not_fabricate_age():
    ctx = _ctx(_nhi(created_at=None))
    assert ctx.token_age_days is None
    assert ctx.days_since_rotation is None


def test_last_used_at_connects_to_days_since_use():
    last_used = _NOW - timedelta(days=10)
    ctx = _ctx(_nhi(last_used_at=last_used))

    assert ctx.days_since_use is not None
    assert ctx.days_since_use >= 9


def test_missing_last_used_at_does_not_fabricate_usage():
    ctx = _ctx(_nhi(last_used_at=None))
    assert ctx.days_since_use is None


def test_old_access_key_triggers_real_credential_state_reasons_not_unknown():
    """GitHub PAT/Slack Bot Token 은 이 데이터가 아예 없어 항상 '미확인'
    처리됐다 — AWS 는 실제 값이 있으므로 임계치를 넘으면 진짜 사유가 나와야 한다."""
    old_created = _NOW - timedelta(days=400)  # max_token_age_days=365, rotation_period_days=90 초과
    ctx = _ctx(_nhi(created_at=old_created, active=True))

    assessment = RiskScorer().score(ctx, [])
    credential_state = next(f for f in assessment.factors if f.area == "credential_state")

    assert any("Token 수명 초과" in reason for reason in credential_state.reasons)
    assert any("Rotation 주기 초과" in reason for reason in credential_state.reasons)
    assert not any("Rotation 이력 없음" in reason for reason in credential_state.reasons)


def test_rotation_period_policy_applies_normally_to_aws_like_slack():
    """AWS Access Key 는 GitHub App Installation Token 이 아니므로 rotation
    억제 가드가 적용되지 않는다 — Slack Bot Token 과 동일하게 정상 평가 대상."""
    ctx = _ctx(_nhi(created_at=None, active=True))  # 회전 이력·생성일 모두 없음

    assert ctx.is_github_app_installation_token is False
    violations = evaluate_policies(ctx)
    assert any(v.policy_id == "ROTATION_PERIOD" for v in violations)


def test_recent_access_key_does_not_trigger_age_or_rotation_reasons():
    recent_created = _NOW - timedelta(days=5)
    ctx = _ctx(_nhi(created_at=recent_created, active=True))

    assessment = RiskScorer().score(ctx, [])
    credential_state = next(f for f in assessment.factors if f.area == "credential_state")

    assert not any("Token 수명 초과" in reason for reason in credential_state.reasons)
    assert not any("Rotation 주기 초과" in reason for reason in credential_state.reasons)
