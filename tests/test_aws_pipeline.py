"""`NHIAnalysisPipeline.analyze_aws_nhi()` 검증.

기존 `build_aws_*` 어댑터를 공통 `_assess()` 흐름에 연결하는 것만 다룬다.
Policy 수집·Scope 변환은 아직 없으므로 `raw_scopes` 는 항상 비어 있고,
`_assess()` 는 이를 다른 provider 와 동일하게 "Scope 미확인" 으로 처리해야
한다(AWS 전용 예외 처리가 새로 생기면 안 된다). GitHub/Slack 경로는 이번
변경으로 전혀 영향받지 않아야 한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agents.inventory_adapter import build_github_nhi_input, build_slack_nhi_input
from agents.pipeline import NHIAnalysisPipeline
from core.aws_inventory_models import AWSNHIInput
from core.models import CredentialStatus
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    Environment,
    NHIType,
    PermissionLevel,
)

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
# 기본 동작
# ---------------------------------------------------------------------------
def test_analyze_aws_nhi_returns_inventory_sourced_analysis():
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi())

    assert analysis.source is AnalysisSource.INVENTORY
    assert analysis.profile.nhi_id == "aws:aws-123456789012-AKIAIOSFODNN7EXAMPLE"
    assert analysis.profile.provider == "aws"
    assert analysis.profile.nhi_type is NHIType.CLOUD_SERVICE_ACCOUNT


def test_analyze_aws_nhi_permissions_are_empty_not_assumed():
    """raw_scopes 가 비어 있어도 GitHub App 처럼 임의로 가정하지 않는다
    (인벤토리 경로는 assume_if_missing=False)."""
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(raw_scopes=[]))

    assert analysis.permissions.permissions == []
    assert analysis.permissions.assumed is False


def test_analyze_aws_nhi_owner_required_violation_when_no_owner():
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(owner=None))
    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "OWNER_REQUIRED" in violation_ids


def test_analyze_aws_nhi_owner_set_avoids_owner_required_violation():
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(owner="platform-team"))
    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "OWNER_REQUIRED" not in violation_ids
    assert analysis.profile.owner == "platform-team"


def test_analyze_aws_nhi_blast_radius_has_no_resources_yet():
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi())
    assert analysis.blast_radius.accessible_resources == 0


# ---------------------------------------------------------------------------
# active/created_at/last_used_at 가 pipeline 을 거쳐 실제로 반영되는지
# ---------------------------------------------------------------------------
def test_analyze_aws_nhi_inactive_key_scores_lower_credential_state():
    active_analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(active=True))
    inactive_analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(active=False))

    active_factor = next(
        f for f in active_analysis.risk.factors if f.area == "credential_state"
    )
    inactive_factor = next(
        f for f in inactive_analysis.risk.factors if f.area == "credential_state"
    )
    assert "외부 검증 결과 활성 Token" in active_factor.reasons
    assert "비활성 자격 증명" in inactive_factor.reasons
    assert inactive_factor.score < active_factor.score


def test_analyze_aws_nhi_old_access_key_triggers_real_rotation_reasons():
    """GitHub PAT/Slack Bot Token 과 달리 AWS 는 실제 CreateDate 가 있으므로
    임계치를 넘으면 '미확인'이 아니라 진짜 사유가 나와야 한다."""
    old_created = _NOW - timedelta(days=400)
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(created_at=old_created, active=True))

    credential_state = next(
        f for f in analysis.risk.factors if f.area == "credential_state"
    )
    assert any("Token 수명 초과" in r for r in credential_state.reasons)
    assert any("Rotation 주기 초과" in r for r in credential_state.reasons)

    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "TOKEN_MAX_AGE" in violation_ids
    assert "ROTATION_PERIOD" in violation_ids


def test_analyze_aws_nhi_recent_access_key_has_no_age_violations():
    recent_created = _NOW - timedelta(days=5)
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(created_at=recent_created, active=True))

    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "TOKEN_MAX_AGE" not in violation_ids
    assert "ROTATION_PERIOD" not in violation_ids


def test_analyze_aws_nhi_missing_created_at_does_not_fabricate_age_violation():
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(created_at=None, active=True))
    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "TOKEN_MAX_AGE" not in violation_ids  # token_age_days 가 None 이라 판정 자체가 스킵됨


def test_analyze_aws_nhi_is_not_treated_as_github_app_installation_token():
    """GitHub App 전용 rotation 억제 가드가 AWS 에는 적용되지 않아야 한다
    (Slack Bot Token 과 동일하게 정상적으로 ROTATION_PERIOD 대상이 됨)."""
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(created_at=None, active=True))
    violation_ids = {v.policy_id for v in analysis.policy.violations}
    assert "ROTATION_PERIOD" in violation_ids


# ---------------------------------------------------------------------------
# signals 오버라이드 — GitHub/Slack 과 동일한 인터페이스
# ---------------------------------------------------------------------------
def test_analyze_aws_nhi_accepts_analysis_signals_instance():
    signals = AnalysisSignals(owner="override-team")
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(_nhi(owner=None), signals=signals)
    assert analysis.profile.owner == "override-team"


def test_analyze_aws_nhi_accepts_plain_dict_signals():
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(
        _nhi(owner=None), signals={"owner": "dict-override-team"}
    )
    assert analysis.profile.owner == "dict-override-team"


# ---------------------------------------------------------------------------
# GitHub/Slack 경로는 이번 변경으로 전혀 영향받지 않는지
# ---------------------------------------------------------------------------
def test_github_pipeline_path_is_unaffected():
    nhi = build_github_nhi_input({"login": "octocat", "id": 1}, [])
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)
    assert analysis.profile.provider == "github"
    assert analysis.profile.nhi_id == "github:github-user-1"


def test_slack_pipeline_path_is_unaffected():
    status = CredentialStatus(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["channels:history"],
        account={
            "token_kind": "bot",
            "team_id": "T1",
            "user": "support-bot",
            "user_id": "U1",
            "bot_id": "B1",
        },
        accessible_resources=[],
    )
    nhi = build_slack_nhi_input(status, [])
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)
    assert analysis.profile.provider == "slack"
    assert analysis.profile.nhi_id == "slack:slack-T1-B1"
