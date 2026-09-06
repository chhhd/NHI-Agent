"""AWS Blast Radius 최소 보강 — `broad_access` 검증.

확인 범위:
  * agents/aws_policy_permission_analyzer.py — Allow Statement의 Resource
    wildcard 감지(`broad_access`)
  * core/aws_inventory_models.py / agents/aws_inventory_service.py —
    분석 결과가 `AWSNHIInput.broad_access` 로 그대로 전달되는지
  * agents/inventory_adapter.py — `signals.extra["aws_broad_access"]` 로
    전달되는지
  * core/nhi_models.py / graph/blast_radius.py — `BlastRadiusReport.broad_access`
    반영과, 정확한 리소스 개수 대신 이 이진값만 위험 근거(`impact_score`)로
    쓰이는지

GitHub/Slack 의 접근 자원 "개수" 기반 계산은 전혀 건드리지 않았다는 것도
함께 확인한다.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from agents.aws_policy_normalizer import normalize_policy_statements
from agents.aws_policy_permission_analyzer import (
    _is_broad_resource,
    analyze_policy_permissions,
)
from agents.inventory_adapter import (
    build_aws_signals,
    build_github_nhi_input,
    build_slack_nhi_input,
)
from agents.pipeline import NHIAnalysisPipeline
from core.aws_inventory_models import AWSNHIInput
from core.models import CredentialStatus
from core.nhi_models import NHIType
from graph.blast_radius import BlastRadiusCalculator


def _statement(effect="Allow", actions=None, resources=None):
    return {"effect": effect, "actions": actions or [], "resources": resources or [], "condition": None}


def _aws_nhi(**overrides):
    defaults = dict(
        nhi_id="aws-123456789012-AKIAEXAMPLE00000000",
        nhi_name="ci-deploy-user",
        nhi_type=NHIType.CLOUD_SERVICE_ACCOUNT,
        access_key_id="AKIAEXAMPLE00000000",
    )
    defaults.update(overrides)
    return AWSNHIInput(**defaults)


# ---------------------------------------------------------------------------
# _is_broad_resource() — wildcard 판정 단위 테스트
# ---------------------------------------------------------------------------
def test_bare_wildcard_is_broad():
    assert _is_broad_resource("*") is True


def test_service_wide_arn_wildcard_is_broad():
    assert _is_broad_resource("arn:aws:s3:::*") is True
    assert _is_broad_resource("arn:aws:iam::123456789012:*") is True


def test_resource_scoped_wildcard_is_not_broad():
    """버킷 하나 안의 객체 전체(`bucket/*`)는 좁은 범위 — 흔한 정상 패턴이라 오탐하면 안 된다."""
    assert _is_broad_resource("arn:aws:s3:::my-bucket/*") is False


def test_specific_resource_without_wildcard_is_not_broad():
    assert _is_broad_resource("arn:aws:s3:::my-bucket") is False
    assert _is_broad_resource("arn:aws:iam::123456789012:user/ci-deploy-user") is False


def test_non_string_resource_is_not_broad():
    assert _is_broad_resource(None) is False
    assert _is_broad_resource(123) is False


# ---------------------------------------------------------------------------
# analyze_policy_permissions() — broad_access 집계
# ---------------------------------------------------------------------------
def test_wildcard_resource_in_allow_statement_sets_broad_access():
    statements = [_statement(actions=["s3:GetObject"], resources=["*"])]
    result = analyze_policy_permissions(statements)
    assert result.broad_access is True


def test_narrow_resource_does_not_set_broad_access():
    statements = [_statement(actions=["s3:GetObject"], resources=["arn:aws:s3:::my-bucket/*"])]
    result = analyze_policy_permissions(statements)
    assert result.broad_access is False


def test_broad_access_true_if_any_statement_among_several_is_broad():
    statements = [
        _statement(actions=["s3:GetObject"], resources=["arn:aws:s3:::my-bucket/*"]),
        _statement(actions=["iam:CreateUser"], resources=["*"]),
    ]
    result = analyze_policy_permissions(statements)
    assert result.broad_access is True


def test_deny_statement_wildcard_resource_does_not_set_broad_access():
    """Deny 문의 Resource 는 '허용된 접근'이 아니므로 broad_access 판정에 영향을 주면 안 된다."""
    statements = [_statement(effect="Deny", actions=["s3:DeleteObject"], resources=["*"])]
    result = analyze_policy_permissions(statements)
    assert result.broad_access is False


def test_no_statements_defaults_broad_access_false():
    assert analyze_policy_permissions([]).broad_access is False


def test_broad_access_reflected_in_to_dict():
    result = analyze_policy_permissions([_statement(resources=["*"])])
    assert result.to_dict()["broad_access"] is True


def test_integrates_with_normalized_administrator_access_document():
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    statements = normalize_policy_statements(document)
    result = analyze_policy_permissions(statements)
    assert result.broad_access is True


def test_integrates_with_normalized_scoped_bucket_document():
    document = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-app-bucket/*",
            }
        ]
    }
    statements = normalize_policy_statements(document)
    result = analyze_policy_permissions(statements)
    assert result.broad_access is False


# ---------------------------------------------------------------------------
# build_aws_signals() — signals.extra 로 전달
# ---------------------------------------------------------------------------
def test_build_aws_signals_carries_broad_access_true():
    signals = build_aws_signals(_aws_nhi(broad_access=True))
    assert signals.extra["aws_broad_access"] is True


def test_build_aws_signals_carries_broad_access_false():
    signals = build_aws_signals(_aws_nhi(broad_access=False))
    assert signals.extra["aws_broad_access"] is False


# ---------------------------------------------------------------------------
# BlastRadiusCalculator — broad_access 반영, 리소스 "개수"는 세지 않음
# ---------------------------------------------------------------------------
def _blast_radius_for(nhi: AWSNHIInput):
    from agents.inventory_adapter import (
        build_aws_context,
        build_aws_credential_record,
        build_aws_profile,
    )

    signals = build_aws_signals(nhi)
    record = build_aws_credential_record(nhi)
    profile = build_aws_profile(nhi, signals)
    context = build_aws_context(nhi, signals)

    from agents.scope_translation_agent import ScopeTranslationAgent

    permissions = ScopeTranslationAgent().translate_finding(record, assume_if_missing=False)
    return BlastRadiusCalculator().compute(record, profile, permissions, context, signals)


def test_blast_radius_broad_access_true_sets_report_flag():
    report = _blast_radius_for(_aws_nhi(broad_access=True))
    assert report.broad_access is True


def test_blast_radius_broad_access_false_by_default():
    report = _blast_radius_for(_aws_nhi(broad_access=False))
    assert report.broad_access is False


def test_blast_radius_does_not_count_accessible_resources_for_aws():
    """정확한 리소스 개수 계산은 하지 않는다 — AWS 는 항상 0으로 남는다."""
    report = _blast_radius_for(_aws_nhi(broad_access=True))
    assert report.accessible_resources == 0
    assert report.resource_samples == []


def test_blast_radius_note_present_only_when_broad_access_true():
    broad = _blast_radius_for(_aws_nhi(broad_access=True))
    narrow = _blast_radius_for(_aws_nhi(broad_access=False))

    assert any("광범위한 Resource" in note for note in broad.notes)
    assert not any("광범위한 Resource" in note for note in narrow.notes)


def test_blast_radius_missing_resource_note_is_suppressed_for_aws():
    """GitHub/Slack 의 '접근 가능 자원 목록을 확인하지 못함' 문구는 AWS 에는
    안 맞는다(개수를 아예 안 세므로 검증 실패처럼 보이면 안 된다)."""
    report = _blast_radius_for(_aws_nhi(broad_access=False))
    assert not any("접근 가능 자원 목록을 확인하지 못함" in note for note in report.notes)


def test_impact_score_broad_access_adds_same_weight_as_top_resource_tier():
    broad = _blast_radius_for(_aws_nhi(broad_access=True, raw_scopes=["s3:GetObject"]))
    narrow = _blast_radius_for(_aws_nhi(broad_access=False, raw_scopes=["s3:GetObject"]))

    assert broad.impact_score - narrow.impact_score == 25


# ---------------------------------------------------------------------------
# end-to-end — 전체 파이프라인을 통해서도 확인
# ---------------------------------------------------------------------------
def test_end_to_end_pipeline_reflects_broad_access():
    nhi = _aws_nhi(broad_access=True, raw_scopes=["iam:CreateUser"])
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(nhi)

    assert analysis.blast_radius.broad_access is True
    assert any("광범위한 Resource" in note for note in analysis.blast_radius.notes)


def test_end_to_end_pipeline_narrow_access_has_no_broad_access_note():
    nhi = _aws_nhi(broad_access=False, raw_scopes=["s3:GetObject"])
    analysis = NHIAnalysisPipeline().analyze_aws_nhi(nhi)

    assert analysis.blast_radius.broad_access is False
    assert not any("광범위한 Resource" in note for note in analysis.blast_radius.notes)


# ---------------------------------------------------------------------------
# GitHub/Slack 은 이번 변경으로 전혀 영향받지 않는지
# ---------------------------------------------------------------------------
def test_github_blast_radius_broad_access_stays_false_and_resources_still_counted():
    nhi = build_github_nhi_input(
        {"login": "octocat", "id": 1},
        [{"full_name": "acme/backend", "private": True}, {"full_name": "acme/frontend", "private": False}],
    )
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)

    assert analysis.blast_radius.broad_access is False
    assert analysis.blast_radius.accessible_resources == 2  # GitHub 는 여전히 개수를 센다
    assert not any("광범위한 Resource" in note for note in analysis.blast_radius.notes)


def test_slack_blast_radius_broad_access_stays_false_and_resources_still_counted():
    status = CredentialStatus(
        provider="slack",
        active=True,
        revoked=False,
        raw_scopes=["channels:history"],
        account={"token_kind": "bot", "team_id": "T1", "user": "bot", "user_id": "U1", "bot_id": "B1"},
        accessible_resources=[{"name": "general", "is_private": False}],
    )
    nhi = build_slack_nhi_input(status, status.accessible_resources)
    analysis = NHIAnalysisPipeline().analyze_slack_nhi(nhi)

    assert analysis.blast_radius.broad_access is False
    assert analysis.blast_radius.accessible_resources == 1  # Slack 도 여전히 개수를 센다


def test_github_missing_resources_note_is_unaffected():
    """AWS 전용 예외 처리를 넣었다고 GitHub 의 기존 '확인 못함' 문구까지
    사라지면 안 된다."""
    nhi = build_github_nhi_input({"login": "octocat", "id": 1}, [])
    analysis = NHIAnalysisPipeline().analyze_github_nhi(nhi)
    assert any("접근 가능 자원 목록을 확인하지 못함" in note for note in analysis.blast_radius.notes)
