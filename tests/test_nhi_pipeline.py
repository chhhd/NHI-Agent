"""NHI 분석 파이프라인 통합 테스트 — 탐지 결과 → 최종 산출 스키마."""

from __future__ import annotations

from agents.pipeline import NHIAnalysisPipeline, finding_from_dict
from core.models import ScanResult, ScanTrigger
from core.nhi_models import AnalysisSignals, NHIType, RecommendedAction, RiskLevel
from scanner.scan_service import SecretScanService
from core.models import ScanTarget
from tests.test_nhi_agents import make_finding

REQUIRED_KEYS = (
    "nhi_name", "nhi_type", "owner", "environment", "permissions",
    "risk_score", "risk_level", "risk_reasons", "recommended_action",
)


def test_pipeline_output_matches_required_schema():
    finding = make_finding(
        file_path="config/production/support_bot.env",
        raw_scopes=["channels:history", "chat:write"],
        credential_active=True,
        credential_revoked=False,
        account={"team": "Customer Support Team", "user": "customer-support-bot", "bot_id": "B01"},
        resources=[{"name": "general"}],
    )
    analysis = NHIAnalysisPipeline().analyze_finding(
        finding, signals=AnalysisSignals(repository="acme/support", repository_public=True)
    )
    data = analysis.to_dict()

    for key in REQUIRED_KEYS:
        assert key in data, key
    assert data["nhi_name"] == "customer-support-bot"
    assert data["nhi_type"] == NHIType.SLACK_BOT.value
    assert data["owner"] == "Customer Support Team"
    assert data["environment"] == "production"
    assert data["permissions"] == ["READ", "WRITE"]
    assert data["risk_level"] in {level.value for level in RiskLevel}
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_reasons"]
    assert data["recommended_action"] == RecommendedAction.TOKEN_ROTATION.value


def test_pipeline_populates_replay_snapshot_for_change_preview():
    """Change Preview가 가정 상태를 재구성할 수 있도록 입력이 보존되는지 확인한다."""
    finding = make_finding(
        raw_scopes=["channels:history", "chat:write"],
        credential_active=True,
        credential_revoked=False,
        account={"team": "Customer Support Team", "user": "customer-support-bot"},
        resources=[{"name": "general"}],
    )
    signals = AnalysisSignals(
        repository="acme/support",
        repository_public=True,
        owner="Customer Support Team",
        created_at="2020-01-01T00:00:00Z",
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot = analysis.to_dict()["replay_snapshot"]

    assert snapshot["signals"]["repository"] == "acme/support"
    assert snapshot["signals"]["owner"] == "Customer Support Team"
    assert snapshot["finding"]["raw_scopes"] == ["channels:history", "chat:write"]
    assert snapshot["finding"]["credential_active"] is True
    assert "_raw_value" not in snapshot["finding"]


def test_pipeline_redacts_untrusted_signal_values_in_replay_snapshot():
    """`signals`의 신뢰할 수 없는 값(감사 로그 등)이 그대로 저장되지 않아야 한다."""
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        repository="acme/support",
        observed_actions=[f"GET /v1/items?access_token={secret}"],
        request_user_agent=f"curl Authorization: Bearer {secret}",
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot = analysis.to_dict()["replay_snapshot"]

    import json

    assert secret not in json.dumps(snapshot, ensure_ascii=False)


def test_pipeline_preserves_long_signal_field_names_in_replay_snapshot():
    """회귀 테스트 — `token_used_after_revocation`처럼 20자 이상인
    `AnalysisSignals` 필드명이 값처럼 마스킹돼 사라지면 안 된다. 이 필드들은
    Change Preview 재계산이 강제 Critical 판정을 재현하는 데 직접 쓰인다
    (`backend/security/redaction.py::sanitize_security_value(preserve_top_level_keys=True)`).
    """
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        repository="acme/support",
        owner="platform-team",
        token_used_after_revocation=True,
        token_replay_suspected=True,
        token_binding_method="DPoP",
        declared_permissions=["READ"],
        exception_expires_at="2026-12-31T00:00:00Z",
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot_signals = analysis.to_dict()["replay_snapshot"]["signals"]

    for field_name, expected in (
        ("token_used_after_revocation", True),
        ("token_replay_suspected", True),
        ("token_binding_method", "DPoP"),
        ("declared_permissions", ["READ"]),
        ("exception_expires_at", "2026-12-31T00:00:00Z"),
    ):
        assert field_name in snapshot_signals, f"{field_name} 키가 마스킹돼 사라짐"
        assert snapshot_signals[field_name] == expected


def test_pipeline_still_redacts_nested_dynamic_keys_in_replay_snapshot():
    """최상위 필드명만 보존된다 — `extra`처럼 호출부가 정의하지 않은 동적
    키는 depth가 올라가면 여전히 정리돼야 한다(기존 보안 범위 유지)."""
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    finding = make_finding(credential_active=True)
    signals = AnalysisSignals(
        repository="acme/support",
        extra={"some_externally_named_long_header_field": secret},
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, signals=signals)
    snapshot_signals = analysis.to_dict()["replay_snapshot"]["signals"]

    assert "some_externally_named_long_header_field" not in snapshot_signals["extra"]
    assert secret not in str(snapshot_signals["extra"])


def test_pipeline_analyzes_scan_result_dict_from_team1():
    """탐지 계층의 `ScanResult.to_dict()` 를 그대로 입력으로 받을 수 있어야 한다."""
    content = "\n".join(
        [
            "# customer support bot",
            "SLACK_BOT_TOKEN=xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d",
        ]
    )
    scan = SecretScanService(enable_entropy=False).scan_targets(
        [ScanTarget(path="config/prod/slack.env", content=content)],
        repository="acme/support",
        trigger=ScanTrigger.MANUAL,
    )
    payload = scan.to_dict()

    report = NHIAnalysisPipeline().analyze_scan_result(payload)

    assert report.repository == "acme/support"
    assert len(report.analyses) == 1
    analysis = report.analyses[0]
    assert analysis.profile.nhi_type is NHIType.SLACK_BOT
    assert analysis.fingerprint == payload["findings"][0]["fingerprint"]
    # 원문은 넘어오지 않는다 (탐지 계층의 보안 속성 유지)
    assert analysis.masked_value and "Ttk4L8xR2mQaZbYuVnW7pQ3d" not in str(analysis.to_dict())


def test_pipeline_report_summary_and_graph():
    slack = make_finding(credential_active=True, raw_scopes=["chat:write"])
    github = make_finding(
        secret_type="GITHUB_PAT", provider="github", file_path="src/deploy.py",
        raw_scopes=["repo"], credential_active=True,
    )
    github.fingerprint = "sha256:github0011"

    report = NHIAnalysisPipeline().analyze_findings(
        [slack, github],
        repository="acme/support",
        default_signals=AnalysisSignals(repository_public=True),
    )
    summary = report.summary()

    assert summary["total"] == 2
    assert sum(summary["by_risk_level"].values()) == 2
    assert summary["max_risk_score"] == report.analyses[0].risk.score  # 위험 순 정렬
    assert report.graph is not None
    assert report.graph["stats"]["NHI"] == 2


def test_pipeline_signals_are_not_shared_between_findings():
    """기본 신호를 복제해서 쓰므로 한 finding 의 분석이 다른 finding 에 새지 않는다."""
    a = make_finding()
    b = make_finding(file_path="src/other.py")
    b.fingerprint = "sha256:other0011"
    signals = AnalysisSignals(repository_public=False)

    NHIAnalysisPipeline().analyze_findings([a, b], repository="acme/x", default_signals=signals)

    assert signals.repository == ""  # 원본이 오염되지 않음


def test_pipeline_unknown_nhi_requires_human_review():
    finding = make_finding(
        secret_type="UNCLASSIFIED_HIGH_ENTROPY",
        provider="unknown",
        file_path="src/util.py",
        line="value = 'aZ81kdlfjW02mfPQzz19'",
        credential_active=True,
    )
    analysis = NHIAnalysisPipeline().analyze_finding(finding, repository="acme/x")

    assert analysis.profile.nhi_type is NHIType.UNKNOWN_NHI
    assert analysis.policy.human_review_required is True
    assert any("특정" in line for line in analysis.policy.evidence)


def test_finding_from_dict_roundtrip():
    original = make_finding(
        raw_scopes=["chat:write"], credential_active=True,
        account={"user": "support-bot"}, resources=[{"name": "general"}],
    )
    restored = finding_from_dict(original.to_dict())

    assert restored.fingerprint == original.fingerprint
    assert restored.raw_scopes == original.raw_scopes
    assert restored.credential_detail == original.credential_detail
    assert restored.context.line == original.context.line
    assert restored.raw_value == ""


def test_pipeline_accepts_scan_result_object():
    scan = ScanResult(repository="acme/support", trigger=ScanTrigger.RESCAN)
    scan.findings = [make_finding(credential_active=True)]

    report = NHIAnalysisPipeline().analyze_scan_result(scan)

    assert report.repository == "acme/support"
    assert len(report.analyses) == 1
