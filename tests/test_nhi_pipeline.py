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
