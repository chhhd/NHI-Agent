"""NHI 분석 파이프라인 — 시스템의 단일 분석 엔진.

입력은 두 경로로 들어오고, 그 뒤 과정은 완전히 같다.

    (A) 저장소 스캔 결과            (B) GitHub NHI 인벤토리 입력
        SecretFinding                   GitHubNHIInput
        → Discovery Agent               → inventory_adapter
          (어떤 NHI 인가)                 (신원·문맥을 선언값으로 확정)
        → Context Analysis Agent
                  │                             │
                  └──────────┬──────────────────┘
                             ▼
        → Scope Translation Agent  : 권한을 공통 4종으로
        → Blast Radius             : 영향 범위
        → Policy Engine            : 위반 판정
        → Risk Scoring Agent       : 100점 만점 위험도 + 강제 Critical
        → Decision Engine          : 자동 조치 / 사람 검토 / 예외
        → Recommendation Agent     : 조치 권고
        → NHIAnalysis              : 대시보드·Agent 공통 산출물
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence

from agents.context_analysis_agent import ContextAnalysisAgent
from agents.discovery_agent import DiscoveryAgent
from agents.event_extraction_agent import EventExtractionAgent
from agents.inventory_adapter import (
    build_aws_context,
    build_aws_credential_record,
    build_aws_profile,
    build_aws_signals,
    build_context,
    build_credential_record,
    build_profile,
    build_signals,
    build_slack_context,
    build_slack_credential_record,
    build_slack_profile,
    build_slack_signals,
)
from agents.saas_inventory_adapter import (
    build_saas_context,
    build_saas_credential_record,
    build_saas_profile,
    build_saas_signals,
)
from agents.policy_evidence_agent import PolicyEvidenceAgent
from agents.recommendation_agent import RecommendationAgent
from agents.risk_scoring_agent import RiskScoringAgent
from agents.scope_translation_agent import ScopeTranslationAgent
from agents.scenario_mapping_agent import ScenarioMappingAgent
from agents.usage_analysis_agent import PermissionUsageAgent, UsageAnalysisAgent
from core.aws_inventory_models import AWSNHIInput
from core.inventory_models import GitHubNHIInput, SaaSNHIInput
from core.slack_inventory_models import SlackNHIInput
from core.models import (
    CodeContext,
    DetectorType,
    ResolutionStatus,
    ScanResult,
    SecretFinding,
    Severity,
)
from core.nhi_models import (
    AnalysisSignals,
    AnalysisSource,
    ChangePreviewSnapshot,
    ContextInsight,
    NHIAnalysis,
    NHIAnalysisReport,
    NHIProfile,
)
from graph.blast_radius import BlastRadiusCalculator, summarize_blast_radius
from graph.relationship_graph import RelationshipGraph
from policy.rules import EvaluationContext, PolicyConfig, evaluate_security_scenarios
from security.redaction import sanitize_security_value

logger = logging.getLogger(__name__)


def finding_from_dict(data: Dict[str, Any]) -> SecretFinding:
    """`ScanResult.to_dict()` 의 finding 항목 → SecretFinding.

    탐지 계층이 JSON 으로 넘겨준 결과를 그대로 분석할 수 있게 한다.
    원문(_raw_value)은 직렬화되지 않으므로 항상 비어 있다.
    """
    ctx = data.get("context") or {}
    return SecretFinding(
        secret_type=data.get("secret_type", ""),
        provider=data.get("provider", "unknown"),
        masked_value=data.get("masked_value", ""),
        fingerprint=data.get("fingerprint", ""),
        file_path=data.get("file_path", ""),
        line_number=int(data.get("line_number", 0) or 0),
        detector=DetectorType(data.get("detector", "regex")),
        severity=Severity(data.get("severity", "medium")),
        entropy=data.get("entropy"),
        match_start=data.get("match_start", 0),
        match_end=data.get("match_end", 0),
        context=CodeContext(
            before=list(ctx.get("before", [])),
            line=ctx.get("line", ""),
            after=list(ctx.get("after", [])),
        ),
        credential_active=data.get("credential_active"),
        credential_revoked=data.get("credential_revoked"),
        raw_scopes=list(data.get("raw_scopes", [])),
        credential_detail=data.get("credential_detail"),
        occurrence_count=int(data.get("occurrence_count", 1) or 1),
        duplicate_locations=list(data.get("duplicate_locations", [])),
        status=ResolutionStatus(data.get("status", "new")),
        detected_at=data.get("detected_at", ""),
        secret_ref=data.get("secret_ref"),
    )


#: `finding_from_dict()`가 복원하는 필드 중 Change Preview 재현에 쓰는 부분만
#: 추린 목록이다. `_raw_value`/원문 Secret은 애초에 여기 들어오지 않는다.
_REPLAY_FINDING_FIELDS = (
    "secret_type",
    "provider",
    "credential_active",
    "credential_revoked",
    "raw_scopes",
    "credential_detail",
    "occurrence_count",
    "duplicate_locations",
    "status",
    "detected_at",
)


def _build_replay_snapshot(
    finding: SecretFinding, signals: AnalysisSignals
) -> ChangePreviewSnapshot:
    """Change Preview가 가정 상태를 재구성할 수 있도록 입력을 보존한다.

    `NHIAnalysis.to_dict()`에 저장되는 값이므로 원문 Secret 값은 절대 담지
    않는다 — `SecretFinding.to_dict()`도 이미 원문을 제거하지만, `signals`는
    감사 로그 등 신뢰할 수 없는 입력(`observed_actions`/`request_user_agent`
    등)을 그대로 담을 수 있으므로 다른 보안 이벤트 직렬화와 동일하게
    `sanitize_security_value()`로 한 번 더 정리한다.

    `preserve_top_level_keys=True`를 준다 — `signals.to_dict()`/`finding_snapshot`의
    최상위 키는 우리가 정의한 `AnalysisSignals`/`SecretFinding` 필드명이지,
    감사 로그에서 온 신뢰 불가 값이 아니다. 이 플래그 없이 기본 동작(키도
    정리)을 쓰면 `token_used_after_revocation`처럼 20자 이상인 필드명이
    `redact_unknown_tokens()`에 토큰으로 오인돼 마스킹되고, `AnalysisSignals
    .from_dict()`가 그 필드를 복원하지 못해 Change Preview 재계산에서 해당
    보안 신호가 조용히 사라진다 — 값이 아니라 필드 자체를 잃는 문제였다.
    `extra` 처럼 호출부가 정의하지 않은 중첩 dict의 키는 여전히 정리된다
    (depth가 올라가면 기본 동작으로 돌아감).
    """
    finding_dict = finding.to_dict()
    finding_snapshot = {
        key: finding_dict.get(key) for key in _REPLAY_FINDING_FIELDS
    }
    return ChangePreviewSnapshot(
        signals=sanitize_security_value(signals.to_dict(), preserve_top_level_keys=True),
        finding=sanitize_security_value(finding_snapshot, preserve_top_level_keys=True),
    )


class NHIAnalysisPipeline:
    """탐지 결과 → NHI 분석 결과."""

    def __init__(
        self,
        *,
        config: Optional[PolicyConfig] = None,
        discovery: Optional[DiscoveryAgent] = None,
        context_analysis: Optional[ContextAnalysisAgent] = None,
        scope_translation: Optional[ScopeTranslationAgent] = None,
        risk_scoring: Optional[RiskScoringAgent] = None,
        policy_evidence: Optional[PolicyEvidenceAgent] = None,
        recommendation: Optional[RecommendationAgent] = None,
        blast_radius: Optional[BlastRadiusCalculator] = None,
        usage_analysis: Optional[UsageAnalysisAgent] = None,
        permission_usage: Optional[PermissionUsageAgent] = None,
        event_extraction: Optional[EventExtractionAgent] = None,
        scenario_mapping: Optional[ScenarioMappingAgent] = None,
    ) -> None:
        self.config = config or PolicyConfig()
        self.discovery = discovery or DiscoveryAgent()
        self.context_analysis = context_analysis or ContextAnalysisAgent()
        self.scope_translation = scope_translation or ScopeTranslationAgent()
        # canonical Usage/SecurityEvent/Scenario 분석 — EvaluationContext 와
        # 강제 Critical 규칙에 연결된다 (`_assess()` 참고).
        self.usage_analysis = usage_analysis or UsageAnalysisAgent(self.scope_translation)
        # 기존 권한 사용률 기반 Event/Scenario 매핑 — RecommendationAgent 의
        # 시나리오 권고가 여기 의존한다. 이름 충돌을 피하려고 `UsageAnalysisAgent`
        # 와 별도 클래스(`PermissionUsageAgent`)로 분리했다.
        self.permission_usage = permission_usage or PermissionUsageAgent(
            scope_translator=self.scope_translation
        )
        self.risk_scoring = risk_scoring or RiskScoringAgent()
        self.policy_evidence = policy_evidence or PolicyEvidenceAgent()
        self.recommendation = recommendation or RecommendationAgent()
        self.blast_radius = blast_radius or BlastRadiusCalculator()
        self.event_extraction = event_extraction or EventExtractionAgent()
        self.scenario_mapping = scenario_mapping or ScenarioMappingAgent()

    # ------------------------------------------------------------------
    # 단건 분석
    # ------------------------------------------------------------------
    def analyze_finding(
        self,
        finding: SecretFinding,
        *,
        signals: Optional[AnalysisSignals] = None,
        repository: str = "",
    ) -> NHIAnalysis:
        signals = signals or AnalysisSignals()
        if repository and not signals.repository:
            signals.repository = repository

        profile = self.discovery.analyze(finding, signals)
        context = self.context_analysis.analyze(finding, signals)
        return self._assess(
            finding,
            profile,
            context,
            signals,
            repository=signals.repository or repository,
            source=AnalysisSource.CODE_SCAN,
        )

    # ------------------------------------------------------------------
    # 인벤토리 단건 분석 (코드 스캔 없이 NHI 정보만으로)
    # ------------------------------------------------------------------
    def analyze_github_nhi(
        self,
        nhi: GitHubNHIInput,
        *,
        signals: Optional[Any] = None,
    ) -> NHIAnalysis:
        """GitHub NHI 인벤토리 1건을 스캔 경로와 같은 기준으로 분석한다.

        `signals` 로 코드·인벤토리 어디에도 없는 외부 사실(감사 로그의 관측 행위,
        AI Agent 종료 여부, 예외 승인 등)을 주입할 수 있다.
        `AnalysisSignals` 또는 그 dict 표현을 모두 받는다.
        """
        overrides: Optional[Dict[str, Any]]
        if isinstance(signals, AnalysisSignals):
            overrides = signals.to_dict()
        else:
            overrides = signals

        analysis_signals = build_signals(nhi, overrides)
        record = build_credential_record(nhi)
        profile = build_profile(nhi, analysis_signals)
        context = build_context(nhi, analysis_signals)

        return self._assess(
            record,
            profile,
            context,
            analysis_signals,
            repository=analysis_signals.repository,
            source=AnalysisSource.INVENTORY,
        )

    def analyze_saas_nhi(
        self,
        nhi: SaaSNHIInput,
        *,
        signals: Optional[Any] = None,
    ) -> NHIAnalysis:
        """Microsoft/Google 등 공급자 중립 SaaS NHI를 분석한다."""
        overrides: Optional[Dict[str, Any]]
        if isinstance(signals, AnalysisSignals):
            overrides = signals.to_dict()
        else:
            overrides = signals

        analysis_signals = build_saas_signals(nhi, overrides)
        record = build_saas_credential_record(nhi)
        profile = build_saas_profile(nhi, analysis_signals)
        context = build_saas_context(nhi, analysis_signals)
        return self._assess(
            record,
            profile,
            context,
            analysis_signals,
            repository="",
            source=AnalysisSource.INVENTORY,
        )

    # ------------------------------------------------------------------
    # 인벤토리 단건 분석 — Slack (GitHub 경로와 완전히 분리, GitHub 쪽은 무수정)
    # ------------------------------------------------------------------
    def analyze_slack_nhi(
        self,
        nhi: SlackNHIInput,
        *,
        signals: Optional[Any] = None,
    ) -> NHIAnalysis:
        """Slack NHI 인벤토리 1건을 스캔 경로와 같은 기준으로 분석한다.

        구조는 `analyze_github_nhi()` 와 동일하다 — Scope Translation 이후
        (`_assess()`) 로직은 provider 와 무관하게 완전히 공유된다. `signals` 는
        `AnalysisSignals` 또는 그 dict 표현을 모두 받는다.
        """
        overrides: Optional[Dict[str, Any]]
        if isinstance(signals, AnalysisSignals):
            overrides = signals.to_dict()
        else:
            overrides = signals

        analysis_signals = build_slack_signals(nhi, overrides)
        record = build_slack_credential_record(nhi)
        profile = build_slack_profile(nhi, analysis_signals)
        context = build_slack_context(nhi, analysis_signals)

        return self._assess(
            record,
            profile,
            context,
            analysis_signals,
            repository=analysis_signals.repository,
            source=AnalysisSource.INVENTORY,
        )

    # ------------------------------------------------------------------
    # 인벤토리 단건 분석 — AWS (GitHub/Slack 경로와 완전히 분리, 둘 다 무수정)
    # ------------------------------------------------------------------
    def analyze_aws_nhi(
        self,
        nhi: AWSNHIInput,
        *,
        signals: Optional[Any] = None,
    ) -> NHIAnalysis:
        """AWS IAM Access Key NHI 인벤토리 1건을 스캔 경로와 같은 기준으로 분석한다.

        구조는 `analyze_github_nhi()`/`analyze_slack_nhi()` 와 동일하다 —
        Scope Translation 이후(`_assess()`) 로직은 provider 와 무관하게
        완전히 공유된다. Policy 수집·Scope 변환은 아직 없어 `nhi.raw_scopes`
        는 항상 비어 있고, `_assess()` 는 이를 다른 provider 와 동일하게
        "Scope 미확인" 으로 처리한다(AWS 전용 예외 처리를 추가하지 않았다).
        `signals` 는 `AnalysisSignals` 또는 그 dict 표현을 모두 받는다.
        """
        overrides: Optional[Dict[str, Any]]
        if isinstance(signals, AnalysisSignals):
            overrides = signals.to_dict()
        else:
            overrides = signals

        analysis_signals = build_aws_signals(nhi, overrides)
        record = build_aws_credential_record(nhi)
        profile = build_aws_profile(nhi, analysis_signals)
        context = build_aws_context(nhi, analysis_signals)

        return self._assess(
            record,
            profile,
            context,
            analysis_signals,
            repository=analysis_signals.repository,
            source=AnalysisSource.INVENTORY,
        )

    # ------------------------------------------------------------------
    # 공통 평가 — 두 입력 경로가 여기서 합쳐진다
    # ------------------------------------------------------------------
    def _assess(
        self,
        finding: SecretFinding,
        profile: NHIProfile,
        context: ContextInsight,
        signals: AnalysisSignals,
        *,
        repository: str,
        source: AnalysisSource,
    ) -> NHIAnalysis:
        # NHI 인벤토리 입력(GitHub App/Slack/AWS 등)은 실제 Scope 가 없을 때
        # Secret 유형 기준으로 권한을 지어내면 안 된다 — `assume_if_missing`
        # 을 명시적으로 넘겨 이 경로에서만 가정하지 않게 한다(origin 쪽
        # `translate_finding(finding)` 호출은 이 인자를 생략해 기본값
        # `True` 를 그대로 쓰므로, 병합 시 이 인자를 반드시 유지해야 한다).
        permissions = self.scope_translation.translate_finding(
            finding,
            assume_if_missing=source is not AnalysisSource.INVENTORY,
        )

        # 1) canonical Usage/SecurityEvent/Scenario 분석 — EvaluationContext·
        #    강제 Critical 규칙(evaluate_forced_critical)과 이미 깊게 연결되어
        #    있으므로 그대로 유지한다. 점수 자체는 policy/scoring.py 가
        #    evaluate_forced_critical(ctx) 를 직접 호출해 계산하므로, 이
        #    블록은 점수를 바꾸지 않고 ctx/NHIAnalysis 보고 필드만 채운다.
        usage, security_events = self.usage_analysis.analyze(
            finding, profile, permissions, signals
        )
        blast = self.blast_radius.compute(finding, profile, permissions, context, signals)

        ctx = EvaluationContext(
            finding=finding,
            profile=profile,
            context=context,
            permissions=permissions,
            signals=signals,
            blast_radius=blast,
            config=self.config,
            declared_permissions=list(usage.declared_permissions),
            observed_permissions=list(usage.observed_permissions),
            source=source,
            usage_analysis=usage,
            security_events=security_events,
            scenario_matches=[],
        )

        # Scenario는 별도 조건 복제가 아니라 강제 Critical 규칙의 canonical 결과로
        # 만든다. 이 시점 이후 보고서와 RiskScorer가 같은 ScenarioMatch를 본다.
        scenario_matches = evaluate_security_scenarios(ctx)
        ctx.scenario_matches = scenario_matches

        # 2) 기존 권한 사용률 기반 Event/Scenario 매핑 — 위 canonical 경로와
        #    독립적으로 계속 계산해 별도 필드(permission_usage/events/
        #    permission_scenario_matches)로 노출한다. RecommendationAgent 의
        #    시나리오 기반 권고(GitHub App Rotation 예외 등)는 계속 이 결과에
        #    의존한다 — canonical scenario_matches 는 이름 체계가 달라
        #    RecommendationAgent 가 읽지 못한다(`scenario_name`/`matched_reason`
        #    속성이 없음).
        permission_usage = self.permission_usage.analyze(permissions, signals)
        events = self.event_extraction.extract(
            profile, permissions, permission_usage, signals=signals, context=context
        )
        permission_scenario_matches = self.scenario_mapping.map(events)

        # 정책 위반 판정이 점수보다 먼저다 (Owner·정책 관리 배점에 위반 수가 들어간다).
        violations = self.policy_evidence.collect_violations(ctx)
        risk = self.risk_scoring.score(ctx, violations)
        policy = self.policy_evidence.decide(ctx, risk, violations)
        recommendations = self.recommendation.recommend(
            ctx, risk, policy, scenario_matches=permission_scenario_matches
        )

        return NHIAnalysis(
            fingerprint=finding.fingerprint,
            repository=repository,
            file_path=finding.file_path,
            line_number=finding.line_number,
            masked_value=finding.masked_value,
            profile=profile,
            context=context,
            permissions=permissions,
            risk=risk,
            policy=policy,
            usage_analysis=usage,
            security_events=security_events,
            scenario_matches=scenario_matches,
            recommendations=recommendations,
            blast_radius=blast,
            source=source,
            permission_usage=permission_usage,
            events=events,
            permission_scenario_matches=permission_scenario_matches,
            replay_snapshot=_build_replay_snapshot(finding, signals),
        )

    # ------------------------------------------------------------------
    # 묶음 분석
    # ------------------------------------------------------------------
    def analyze_findings(
        self,
        findings: Iterable[SecretFinding],
        *,
        repository: str = "",
        default_signals: Optional[AnalysisSignals] = None,
        signals_by_fingerprint: Optional[Dict[str, AnalysisSignals]] = None,
        build_graph: bool = True,
    ) -> NHIAnalysisReport:
        overrides = signals_by_fingerprint or {}
        report = NHIAnalysisReport(repository=repository)
        graph = RelationshipGraph()

        for finding in findings:
            signals = overrides.get(finding.fingerprint) or self._clone_signals(
                default_signals, repository
            )
            analysis = self.analyze_finding(finding, signals=signals, repository=repository)
            report.analyses.append(analysis)
            if build_graph:
                graph.add_chain(
                    analysis.profile,
                    analysis.permissions,
                    analysis.blast_radius,
                    repository=repository,
                )

        report.analyses.sort(key=lambda a: a.risk.score, reverse=True)
        if build_graph:
            report.graph = graph.to_dict()
        return report

    def analyze_scan_result(
        self,
        scan_result: Any,
        *,
        default_signals: Optional[AnalysisSignals] = None,
        signals_by_fingerprint: Optional[Dict[str, AnalysisSignals]] = None,
    ) -> NHIAnalysisReport:
        """`ScanResult` 또는 그 `to_dict()` 결과를 받아 분석한다."""
        if isinstance(scan_result, ScanResult):
            repository = scan_result.repository
            findings: Sequence[SecretFinding] = scan_result.findings
        elif isinstance(scan_result, dict):
            repository = scan_result.get("repository", "")
            findings = [finding_from_dict(f) for f in scan_result.get("findings", [])]
        else:
            raise TypeError("scan_result 는 ScanResult 또는 dict 여야 한다")

        return self.analyze_findings(
            findings,
            repository=repository,
            default_signals=default_signals,
            signals_by_fingerprint=signals_by_fingerprint,
        )

    # ------------------------------------------------------------------
    def build_graph(self, analyses: Iterable[NHIAnalysis]) -> RelationshipGraph:
        """분석 결과들로 관계 그래프를 만든다 (여러 스캔 결과 합성용)."""
        graph = RelationshipGraph()
        for analysis in analyses:
            graph.add_chain(
                analysis.profile,
                analysis.permissions,
                analysis.blast_radius,
                repository=analysis.repository,
            )
        return graph

    @staticmethod
    def blast_radius_summary(analyses: Iterable[NHIAnalysis]) -> Dict[str, Any]:
        return summarize_blast_radius(a.blast_radius for a in analyses)

    @staticmethod
    def _clone_signals(
        signals: Optional[AnalysisSignals], repository: str
    ) -> AnalysisSignals:
        """기본 신호를 finding 별로 복제한다 (파이프라인이 값을 채우므로 공유 금지)."""
        if signals is None:
            return AnalysisSignals(repository=repository)
        clone = AnalysisSignals.from_dict(signals.to_dict())
        if repository and not clone.repository:
            clone.repository = repository
        return clone
