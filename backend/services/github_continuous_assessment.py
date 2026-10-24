"""GitHub 인벤토리와 Audit Log를 기존 NHI 분석·조치 흐름으로 연결한다."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from agents.pipeline import NHIAnalysisPipeline
from connectors.github_connector import GitHubConnector
from core.nhi_models import AnalysisSignals, parse_dt
from normalization.github_audit import GitHubAuditNormalizer, canonical_nhi_id
from normalization.usage_event_adapter import UsageEventAdapter
from normalization import observation_from_inventory
from processing.analysis_persistence import persist_analysis
from security.privacy import PrivacyProtector
from security.redaction import sanitize_security_text
from storage.base import Storage


SOURCE = "organization_audit_log"


class GitHubContinuousAssessmentService:
    """수집 → 최소화 → 사용 분석 → 위험 재평가 → 조치 생성의 단일 흐름."""

    def __init__(
        self,
        storage: Storage,
        *,
        inventory_connector: GitHubConnector,
        audit_connector: GitHubConnector,
        pipeline: Optional[NHIAnalysisPipeline] = None,
        privacy: Optional[PrivacyProtector] = None,
    ) -> None:
        self.storage = storage
        self.inventory_connector = inventory_connector
        self.audit_connector = audit_connector
        self.pipeline = pipeline or NHIAnalysisPipeline()
        self.privacy = privacy or PrivacyProtector()

    def run(
        self,
        organization: str,
        *,
        inventory_limit: int = 100,
        audit_limit: int = 1000,
        since: Optional[str] = None,
        signals: Optional[Dict[str, Any]] = None,
        signals_by_nhi_id: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        settings = self.privacy.settings
        retention_days = min(max(settings.usage_retention_days, 1), 365)
        minimum_days = min(max(settings.usage_min_coverage_days, 1), retention_days)
        checkpoint = self.storage.get_collection_checkpoint(
            provider="github", source=SOURCE, scope=organization
        )
        query_since, prior_start = self._collection_window(since, checkpoint)

        inventory = self.inventory_connector.discover_organization_apps(
            organization, limit=inventory_limit
        )
        audit = self.audit_connector.collect_organization_audit_log(
            organization, since=query_since, limit=audit_limit
        )
        normalized = GitHubAuditNormalizer(self.privacy).normalize(
            audit.events,
            identities=inventory.items,
            since=query_since,
        )
        storage_result = self.storage.save_usage_events(
            normalized.events, retention_days=retention_days
        )

        current_complete = (
            audit.collection_complete
            and normalized.invalid_event_count == 0
            and normalized.unmatched_programmatic_event_count == 0
        )
        collected_at = datetime.now(timezone.utc)
        coverage_start = prior_start or query_since
        coverage_end = collected_at.isoformat()
        coverage_days = self._coverage_days(coverage_start, coverage_end)
        coverage_complete = current_complete and coverage_days >= minimum_days

        analyses: List[Dict[str, Any]] = []
        persistence_failures: List[Dict[str, str]] = []
        action_ids: List[str] = []
        saturated_nhi_count = 0
        adapter = UsageEventAdapter()
        overrides = signals_by_nhi_id or {}
        for item in inventory.items:
            nhi_id = canonical_nhi_id(item)
            observation = observation_from_inventory(item)
            self.storage.save_observation(observation)
            events = self.storage.list_usage_events(
                principal_id=nhi_id,
                provider="github",
                since=coverage_start,
                limit=10001,
            )
            event_limit_reached = len(events) > 10000
            if event_limit_reached:
                saturated_nhi_count += 1
            derived = adapter.to_signals(
                events[:10000],
                principal_ids=[nhi_id],
                declared_permissions=item.scopes,
                data_complete=coverage_complete and not event_limit_reached,
            )
            derived.extra.update(
                {
                    "usage_collection_complete": current_complete,
                    "usage_coverage_start": coverage_start,
                    "usage_coverage_end": coverage_end,
                    "usage_coverage_days": coverage_days,
                    "usage_minimum_coverage_days": minimum_days,
                    "usage_event_limit_reached": event_limit_reached,
                    "privacy_mode": self.privacy.mode,
                }
            )
            base_payload = dict(signals or {})
            specific = overrides.get(item.nhi_id) or overrides.get(nhi_id) or {}
            for key, value in specific.items():
                if key == "extra" and isinstance(value, dict):
                    extra = dict(base_payload.get("extra") or {})
                    extra.update(value)
                    base_payload["extra"] = extra
                else:
                    base_payload[key] = value
            merged = adapter.merge_into_signals(
                AnalysisSignals.from_dict(base_payload), derived
            )
            # 이미 조회한 타임스탬프 있는 UsageEvent 목록을 그대로 논문 기반
            # 시나리오 평가(ER·EC·PW·FR·UR)에도 넘긴다 — risk_score 계산에는
            # 영향 없는 부가 평가다. ER 매핑표가 아직 비어 있어 1차 구현에서는
            # UNCONFIGURED_WEIGHT 로 귀결되지만, GitHub 이벤트는 실제로 연결된다.
            analysis = self.pipeline.analyze_github_nhi(
                item, signals=merged, usage_events=events[:10000]
            )
            payload = analysis.to_dict()
            try:
                saved = persist_analysis(
                    self.storage,
                    analysis,
                    input_revision=(
                        derived.extra.get("usage_source_event_id")
                        or audit.latest_cursor
                        or observation.source_event_id
                    ),
                )
                payload["persistence"] = saved
                action_ids.extend(str(value) for value in saved.get("action_ids", []))
            except Exception as exc:
                persistence_failures.append(
                    {
                        "nhi_id": item.nhi_id,
                        "error": type(exc).__name__,
                    }
                )
            analyses.append(payload)

        checkpoint_detail = {
            "coverage_start": coverage_start,
            "coverage_end": coverage_end,
            "coverage_days": coverage_days,
            "coverage_complete": coverage_complete,
            "last_collection_complete": current_complete,
            "event_count": len(normalized.events),
        }
        # 불완전 수집은 다음 증분 수집 기준을 전진시키지 않는다.
        next_cursor = coverage_end if current_complete else (
            checkpoint.get("cursor") if checkpoint else None
        )
        self.storage.save_collection_checkpoint(
            provider="github",
            source=SOURCE,
            scope=organization,
            cursor=next_cursor,
            detail=checkpoint_detail,
        )

        summary = {
            "kind": "github_continuous_assessment",
            "organization": sanitize_security_text(organization),
            "inventory": {
                "count": len(inventory.items),
                "complete": inventory.inventory_complete,
                "truncated": inventory.retrieval_truncated,
                "parse_failure_count": len(inventory.failures),
            },
            "audit_collection": {
                **audit.summary(),
                **normalized.summary(),
                "effective_complete": current_complete,
                "query_since": query_since,
                "coverage_start": coverage_start,
                "coverage_end": coverage_end,
                "coverage_days": coverage_days,
                "minimum_coverage_days": minimum_days,
                "absence_based_decisions_allowed": coverage_complete,
            },
            "storage": {**storage_result, "retention_days": retention_days},
            "privacy": self.privacy.summary().to_dict(),
            "analysis_count": len(analyses),
            "action_request_count": len(set(action_ids)),
            "event_limit_reached_nhi_count": saturated_nhi_count,
            "persistence_failure_count": len(persistence_failures),
        }
        audit_event_id = self.storage.append_audit_event(
            "GITHUB_CONTINUOUS_ASSESSMENT_COMPLETED",
            actor="github-continuous-assessment",
            target=organization,
            detail=summary,
        )
        return {
            "summary": summary,
            "analyses": analyses,
            "action_ids": sorted(set(action_ids)),
            "persistence_failures": persistence_failures,
            "audit_event_id": audit_event_id,
        }

    @staticmethod
    def _collection_window(
        explicit_since: Optional[str], checkpoint: Optional[Dict[str, Any]]
    ) -> tuple[str, Optional[str]]:
        if explicit_since:
            parsed = parse_dt(explicit_since)
            if parsed is None:
                raise ValueError("since는 ISO 8601 시각이어야 합니다.")
            previous_start = None
            if checkpoint:
                previous_start = (checkpoint.get("detail") or {}).get("coverage_start")
            starts = [value for value in (parsed.isoformat(), previous_start) if parse_dt(value)]
            return parsed.isoformat(), min(starts, key=lambda value: parse_dt(value))

        if checkpoint and checkpoint.get("cursor"):
            cursor = parse_dt(str(checkpoint["cursor"]))
            detail = checkpoint.get("detail") or {}
            if cursor is not None:
                # 경계 시각의 지연 이벤트를 놓치지 않도록 5분 겹쳐 수집한다.
                return (cursor - timedelta(minutes=5)).isoformat(), detail.get("coverage_start")

        start = datetime.now(timezone.utc) - timedelta(days=1)
        return start.isoformat(), None

    @staticmethod
    def _coverage_days(start: str, end: str) -> int:
        start_dt = parse_dt(start)
        end_dt = parse_dt(end)
        if start_dt is None or end_dt is None or end_dt < start_dt:
            return 0
        return (end_dt - start_dt).days


__all__ = ["GitHubContinuousAssessmentService"]
