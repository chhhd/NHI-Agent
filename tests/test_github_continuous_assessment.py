"""GitHub Audit Log 지속평가와 개인정보 최소화 통합 테스트."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from backend.services.github_continuous_assessment import (
    GitHubContinuousAssessmentService,
)
from connectors.github_connector import (
    GitHubAuditLogResult,
    GitHubConnector,
    GitHubOrganizationDiscoveryResult,
)
from connectors.base_connector import AuthenticationError
from core.config import PrivacySettings, reset_settings
from core.inventory_models import GitHubNHIInput, GitHubNHIType
from core.usage_models import UsageEvent
from normalization.github_audit import GitHubAuditNormalizer
from security.privacy import PrivacyProtector
from storage.sqlite_store import SQLiteStorage


def _identity() -> GitHubNHIInput:
    return GitHubNHIInput(
        nhi_id="github-app-installation:42",
        nhi_name="deploy-app@acme",
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner=None,
        account={
            "installation_id": 42,
            "app_id": 9001,
            "app_slug": "deploy-app",
        },
        raw_permissions={"contents": "read", "administration": "write"},
        repository_inventory_complete=False,
        inventory_is_complete=True,
    )


def _privacy() -> PrivacyProtector:
    return PrivacyProtector(
        PrivacySettings(
            mode="strict",
            pseudonymization_key="unit-test-privacy-key-that-is-long-enough",
            usage_retention_days=90,
            usage_min_coverage_days=30,
        )
    )


def test_github_audit_normalizer_removes_direct_identifiers():
    actor = "deploy-app[bot]"
    ip = "203.0.113.99"
    user_agent = "Mozilla/5.0 full identifying string"
    result = GitHubAuditNormalizer(_privacy()).normalize(
        [
            {
                "_document_id": "github-document-1",
                "created_at": 1_799_000_000_000,
                "action": "contents:write",
                "actor": actor,
                "actor_ip": ip,
                "user_agent": user_agent,
                "repo": "acme/private-repo",
            },
            {
                "_document_id": "unrelated-human-event",
                "created_at": 1_799_000_000_000,
                "action": "repo.access",
                "actor": "alice-personal-login",
                "actor_ip": "198.51.100.7",
            },
        ],
        identities=[_identity()],
    )

    assert result.matched_nhi_event_count == 1
    assert result.unmatched_actor_event_count == 1
    assert len(result.events) == 1
    event = result.events[0]
    serialized = str(event.to_dict())
    assert event.principal_id == "github:github-app-installation:42"
    assert actor not in serialized
    assert ip not in serialized
    assert user_agent not in serialized
    assert event.attributes["network"].startswith("network:")
    assert event.attributes["user_agent_family"] == "browser"


def test_audit_connector_never_falls_back_to_repository_scan_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "scan-token-must-not-be-reused")
    monkeypatch.delenv("GITHUB_AUDIT_TOKEN", raising=False)
    reset_settings()
    try:
        with GitHubConnector.for_audit() as connector:
            assert connector.token == ""
            try:
                connector.collect_organization_audit_log("acme")
            except AuthenticationError as exc:
                assert "GITHUB_AUDIT_TOKEN" in str(exc)
            else:  # pragma: no cover
                raise AssertionError("Audit Log 수집은 별도 토큰 없이 실행되면 안 됩니다.")
    finally:
        reset_settings()


def test_usage_event_storage_is_idempotent_and_enforces_retention():
    store = SQLiteStorage(":memory:")
    try:
        now = datetime.now(timezone.utc)
        current = UsageEvent(
            event_id="event-current",
            provider="github",
            principal_id="github:app-1",
            action="contents:read",
            occurred_at=now.isoformat(),
        )
        expired = UsageEvent(
            event_id="event-expired",
            provider="github",
            principal_id="github:app-1",
            action="contents:read",
            occurred_at=(now - timedelta(days=40)).isoformat(),
        )
        first = store.save_usage_events([current, expired], retention_days=30)
        second = store.save_usage_events([current], retention_days=30)

        assert first["inserted"] == 1
        assert first["expired_skipped"] == 1
        assert second["duplicates"] == 1
        assert [event.event_id for event in store.list_usage_events()] == [
            "event-current"
        ]
    finally:
        store.close()


class _InventoryConnector:
    def discover_organization_apps(self, organization: str, *, limit: int):
        return GitHubOrganizationDiscoveryResult(
            organization=organization,
            items=[_identity()],
            total_count=1,
            pages_fetched=1,
            inventory_complete=True,
        )


class _AuditConnector:
    def collect_organization_audit_log(self, organization: str, *, since: str, limit: int):
        return GitHubAuditLogResult(
            organization=organization,
            events=[
                {
                    "_document_id": "document-sensitive-link-id",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "action": "contents:write",
                    "actor": "deploy-app[bot]",
                    "actor_ip": "203.0.113.21",
                    "user_agent": "curl/8.0 secret-client-detail",
                    "repo": "acme/backend",
                }
            ],
            pages_fetched=1,
            collection_complete=True,
            latest_cursor=datetime.now(timezone.utc).isoformat(),
        )


def test_continuous_assessment_persists_analysis_and_action_without_raw_pii():
    store = SQLiteStorage(":memory:")
    privacy = _privacy()
    since = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    try:
        result = GitHubContinuousAssessmentService(
            store,
            inventory_connector=_InventoryConnector(),
            audit_connector=_AuditConnector(),
            privacy=privacy,
        ).run("acme", since=since)

        assert result["summary"]["analysis_count"] == 1
        assert result["summary"]["audit_collection"][
            "absence_based_decisions_allowed"
        ] is True
        assert result["summary"]["privacy"]["raw_actor_persisted"] is False
        assert result["action_ids"]
        stored = str([event.to_dict() for event in store.list_usage_events()])
        assert "deploy-app[bot]" not in stored
        assert "203.0.113.21" not in stored
        assert "secret-client-detail" not in stored
        assert store.get_collection_checkpoint(
            provider="github", source="organization_audit_log", scope="acme"
        ) is not None
    finally:
        store.close()


def test_github_audit_connector_paginates_without_returning_raw_in_summary():
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        if page == 1:
            return httpx.Response(
                200,
                json=[{"_document_id": "one", "created_at": 1, "action": "a"}],
                headers={
                    "Link": '<https://api.github.com/orgs/acme/audit-log?page=2>; rel="next"'
                },
            )
        return httpx.Response(
            200,
            json=[{"_document_id": "two", "created_at": 2, "action": "b"}],
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with GitHubConnector("audit-token", client=client) as connector:
        result = connector.collect_organization_audit_log("acme", limit=10)

    assert result.pages_fetched == 2
    assert result.collection_complete is True
    assert len(result.events) == 2
    assert "events" not in result.summary()
    assert "one" not in str(result.summary())
