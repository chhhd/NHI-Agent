"""POST /integrations/github/discover — 수집 → 분석 → 영속화 → 감사 → 이력 연동 검증."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from agent_runtime.models import GitHubInventoryAgentRequest
from agent_runtime.tools import build_tool_registry as real_build_tool_registry
from connectors.github_connector import GitHubOrganizationDiscoveryResult
from core.config import reset_settings
from storage.sqlite_store import SQLiteStorage

from tests.helpers_app import load_private_app, unload_private_app
from tests.test_agent_runtime import _StubInventoryConnector

ADMIN = "bootstrap-shared-key-0123456789abcdef0123"


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("NHI_ADMIN_API_KEY", ADMIN)
    module, name = load_private_app(tmp_path, monkeypatch)
    module.storage = SQLiteStorage(":memory:")
    reset_settings()
    yield module
    module.storage.close()
    unload_private_app(module, name)


def use_collection(app, monkeypatch, nhi_items, *, complete=True, truncated_total=None):
    collection = _StubInventoryConnector(
        GitHubOrganizationDiscoveryResult(
            organization="acme",
            items=nhi_items,
            total_count=truncated_total if truncated_total is not None else len(nhi_items),
            pages_fetched=1,
            inventory_complete=complete,
        )
    )
    monkeypatch.setattr(
        app,
        "build_tool_registry",
        lambda **_: real_build_tool_registry(
            collection_connector_factory=lambda: collection,
            connector_factory=lambda: (_ for _ in ()).throw(AssertionError("스캔 커넥터는 쓰지 않는다")),
        ),
    )
    return collection


def request(**kwargs):
    return GitHubInventoryAgentRequest(organization="acme", inventory_limit=25, **kwargs)


def test_requires_an_admin_key(app, monkeypatch, high_risk_nhi):
    use_collection(app, monkeypatch, [high_risk_nhi])
    with pytest.raises(HTTPException) as exc:
        app.discover_github_nhi(request(), x_nhi_admin_key=None)
    assert exc.value.status_code == 401


def test_collects_analyzes_persists_and_audits_without_leaking_inventory(
    app, monkeypatch, high_risk_nhi, low_risk_nhi
):
    high = high_risk_nhi.model_copy(deep=True, update={"nhi_id": "installation:101"})
    low = low_risk_nhi.model_copy(deep=True, update={"nhi_id": "installation:102"})
    use_collection(app, monkeypatch, [low, high])

    result = app.discover_github_nhi(request(), x_nhi_admin_key=ADMIN)

    assert result["persistence_failures"] == []
    assert len(result["persistence"]) == 2 and len(result["observation_ids"]) == 2
    summary = result["run_summary"]
    assert summary["collection"]["inventory_complete"] is True
    assert summary["persistence"]["complete"] is True
    assert summary["analysis"]["count"] == 2

    # 분석 결과가 NHI 인벤토리와 5B 이력 API 로 이어진다
    ids = {item["nhi_id"] for item in app.storage.list_nhi_records(limit=10)}
    assert {"github:installation:101", "github:installation:102"} <= ids
    history = app.get_nhi_analysis_history("github:installation:101")
    assert history["count"] == 1

    audit = [e for e in app.storage.list_audit_events() if e["event_type"] == "GITHUB_INVENTORY_AGENT_COMPLETED"]
    assert len(audit) == 1
    assert audit[0]["target"] == "acme"
    assert "items" not in audit[0]["detail"] and "inventory" not in audit[0]["detail"]


def test_partial_collection_is_reported_as_incomplete_not_as_clean(app, monkeypatch, high_risk_nhi):
    item = high_risk_nhi.model_copy(deep=True, update={"nhi_id": "installation:7"})
    use_collection(app, monkeypatch, [item], complete=False, truncated_total=40)
    result = app.discover_github_nhi(request(), x_nhi_admin_key=ADMIN)
    collection = result["run_summary"]["collection"]
    assert collection["inventory_complete"] is False
    assert collection["total_count"] == 40 and collection["count"] == 1


def test_connector_failure_is_surfaced_as_http_error_and_nothing_is_persisted(app, monkeypatch):
    class Broken:
        def discover_organization_apps(self, *args, **kwargs):
            from connectors.base_connector import PermissionDeniedError

            raise PermissionDeniedError("조직 Administration read 권한 없음")

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        app,
        "build_tool_registry",
        lambda **_: real_build_tool_registry(collection_connector_factory=lambda: Broken()),
    )
    with pytest.raises(HTTPException) as exc:
        app.discover_github_nhi(request(), x_nhi_admin_key=ADMIN)
    assert exc.value.status_code in (403, 502)
    assert app.storage.list_nhi_records(limit=10) == []
