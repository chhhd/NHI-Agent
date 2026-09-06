"""processing/analysis_persistence.py::persist_analysis() 의 `provider_detail` 저장.

`provider_detail` 은 선택 인자다 — 넘기지 않으면 기존 호출부(GitHub/Slack/
스캔 경로 등)와 완전히 동일하게 동작해야 한다(`nhi_data` 에 새 키가 생기지
않음). 넘기면 `nhi_data["provider_detail"]` 에 그대로 저장돼 `GET /nhi`/
`GET /nhi/{nhi_id}` 응답에 그대로 노출돼야 한다. 이번 단계에서는 저장 구조만
다루며, GitHub/Slack 호출부가 실제로 `provider_detail` 을 채우는 것은 범위
밖이다(AWS 엔드포인트만 채운다 — `tests/test_aws_api.py` 참고).
"""

from __future__ import annotations

import pytest

from agents.pipeline import NHIAnalysisPipeline
from core.nhi_models import AnalysisSignals
from processing import persist_analysis
from storage.sqlite_store import SQLiteStorage
from tests.test_nhi_agents import make_finding


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def _analysis():
    finding = make_finding(credential_active=True)
    return NHIAnalysisPipeline().analyze_finding(
        finding,
        repository="acme/support",
        signals=AnalysisSignals(repository_public=True),
    )


def test_provider_detail_omitted_by_default_keeps_existing_shape(store):
    """provider_detail 을 넘기지 않으면 nhi_data 에 그 키 자체가 생기지 않는다 —
    기존 GitHub/Slack/스캔 경로 호출부와 완전히 동일해야 한다."""
    analysis = _analysis()

    persist_analysis(store, analysis)

    record = store.get_nhi_record(analysis.profile.nhi_id)
    assert record is not None
    assert "provider_detail" not in record


def test_provider_detail_none_explicitly_keeps_existing_shape(store):
    analysis = _analysis()

    persist_analysis(store, analysis, provider_detail=None)

    record = store.get_nhi_record(analysis.profile.nhi_id)
    assert "provider_detail" not in record


def test_provider_detail_is_stored_verbatim(store):
    analysis = _analysis()
    detail = {
        "aws": {
            "access_key_id": "AKIAEXAMPLE00000000",
            "broad_access": True,
            "policy_fetch_errors": ["PolicyX 문서 조회 실패: 500"],
        }
    }

    persist_analysis(store, analysis, provider_detail=detail)

    record = store.get_nhi_record(analysis.profile.nhi_id)
    assert record["provider_detail"] == detail


def test_provider_detail_is_reflected_in_list_nhi_records(store):
    analysis = _analysis()
    detail = {"aws": {"access_key_id": "AKIAEXAMPLE00000000", "broad_access": False, "policy_fetch_errors": []}}

    persist_analysis(store, analysis, provider_detail=detail)

    records = store.list_nhi_records()
    record = next(item for item in records if item["nhi_id"] == analysis.profile.nhi_id)
    assert record["provider_detail"] == detail


def test_provider_detail_does_not_affect_other_persisted_fields(store):
    """provider_detail 추가가 기존에 저장되던 다른 필드 값을 바꾸면 안 된다."""
    analysis = _analysis()

    without = persist_analysis(store, analysis)
    record_without = store.get_nhi_record(analysis.profile.nhi_id)

    with_detail = persist_analysis(
        store, analysis, provider_detail={"aws": {"access_key_id": "AKIAX"}}
    )
    record_with = store.get_nhi_record(analysis.profile.nhi_id)

    for key in ("risk_score", "risk_level", "recommended_action", "permissions", "raw_scopes"):
        assert record_without[key] == record_with[key]
