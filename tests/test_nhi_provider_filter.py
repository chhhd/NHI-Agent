"""GET /nhi?provider=... — provider 필터 테스트.

`provider` 를 생략하면 기존과 동일하게 전체를 반환해야 한다. 지정하면 정확히
일치하는 레코드만 반환하고, 저장된 레코드가 없는 provider(오타 포함)는
오류가 아니라 빈 목록으로 처리해야 한다. 기존 응답 구조
(`{"count": int, "nhi": [...]}`) 는 그대로 유지된다.
"""

from __future__ import annotations

import os

import pytest

from core.config import reset_settings


@pytest.fixture(autouse=True)
def _no_default_tokens(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    reset_settings()
    yield
    reset_settings()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """임시 DB 경로를 지정한 뒤 앱을 로딩한다 (프로젝트 디렉터리 오염 방지)."""
    os.environ["NHI_DB_PATH"] = str(tmp_path_factory.mktemp("db") / "test.db")
    from fastapi.testclient import TestClient

    import api.app as app_module

    return TestClient(app_module.app)


@pytest.fixture(scope="module", autouse=True)
def _seed_records(client):
    """provider 가 다른 NHI 레코드 3건을 직접 저장소에 심어둔다.

    라이브 커넥터/파이프라인 없이 필터링 자체만 검증하면 되므로
    `storage.upsert_nhi()` 로 최소 shape 만 직접 저장한다.
    """
    import api.app as app_module

    app_module.storage.upsert_nhi(
        "github:seed-1",
        {"nhi_id": "github:seed-1", "provider": "github", "nhi_name": "octocat", "owner": None},
    )
    app_module.storage.upsert_nhi(
        "slack:seed-1",
        {"nhi_id": "slack:seed-1", "provider": "slack", "nhi_name": "support-bot", "owner": None},
    )
    app_module.storage.upsert_nhi(
        "aws:seed-1",
        {"nhi_id": "aws:seed-1", "provider": "aws", "nhi_name": "ci-deploy-user", "owner": None},
    )


# ---------------------------------------------------------------------------
# provider 생략 — 기존과 동일하게 전체 반환
# ---------------------------------------------------------------------------
def test_no_provider_returns_all_records(client):
    response = client.get("/nhi")

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"count", "nhi"}
    ids = {item["nhi_id"] for item in body["nhi"]}
    assert {"github:seed-1", "slack:seed-1", "aws:seed-1"} <= ids
    assert body["count"] == len(body["nhi"])


# ---------------------------------------------------------------------------
# provider 지정 — 정확히 일치하는 것만
# ---------------------------------------------------------------------------
def test_provider_aws_returns_only_aws_records(client):
    """`storage` 는 프로세스 전역 싱글턴이라(`get_default_storage()`) 전체
    테스트 스위트를 한 프로세스로 같이 돌리면 다른 테스트 파일이 심어둔
    aws 레코드도 함께 보일 수 있다 — 그래서 "정확히 1건"이 아니라 "필터
    결과에 다른 provider 가 섞이지 않는지"와 "이 파일이 심은 레코드가
    포함되는지"만 확인한다."""
    response = client.get("/nhi", params={"provider": "aws"})

    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert all(item["provider"] == "aws" for item in body["nhi"])
    assert any(item["nhi_id"] == "aws:seed-1" for item in body["nhi"])


def test_provider_slack_returns_only_slack_records(client):
    response = client.get("/nhi", params={"provider": "slack"})

    body = response.json()
    assert body["count"] >= 1
    assert all(item["provider"] == "slack" for item in body["nhi"])
    assert any(item["nhi_id"] == "slack:seed-1" for item in body["nhi"])


def test_provider_github_returns_only_github_records(client):
    response = client.get("/nhi", params={"provider": "github"})

    body = response.json()
    assert body["count"] >= 1
    assert all(item["provider"] == "github" for item in body["nhi"])
    assert any(item["nhi_id"] == "github:seed-1" for item in body["nhi"])


# ---------------------------------------------------------------------------
# 존재하지 않는/잘못된 provider — 오류가 아니라 빈 결과
# ---------------------------------------------------------------------------
def test_unknown_provider_returns_empty_result_not_error(client):
    response = client.get("/nhi", params={"provider": "not-a-real-provider"})

    assert response.status_code == 200
    assert response.json() == {"count": 0, "nhi": []}


def test_empty_string_provider_is_treated_as_a_literal_filter_value(client):
    """빈 문자열도 유효한 쿼리 파라미터 값이다 — 파싱 오류 없이 처리되고,
    일치하는 레코드가 없으므로 빈 결과가 된다."""
    response = client.get("/nhi", params={"provider": ""})

    assert response.status_code == 200
    assert response.json() == {"count": 0, "nhi": []}


# ---------------------------------------------------------------------------
# 응답 구조 자체는 바뀌지 않았는지
# ---------------------------------------------------------------------------
def test_response_shape_is_unchanged_with_provider_filter(client):
    response = client.get("/nhi", params={"provider": "aws"})

    body = response.json()
    assert set(body.keys()) == {"count", "nhi"}
    assert isinstance(body["nhi"], list)
    assert isinstance(body["count"], int)


def test_limit_and_provider_can_be_combined(client):
    """`limit=1` 은 세션 전역 상태와 무관하게 항상 정확히 지켜져야 한다 —
    어떤 aws 레코드가 반환되는지(순서)는 다른 테스트 파일의 삽입 순서에
    따라 달라질 수 있으므로 개수와 provider 일치만 확인한다."""
    response = client.get("/nhi", params={"provider": "aws", "limit": 1})

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert len(body["nhi"]) == 1
    assert body["nhi"][0]["provider"] == "aws"
