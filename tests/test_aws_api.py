"""POST /nhi/aws/inventory/analyze — API 엔드포인트 테스트.

`AWSConnector` 는 `BaseConnector` 를 상속하지 않아(SigV4 인증) 다른
provider 들처럼 `httpx.MockTransport` 로 감쌀 수 없다 — `botocore.stub.Stubber`
로 sts/iam 클라이언트를 대체한다(`tests/test_aws_connector.py`,
`tests/test_aws_inventory_service.py` 와 동일한 패턴).

기존 GitHub/Slack 엔드포인트(`/nhi/github/inventory/analyze`,
`/nhi/github/app/inventory/analyze`, `/nhi/slack/inventory/analyze`)는
건드리지 않는다. `provider_detail` 저장 구조도 이번 범위에 포함하지 않는다 —
응답/저장 모양은 GitHub/Slack 과 동일하게 `NHIAnalysis.to_dict()` 그대로다.
"""

from __future__ import annotations

import os

import boto3
import pytest
from botocore.stub import Stubber

from core.config import reset_settings


@pytest.fixture(autouse=True)
def _no_default_tokens(monkeypatch):
    """Agent 실행 등에서 실제 외부 호출이 나가지 않게 한다."""
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


def _dummy_session(access_key_id: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key="dummy-secret",
        region_name="us-east-1",
    )


@pytest.fixture(scope="module")
def sts_client():
    return _dummy_session("AKIAFIXTURESESSION00").client("sts")


@pytest.fixture(scope="module")
def iam_client():
    return _dummy_session("AKIAFIXTURESESSION00").client("iam")


def _patch_connector_factory(monkeypatch, app_module, sts_client, iam_client, *, current_access_key_id):
    from connectors.aws_connector import AWSConnector

    def connector_factory():
        return AWSConnector(
            session=_dummy_session(current_access_key_id),
            sts_client=sts_client,
            iam_client=iam_client,
        )

    monkeypatch.setattr(app_module, "AWSConnector", connector_factory)


# ---------------------------------------------------------------------------
# 정상 흐름
# ---------------------------------------------------------------------------
def test_aws_inventory_endpoint_returns_analysis_and_persists_it(
    client, monkeypatch, sts_client, iam_client
):
    import api.app as app_module

    _patch_connector_factory(
        monkeypatch, app_module, sts_client, iam_client,
        current_access_key_id="AKIACURRENTKEY00000",
    )

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {
                "Account": "123456789012",
                "UserId": "AIDAEXAMPLE123456789",
                "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user",
            },
        )
        iam_stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "ci-deploy-user",
                        "AccessKeyId": "AKIACURRENTKEY00000",
                        "Status": "Active",
                    }
                ]
            },
            {},
        )
        iam_stub.add_response(
            "get_access_key_last_used",
            {
                "UserName": "ci-deploy-user",
                "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"},
            },
            {"AccessKeyId": "AKIACURRENTKEY00000"},
        )
        iam_stub.add_response(
            "list_attached_user_policies",
            {"AttachedPolicies": [], "IsTruncated": False},
            {"UserName": "ci-deploy-user", "MaxItems": 100},
        )

        response = client.post("/nhi/aws/inventory/analyze")

    assert response.status_code == 200
    body = response.json()
    assert body["nhi_name"] == "ci-deploy-user"
    assert body["source"] == "inventory"
    assert "persistence" in body

    records = client.get("/nhi").json()["nhi"]
    record = next(
        item for item in records
        if item["nhi_id"] == "aws:aws-123456789012-AKIACURRENTKEY00000"
    )
    assert record["risk_score"] == body["risk_score"]
    assert record["risk_level"] == body["risk_level"]

    # provider_detail — AWS 고유 필드(access_key_id/broad_access/policy_fetch_errors)가
    # 저장된 레코드에 그대로 실려 있어야 한다.
    assert record["provider_detail"]["aws"] == {
        "access_key_id": "AKIACURRENTKEY00000",
        "broad_access": False,
        "policy_fetch_errors": [],
    }


# ---------------------------------------------------------------------------
# 예외 매핑
# ---------------------------------------------------------------------------
def test_aws_inventory_endpoint_returns_401_when_credentials_invalid(
    client, monkeypatch, sts_client, iam_client
):
    import api.app as app_module

    _patch_connector_factory(
        monkeypatch, app_module, sts_client, iam_client,
        current_access_key_id="AKIAINVALIDKEY00000",
    )

    with Stubber(sts_client) as sts_stub:
        sts_stub.add_client_error(
            "get_caller_identity",
            service_error_code="InvalidClientTokenId",
            service_message="The security token included in the request is invalid.",
            http_status_code=403,
        )

        response = client.post("/nhi/aws/inventory/analyze")

    assert response.status_code == 401


def test_aws_inventory_endpoint_returns_403_when_permission_denied(
    client, monkeypatch, sts_client, iam_client
):
    import api.app as app_module

    _patch_connector_factory(
        monkeypatch, app_module, sts_client, iam_client,
        current_access_key_id="AKIACURRENTKEY00000",
    )

    with Stubber(sts_client) as sts_stub, Stubber(iam_client) as iam_stub:
        sts_stub.add_response(
            "get_caller_identity",
            {
                "Account": "123456789012",
                "UserId": "AIDAEXAMPLE123456789",
                "Arn": "arn:aws:iam::123456789012:user/ci-deploy-user",
            },
        )
        iam_stub.add_client_error(
            "list_access_keys",
            service_error_code="AccessDenied",
            service_message="User is not authorized to perform: iam:ListAccessKeys",
            http_status_code=403,
        )

        response = client.post("/nhi/aws/inventory/analyze")

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# 기존 GitHub/Slack 엔드포인트는 영향받지 않았는지
# ---------------------------------------------------------------------------
def test_slack_inventory_endpoint_still_registered_and_independent(client, monkeypatch):
    import httpx

    import api.app as app_module
    from connectors.slack_connector import SlackConnector

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth.test":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "team": "Acme",
                    "team_id": "T999",
                    "user": "support-bot",
                    "user_id": "U1",
                    "bot_id": "B1",
                    "app_id": "A1",
                },
                headers={"x-oauth-scopes": "channels:history"},
            )
        if request.url.path == "/api/conversations.list":
            return httpx.Response(200, json={"ok": True, "channels": []})
        raise AssertionError(f"unexpected path: {request.url.path}")

    def connector_factory():
        return SlackConnector(
            "xoxb-unaffected-by-aws-endpoint",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

    monkeypatch.setattr(app_module, "SlackConnector", connector_factory)

    response = client.post("/nhi/slack/inventory/analyze")

    assert response.status_code == 200
    body = response.json()
    assert body["nhi_name"] == "support-bot"

    # Slack 호출부는 provider_detail 을 넘기지 않으므로 저장된 레코드에
    # 그 키 자체가 생기면 안 된다 (AWS 엔드포인트만 채운다).
    records = client.get("/nhi").json()["nhi"]
    slack_record = next(item for item in records if item["nhi_id"] == "slack:slack-T999-B1")
    assert "provider_detail" not in slack_record
