import httpx

from agents.github_inventory_service import analyze_github_nhi_from_connector
from connectors.github_connector import GitHubConnector


def test_connector_inventory_is_analyzed_without_storing_token():
    token = "ghp-service-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "octocat", "id": 42})
        if request.url.path == "/user/repos":
            return httpx.Response(
                200,
                json=[
                    {
                        "name": "private-repo",
                        "full_name": "octocat/private-repo",
                        "private": True,
                        "owner": {"login": "octocat"},
                    },
                    {
                        "name": "public-repo",
                        "full_name": "octocat/public-repo",
                        "private": False,
                        "owner": {"login": "octocat"},
                    },
                ],
            )
        raise AssertionError(f"unexpected path: {request.url.path}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with GitHubConnector(token, client=client) as connector:
        analysis = analyze_github_nhi_from_connector(connector)

    assert analysis.profile.account["login"] == "octocat"
    assert analysis.profile.owner is None
    assert analysis.context.data_sensitivity.value == "internal"
    assert analysis.context.path_signals == ["접근 저장소 2개"]
    assert token not in repr(analysis)
