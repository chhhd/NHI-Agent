import httpx

from agents.inventory_adapter import build_github_nhi_input
from connectors.github_connector import GitHubConnector


def test_github_connector_results_are_assembled_into_inventory_input():
    token = "ghp-assembly-secret"

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

    with GitHubConnector(token, client=httpx.Client(transport=httpx.MockTransport(handler))) as github:
        user = github.get_authenticated_user()
        repositories = github.list_accessible_repositories()
        nhi = build_github_nhi_input(user, repositories)

    assert nhi.nhi_id == "github-user-42"
    assert nhi.nhi_name == "octocat"
    assert nhi.owner is None
    assert [repo.name for repo in nhi.repositories] == [
        "octocat/private-repo",
        "octocat/public-repo",
    ]
    assert [repo.visibility for repo in nhi.repositories] == ["private", "public"]
    assert token not in repr(nhi)
