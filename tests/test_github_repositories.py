import httpx
import pytest

from connectors.base_connector import AuthenticationError, ConnectorError, RateLimitError
from connectors.github_connector import GitHubConnector


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_lists_minimal_repository_fields_from_first_page():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/user/repos"
        assert request.url.params["page"] == "1"
        return httpx.Response(
            200,
            json=[
                {
                    "name": "demo",
                    "full_name": "octocat/demo",
                    "private": True,
                    "owner": {"login": "octocat", "id": 1},
                    "permissions": {"admin": True},
                }
            ],
        )

    with GitHubConnector("ghp-test", client=_client(handler)) as github:
        repositories = github.list_accessible_repositories()

    assert repositories == [
        {
            "name": "demo",
            "full_name": "octocat/demo",
            "private": True,
            "owner_login": "octocat",
        }
    ]


def test_lists_multiple_repository_pages():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.params.get("page") == "1":
            return httpx.Response(
                200,
                json=[{"name": "one", "full_name": "o/one", "private": False, "owner": {"login": "o"}}],
                headers={"Link": '<https://api.github.test/user/repos?page=2>; rel="next"'},
            )
        return httpx.Response(
            200,
            json=[{"name": "two", "full_name": "o/two", "private": True, "owner": {"login": "o"}}],
        )

    with GitHubConnector("ghp-test", api_base="https://api.github.test", client=_client(handler)) as github:
        repositories = github.list_accessible_repositories()

    assert [repo["name"] for repo in repositories] == ["one", "two"]
    assert len(requests) == 2


def test_empty_repository_list_is_returned_as_empty():
    with GitHubConnector("ghp-test", client=_client(lambda request: httpx.Response(200, json=[]))) as github:
        assert github.list_accessible_repositories() == []


def test_repository_list_401_does_not_expose_token():
    token = "ghp-invalid"
    with GitHubConnector(token, client=_client(lambda request: httpx.Response(401, json={}))) as github:
        with pytest.raises(AuthenticationError) as error:
            github.list_accessible_repositories()

    assert error.value.status_code == 401
    assert token not in str(error.value)


def test_repository_list_rate_limit_error_is_safe():
    token = "ghp-rate-limit"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "rate limited"}, headers={"Retry-After": "1"})

    with GitHubConnector(token, client=_client(handler)) as github:
        github.max_wait_seconds = 0
        with pytest.raises(RateLimitError) as error:
            github.list_accessible_repositories()

    assert error.value.status_code == 429
    assert token not in str(error.value)


def test_repository_list_api_error_does_not_return_provider_payload():
    with GitHubConnector("ghp-test", client=_client(lambda request: httpx.Response(500, json={"secret": "hidden"})), max_retries=0) as github:
        with pytest.raises(ConnectorError) as error:
            github.list_accessible_repositories()

    assert error.value.status_code == 500
    assert "secret" not in str(error.value)
