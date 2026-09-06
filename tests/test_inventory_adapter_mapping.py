from agents.inventory_adapter import build_profile, build_signals
from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
from core.nhi_models import AnalysisSignals, Environment


def _input() -> GitHubNHIInput:
    return GitHubNHIInput(
        nhi_id="token-1",
        nhi_name="deployment-token",
        nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
        owner="platform-team",
        environment=Environment.PRODUCTION,
        repositories=[
            RepositoryInfo(name="octocat/private-repo", visibility="private"),
            RepositoryInfo(name="octocat/public-repo", visibility="public"),
        ],
    )


def test_github_login_is_kept_in_account_and_owner_remains_separate():
    signals = AnalysisSignals(
        owner="platform-team",
        extra={"github_user": {"login": "octocat", "id": 7}},
    )

    profile = build_profile(_input(), signals)

    assert profile.account["login"] == "octocat"
    assert profile.owner == "platform-team"
    assert profile.owner != profile.account["login"]


def test_repository_owner_and_visibility_are_kept_in_signal_extra():
    signals = build_signals(_input())

    assert signals.extra["repositories"] == [
        {
            "full_name": "octocat/private-repo",
            "name": "octocat/private-repo",
            "owner_login": "octocat",
            "visibility": "private",
            "is_sensitive": False,
        },
        {
            "full_name": "octocat/public-repo",
            "name": "octocat/public-repo",
            "owner_login": "octocat",
            "visibility": "public",
            "is_sensitive": False,
        },
    ]
