from agents.pipeline import NHIAnalysisPipeline
from agents.scope_translation_agent import ScopeTranslationAgent
from core.inventory_models import GitHubNHIInput, GitHubNHIType
from core.nhi_models import PermissionLevel
from tests.test_nhi_agents import make_finding


def test_secret_finding_without_scopes_keeps_existing_assumption():
    profile = ScopeTranslationAgent().translate_finding(
        make_finding(raw_scopes=[], secret_type="GITHUB_PAT")
    )

    assert profile.assumed is True
    assert profile.permissions == [
        PermissionLevel.READ,
        PermissionLevel.WRITE,
        PermissionLevel.DELETE,
        PermissionLevel.ADMIN,
    ]


def test_github_inventory_without_permission_data_stays_unknown():
    analysis = NHIAnalysisPipeline().analyze_github_nhi(
        GitHubNHIInput(
            nhi_id="github-user-1",
            nhi_name="octocat",
            nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
        )
    )

    assert analysis.permissions.permissions == []
    assert analysis.permissions.highest is None
    assert analysis.permissions.assumed is False
    assert analysis.permissions.mappings == []


def test_github_inventory_with_real_permission_data_still_translates():
    analysis = NHIAnalysisPipeline().analyze_github_nhi(
        GitHubNHIInput(
            nhi_id="github-user-1",
            nhi_name="octocat",
            nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
            raw_permissions={"metadata": "read"},
        )
    )

    assert analysis.permissions.permissions == [PermissionLevel.READ]
    assert analysis.permissions.assumed is False
    assert analysis.permissions.highest is PermissionLevel.READ
