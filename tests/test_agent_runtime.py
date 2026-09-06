"""Agent 실행 계층 테스트 — 계획 / 조건부 재계획 / 실제 도구 실행.

네트워크는 쓰지 않는다. 저장소 스캔 도구는 GitHub Connector 를 인자로 받으므로
테스트에서는 대역 구현을 넣는다. 토큰이 없는 기본 상태에서는 스캔을 시도하지 않고
"실행하지 않았다" 를 명시하는지도 함께 확인한다.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from agent_runtime.models import (
    ActionOrigin,
    AgentAction,
    AgentActionType,
    AgentStatus,
    GitHubInventoryAgentRequest,
    NHIAgentRequest,
    NHIAgentState,
)
from agent_runtime.orchestrator import run_nhi_agent
from agent_runtime.replanner import replan_after_secret_scan
from agent_runtime.tools import build_tool_registry
from connectors.base_connector import AuthenticationError
from connectors.github_connector import GitHubOrganizationDiscoveryResult
from core.config import reset_settings
from core.models import ScanTarget
from core.nhi_models import RiskLevel

#: 테스트용 Slack Bot Token 형태 문자열 (실제 자격 증명이 아니다)
FAKE_SLACK_TOKEN = "xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d"


@pytest.fixture(autouse=True)
def _no_github_token(monkeypatch):
    """토큰이 없는 상태를 기본값으로 둬서 실수로 외부 호출이 나가지 않게 한다."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_INVENTORY_TOKEN", raising=False)
    reset_settings()
    yield
    reset_settings()


class _StubGitHubConnector:
    """`list_files` / `build_scan_targets` 만 흉내내는 대역 Connector."""

    def __init__(self, files: Dict[str, str]):
        self.files = files
        self.closed = False

    def __enter__(self) -> "_StubGitHubConnector":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.closed = True

    def list_files(self, full_name: str, ref=None, **kwargs) -> List[Dict[str, Any]]:
        return [{"path": path} for path in self.files]

    def build_scan_targets(self, full_name: str, paths, ref=None) -> List[ScanTarget]:
        return [ScanTarget(path=path, content=self.files[path]) for path in paths]


class _FailingGitHubConnector:
    def __enter__(self) -> "_FailingGitHubConnector":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        return None

    def list_files(self, full_name: str, ref=None, **kwargs):
        raise AuthenticationError("토큰이 유효하지 않습니다", status_code=401)

    def build_scan_targets(self, *args, **kwargs):  # pragma: no cover - 도달하지 않는다
        raise AssertionError("list_files 가 먼저 실패해야 한다")


class _StubInventoryConnector:
    """조직 App installation 수집 결과를 돌려주는 읽기 전용 대역."""

    def __init__(self, result: GitHubOrganizationDiscoveryResult):
        self.result = result
        self.calls = []

    def __enter__(self) -> "_StubInventoryConnector":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        return None

    def discover_organization_apps(self, organization: str, *, limit: int):
        self.calls.append((organization, limit))
        return self.result


def _action_types(state) -> List[AgentActionType]:
    return [action.action_type for action in state.plan]


def test_replanner_inserts_new_action_before_pending_complete(low_risk_nhi):
    state = NHIAgentState(request=NHIAgentRequest(nhi=low_risk_nhi))
    state.plan = [
        AgentAction(
            step=1,
            action_type=AgentActionType.ANALYZE_NHI,
            reason="기본 분석",
            completed=True,
        ),
        AgentAction(
            step=2,
            action_type=AgentActionType.COMPLETE,
            reason="종료 예정",
        ),
    ]

    added = state.add_action(
        AgentActionType.EVALUATE_POLICY,
        reason="후속 근거에서 정책 평가 필요",
    )

    assert added is not None
    assert _action_types(state) == [
        AgentActionType.ANALYZE_NHI,
        AgentActionType.EVALUATE_POLICY,
        AgentActionType.COMPLETE,
    ]
    assert [action.step for action in state.plan] == [1, 2, 3]


# ---------------------------------------------------------------------------
# 계획 및 조건부 재계획
# ---------------------------------------------------------------------------
def test_initial_plan_only_analyzes(high_risk_nhi):
    """처음부터 모든 도구를 계획하지 않는다."""
    state = run_nhi_agent(
        NHIAgentRequest(nhi=high_risk_nhi, allow_secret_scan=False, allow_policy_evaluation=False)
    )

    assert state.status is AgentStatus.COMPLETED
    assert state.plan[0].action_type is AgentActionType.ANALYZE_NHI
    assert state.plan[0].created_by is ActionOrigin.INITIAL_PLAN
    assert AgentActionType.SCAN_SECRETS not in _action_types(state)
    assert state.analysis is not None
    assert state.analysis.risk.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert "허용되지 않아" in state.plan[-1].reason


def test_high_risk_adds_secret_scan(high_risk_nhi):
    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi,
            goal="고위험 NHI 를 분석하고 추가 검사를 수행한다.",
            allow_secret_scan=True,
        )
    )

    assert state.status is AgentStatus.COMPLETED
    assert state.replan_count == 2
    assert AgentActionType.SCAN_SECRETS in _action_types(state)

    scan_action = next(
        a for a in state.plan if a.action_type is AgentActionType.SCAN_SECRETS
    )
    assert scan_action.created_by is ActionOrigin.REPLANNER
    assert "위험 등급" in scan_action.reason
    assert any("실행되지 않았으므로" in note for note in state.replan_notes)


def test_low_risk_does_not_add_secret_scan(low_risk_nhi):
    """허용했더라도 위험 등급이 낮으면 스캔하지 않는다 (설정 기반 실행과의 차이)."""
    state = run_nhi_agent(NHIAgentRequest(nhi=low_risk_nhi, allow_secret_scan=True))

    assert state.status is AgentStatus.COMPLETED
    assert AgentActionType.SCAN_SECRETS not in _action_types(state)
    assert state.secret_scan_result is None
    assert "임계값에 미달" in state.plan[-1].reason


def test_plan_has_no_duplicate_actions(high_risk_nhi):
    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi, allow_secret_scan=True, allow_policy_evaluation=True
        )
    )
    types = _action_types(state)

    for action_type in AgentActionType:
        assert types.count(action_type) <= 1
    assert types[-1] is AgentActionType.COMPLETE
    assert state.status is AgentStatus.COMPLETED


# ---------------------------------------------------------------------------
# 정책 평가 도구 — 실제 정책 판정 결과를 정리한다
# ---------------------------------------------------------------------------
def test_policy_evaluation_reports_real_violations(high_risk_nhi):
    state = run_nhi_agent(
        NHIAgentRequest(nhi=high_risk_nhi, allow_policy_evaluation=True)
    )
    policy = state.policy_evaluation_result

    assert policy is not None
    assert policy["policy_evaluated"] is True
    assert policy["violation_count"] >= 1
    assert "OWNER_REQUIRED" in {v["policy_id"] for v in policy["violations"]}
    # 무엇을 기준으로 판정했는지 함께 남는다.
    assert "ADMIN_SCOPE_RESTRICTED" in policy["evaluated_policies"]
    assert "OWNERLESS_SENSITIVE_DATA_ACCESS" in policy["forced_critical_rules"]
    assert policy["thresholds"]["rotation_period_days"] == 90
    assert policy["human_review_required"] is True


# ---------------------------------------------------------------------------
# 저장소 Secret 스캔 도구
# ---------------------------------------------------------------------------
def test_secret_scan_is_skipped_without_token(high_risk_nhi):
    """검사하지 않은 것을 'Secret 없음' 으로 보고하지 않는다."""
    state = run_nhi_agent(
        NHIAgentRequest(nhi=high_risk_nhi, allow_secret_scan=True, scan_repository_limit=2)
    )
    scan = state.secret_scan_result

    assert scan["scan_executed"] is False
    scan_action = next(
        a for a in state.plan if a.action_type is AgentActionType.SCAN_SECRETS
    )
    assert scan_action.result["scan_executed"] is False
    assert scan_action.result["finding_count"] is None
    assert "GITHUB_TOKEN" in scan_action.result["reason"]
    assert state.status is AgentStatus.COMPLETED
    assert state.replan_count == 2
    assert state.plan[-1].action_type is AgentActionType.COMPLETE


def test_secret_scan_finds_and_scores_credentials(monkeypatch, high_risk_nhi):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_value")
    reset_settings()

    stub = _StubGitHubConnector(
        {
            "config/prod/slack.env": f"# support bot\nSLACK_BOT_TOKEN={FAKE_SLACK_TOKEN}\n",
            "README.md": "no secrets here\n",
        }
    )
    registry = build_tool_registry(connector_factory=lambda: stub)

    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi,
            allow_secret_scan=True,
            allow_policy_evaluation=True,
            scan_repository_limit=2,
        ),
        registry=registry,
    )
    scan = state.secret_scan_result

    assert state.status is AgentStatus.COMPLETED
    assert scan["scan_executed"] is True
    # 5개 저장소 중 2개만 검사하고, 나머지는 건너뛴 사실을 남긴다.
    assert len(scan["repositories_scanned"]) == 2
    assert len(scan["repositories_skipped"]) == 3
    assert scan["scan_complete"] is False
    assert scan["repository_count_skipped"] == 3
    assert scan["finding_count"] == 2  # 저장소 2개 × Slack Token 1건
    assert scan["discovered_analysis_count"] == 2
    assert len(state.discovered_analyses) == 2
    assert state.replan_count == 2
    assert state.policy_evaluation_result["discovered_summary"]["total"] == 2
    assert state.policy_evaluation_result["aggregate_analysis_count"] == 3
    assert state.policy_evaluation_result["aggregate_max_risk_score"] >= max(
        analysis.risk.score for analysis in state.discovered_analyses
    )
    assert state.policy_evaluation_result["aggregate_human_review_required"] is True
    assert any("전체 저장소 인벤토리에 대한 결론이 아니다" in note for note in state.replan_notes)
    assert _action_types(state) == [
        AgentActionType.ANALYZE_NHI,
        AgentActionType.SCAN_SECRETS,
        AgentActionType.EVALUATE_POLICY,
        AgentActionType.COMPLETE,
    ]

    first = scan["repositories_scanned"][0]
    assert first["nhi_analysis"]["total"] == 1
    assert first["nhi_analysis"]["max_risk_score"] > 0

    # 원문은 어디에도 실리지 않는다.
    assert FAKE_SLACK_TOKEN not in str(scan)
    assert FAKE_SLACK_TOKEN not in str(state.to_dict())


def test_secret_scan_failure_does_not_fail_whole_agent(monkeypatch, high_risk_nhi):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_value")
    reset_settings()

    registry = build_tool_registry(connector_factory=_FailingGitHubConnector)
    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi, allow_secret_scan=True, scan_repository_limit=1
        ),
        registry=registry,
    )
    scan = state.secret_scan_result

    # 분석 결과는 유지되고, 스캔 실패는 실패한 저장소로 기록된다.
    assert state.status is AgentStatus.COMPLETED
    assert state.analysis is not None
    assert scan["scan_executed"] is True
    assert scan["finding_count"] == 0
    assert scan["scan_complete"] is False
    assert scan["repository_count_scanned"] == 0
    assert scan["repositories_failed"][0]["repository"] == "acme/backend"
    assert any("결과가 부분적" in note for note in state.replan_notes)
    assert any("유무를 판단할 수 없다" in note for note in state.replan_notes)


def test_secret_scan_without_repositories(monkeypatch, high_risk_nhi):
    """스캔 대상이 없으면 그 사실을 이유로 남긴다."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_value")
    reset_settings()
    high_risk_nhi.repositories = []

    registry = build_tool_registry()
    state = run_nhi_agent(
        NHIAgentRequest(nhi=high_risk_nhi, allow_secret_scan=True), registry=registry
    )
    result = state.secret_scan_result

    assert result["scan_executed"] is False
    assert result["finding_count"] is None
    assert "저장소" in result["reason"]
    assert state.replan_count == 2
    assert state.plan[-1].action_type is AgentActionType.COMPLETE


def test_successful_zero_finding_scan_is_not_reported_as_unknown(
    monkeypatch, high_risk_nhi
):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_value")
    reset_settings()
    stub = _StubGitHubConnector({"README.md": "ordinary documentation\n"})
    registry = build_tool_registry(connector_factory=lambda: stub)

    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi,
            allow_secret_scan=True,
            scan_repository_limit=5,
        ),
        registry=registry,
    )

    assert state.secret_scan_result["scan_executed"] is True
    assert state.secret_scan_result["scan_complete"] is True
    assert state.secret_scan_result["finding_count"] == 0
    assert any("발견하지 못했다" in note for note in state.replan_notes)
    assert not any("유무를 판단할 수 없다" in note for note in state.replan_notes)


def test_secret_scan_replanner_is_idempotent(high_risk_nhi):
    state = run_nhi_agent(
        NHIAgentRequest(nhi=high_risk_nhi, allow_secret_scan=True)
    )
    before = (state.replan_count, len(state.replan_notes), len(state.plan))

    replan_after_secret_scan(state)

    assert (state.replan_count, len(state.replan_notes), len(state.plan)) == before


# ---------------------------------------------------------------------------
# GitHub 조직 App installation 수집
# ---------------------------------------------------------------------------
def test_github_collection_uses_separate_factory_and_analyzes_every_item(
    high_risk_nhi, low_risk_nhi
):
    high = high_risk_nhi.model_copy(
        deep=True, update={"nhi_id": "github-app-installation:101"}
    )
    low = low_risk_nhi.model_copy(
        deep=True, update={"nhi_id": "github-app-installation:102"}
    )
    collection = _StubInventoryConnector(
        GitHubOrganizationDiscoveryResult(
            organization="acme",
            items=[low, high],
            total_count=2,
            pages_fetched=1,
            inventory_complete=True,
        )
    )

    def forbidden_scan_factory():  # pragma: no cover - 호출되면 즉시 실패
        raise AssertionError("수집 전용 실행에서 scan connector를 만들면 안 됩니다.")

    registry = build_tool_registry(
        collection_connector_factory=lambda: collection,
        connector_factory=forbidden_scan_factory,
    )
    state = run_nhi_agent(
        GitHubInventoryAgentRequest(
            organization="acme",
            inventory_limit=25,
            analyze=True,
            allow_secret_scan=False,
            allow_policy_evaluation=True,
        ),
        registry=registry,
    )

    assert state.status is AgentStatus.COMPLETED
    assert collection.calls == [("acme", 25)]
    assert len(state.collected_inventory) == 2
    assert len(state.inventory_analyses) == 2
    assert state.analysis is not None
    assert state.analysis.profile.nhi_id == "github:github-app-installation:101"
    assert state.replan_count == 2
    assert _action_types(state) == [
        AgentActionType.COLLECT_GITHUB_DATA,
        AgentActionType.ANALYZE_NHI,
        AgentActionType.EVALUATE_POLICY,
        AgentActionType.COMPLETE,
    ]
    serialized = state.to_dict()
    collect_step = next(
        step for step in serialized["plan"]
        if step["action_type"] == AgentActionType.COLLECT_GITHUB_DATA.value
    )
    analyze_step = next(
        step for step in serialized["plan"]
        if step["action_type"] == AgentActionType.ANALYZE_NHI.value
    )
    assert "inventory" not in collect_step["result"]
    assert "analyses" not in analyze_step["result"]
    assert len(serialized["github_collection"]["inventory"]) == 2
    assert len(serialized["inventory_analyses"]) == 2


def test_github_collection_preserves_complete_empty_result():
    collection = _StubInventoryConnector(
        GitHubOrganizationDiscoveryResult(
            organization="acme",
            items=[],
            total_count=0,
            pages_fetched=1,
            inventory_complete=True,
        )
    )
    registry = build_tool_registry(
        collection_connector_factory=lambda: collection,
    )

    state = run_nhi_agent(
        GitHubInventoryAgentRequest(
            organization="acme",
            analyze=False,
        ),
        registry=registry,
    )

    assert state.status is AgentStatus.COMPLETED
    assert state.github_collection_result["count"] == 0
    assert state.github_collection_result["inventory_complete"] is True
    assert state.inventory_analyses == []
    assert state.replan_count == 1
    assert _action_types(state) == [
        AgentActionType.COLLECT_GITHUB_DATA,
        AgentActionType.COMPLETE,
    ]
    assert "일치하는 installation이 없다" in state.plan[-1].reason


# ---------------------------------------------------------------------------
# 상태 직렬화 (API 응답 형태)
# ---------------------------------------------------------------------------
def test_state_to_dict_contains_plan_and_results(high_risk_nhi):
    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi, allow_secret_scan=True, allow_policy_evaluation=True
        )
    )
    data = state.to_dict()

    assert data["status"] == AgentStatus.COMPLETED.value
    assert data["nhi_analysis"]["risk_level"] == RiskLevel.CRITICAL.value
    assert data["policy_evaluation"]["policy_evaluated"] is True
    assert [step["step"] for step in data["plan"]] == list(
        range(1, len(data["plan"]) + 1)
    )
    assert data["request"]["nhi"]["nhi_id"] == high_risk_nhi.nhi_id


def test_state_to_dict_redacts_untrusted_signal_values(high_risk_nhi):
    raw_token = "ghp_testSignalToken1234567890ABCDEFGHIJ"
    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=high_risk_nhi,
            signals={"extra": {"audit_line": f"Authorization: Bearer {raw_token}"}},
        )
    )

    serialized = str(state.to_dict())
    assert raw_token not in serialized
    assert "<redacted>" in serialized


def test_github_collection_request_rejects_unbounded_or_extra_input():
    with pytest.raises(ValueError):
        GitHubInventoryAgentRequest(organization="acme", inventory_limit=501)
    with pytest.raises(ValueError):
        GitHubInventoryAgentRequest(organization="acme", access_token="must-not-be-body")
