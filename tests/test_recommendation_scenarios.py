from agents.recommendation_agent import RecommendationAgent
from core.nhi_models import RecommendedAction, PermissionUsageScenarioMatch
from policy.decision_engine import DecisionEngine
from policy.rules import evaluate_policies
from policy.scoring import RiskScorer
from tests.test_policy_engine import build_ctx


def _recommendations():
    ctx = build_ctx()
    violations = evaluate_policies(ctx)
    risk = RiskScorer().score(ctx, violations)
    policy = DecisionEngine().decide(ctx, risk, violations)
    return ctx, risk, policy


def _scenario(scenario_id, name="Scenario evidence"):
    return PermissionUsageScenarioMatch(
        scenario_id=scenario_id,
        scenario_name=name,
        matched_reason="required event evidence is present",
    )


def test_existing_action_is_not_duplicated_and_rationale_is_merged():
    ctx, risk, policy = _recommendations()
    recommendations = RecommendationAgent().recommend(
        ctx, risk, policy, [_scenario("SCN_003", "Excessive privilege")]
    )

    matching = [r for r in recommendations if r.action is RecommendedAction.SCOPE_REDUCTION]
    assert len(matching) == 1
    assert "Excessive privilege" in matching[0].rationale
    assert "required event evidence is present" in matching[0].rationale


def test_missing_existing_action_is_created_from_scenario():
    ctx, risk, policy = _recommendations()
    recommendations = RecommendationAgent().recommend(
        ctx, risk, policy, [_scenario("SCN_004", "Unauthorized mutation")]
    )

    revocations = [r for r in recommendations if r.action is RecommendedAction.TOKEN_REVOCATION]
    assert len(revocations) == 1
    assert revocations[0].priority == 1


def test_none_preserves_existing_recommendation_behavior():
    ctx, risk, policy = _recommendations()
    agent = RecommendationAgent()

    without = agent.recommend(ctx, risk, policy)
    explicitly_none = agent.recommend(ctx, risk, policy, scenario_matches=None)
    assert explicitly_none == without


def test_multiple_scenarios_for_same_action_remain_one_recommendation():
    ctx, risk, policy = _recommendations()
    recommendations = RecommendationAgent().recommend(
        ctx,
        risk,
        policy,
        [_scenario("SCN_003", "Scenario one"), _scenario("SCN_003", "Scenario two")],
    )

    matching = [r for r in recommendations if r.action is RecommendedAction.SCOPE_REDUCTION]
    assert len(matching) == 1
    assert "Scenario one" in matching[0].rationale
    assert "Scenario two" in matching[0].rationale
