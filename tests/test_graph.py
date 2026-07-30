"""관계 그래프 / Blast Radius 테스트."""

from __future__ import annotations

from agents.context_analysis_agent import ContextAnalysisAgent
from agents.discovery_agent import DiscoveryAgent
from agents.scope_translation_agent import ScopeTranslationAgent
from core.nhi_models import AnalysisSignals
from graph.blast_radius import BlastRadiusCalculator, summarize_blast_radius
from graph.relationship_graph import EdgeType, NodeType, RelationshipGraph
from tests.test_nhi_agents import make_finding


def _parts(finding, signals=None):
    signals = signals or AnalysisSignals()
    profile = DiscoveryAgent().analyze(finding, signals)
    context = ContextAnalysisAgent().analyze(finding, signals)
    permissions = ScopeTranslationAgent().translate_finding(finding)
    blast = BlastRadiusCalculator().compute(finding, profile, permissions, context, signals)
    return profile, permissions, blast


# ---------------------------------------------------------------------------
# Blast Radius
# ---------------------------------------------------------------------------
def test_blast_radius_counts_services_and_resources():
    finding = make_finding(
        raw_scopes=["channels:history", "chat:write"],
        credential_active=True,
        account={"team": "Support", "user": "support-bot"},
        resources=[{"name": "general"}, {"name": "incidents"}, {"name": "support"}],
    )
    _, _, blast = _parts(finding)

    assert blast.connected_services == ["Slack"]
    assert blast.accessible_resources == 3
    assert blast.resource_samples[:2] == ["general", "incidents"]
    assert blast.can_read and blast.can_write
    assert blast.can_delete is False
    assert blast.external_transfer_possible is True


def test_blast_radius_admin_scope_implies_delete():
    finding = make_finding(secret_type="GITHUB_PAT", provider="github", raw_scopes=["repo"])
    _, _, blast = _parts(finding)

    assert blast.can_delete is True
    assert blast.impact_score >= 40


def test_blast_radius_cross_project_flag():
    finding = make_finding(credential_active=True)
    _, _, blast = _parts(
        finding, AnalysisSignals(shared_projects=["acme/payments", "acme/support"])
    )

    assert blast.cross_project_impact is True
    assert blast.affected_projects == ["acme/payments", "acme/support"]


def test_blast_radius_notes_missing_scope_information():
    finding = make_finding(raw_scopes=[])
    _, _, blast = _parts(finding)

    assert any("Scope 미확인" in note for note in blast.notes)


def test_summarize_blast_radius_merges_reports():
    slack = make_finding(
        raw_scopes=["chat:write"], resources=[{"name": "general"}], credential_active=True
    )
    github = make_finding(
        secret_type="GITHUB_PAT", provider="github", raw_scopes=["repo"],
        resources=[{"full_name": "acme/api"}],
    )
    reports = [_parts(slack)[2], _parts(github)[2]]
    summary = summarize_blast_radius(reports)

    assert summary["connected_service_count"] == 2
    assert set(summary["connected_services"]) == {"Slack", "GitHub"}
    assert summary["accessible_resources"] == 2
    assert summary["delete_capable_credentials"] == 1


# ---------------------------------------------------------------------------
# 관계 그래프
# ---------------------------------------------------------------------------
def test_graph_builds_full_chain():
    """AI Agent → NHI → Credential → Permission → Service → Resource."""
    finding = make_finding(
        secret_type="ANTHROPIC_API_KEY",
        provider="anthropic",
        file_path="services/support_agent/config.py",
        line="ANTHROPIC_API_KEY = 'sk-ant-****'",
        raw_scopes=["read", "write"],
        resources=[{"name": "claude-sonnet"}],
    )
    profile, permissions, blast = _parts(finding)
    graph = RelationshipGraph()
    nhi_node = graph.add_chain(profile, permissions, blast, repository="acme/support")

    assert profile.linked_ai_agent == "support-agent"
    stats = graph.stats()
    for node_type in (
        NodeType.AI_AGENT, NodeType.NHI, NodeType.CREDENTIAL,
        NodeType.PERMISSION, NodeType.SERVICE, NodeType.RESOURCE,
    ):
        assert stats[node_type.value] >= 1, node_type

    edge_types = {e.type for e in graph.edges}
    assert EdgeType.USES in edge_types
    assert EdgeType.AUTHENTICATES_WITH in edge_types
    assert EdgeType.GRANTS in edge_types
    assert EdgeType.APPLIES_TO in edge_types
    assert EdgeType.EXPOSES in edge_types

    reachable = graph.reachable(nhi_node)
    assert any(n.startswith("resource:") for n in reachable)
    assert graph.nodes_of_type(NodeType.SERVICE, within=reachable)


def test_graph_is_idempotent_for_repeated_chain():
    finding = make_finding(raw_scopes=["chat:write"], resources=[{"name": "general"}])
    profile, permissions, blast = _parts(finding)

    graph = RelationshipGraph()
    graph.add_chain(profile, permissions, blast)
    node_count, edge_count = len(graph.nodes), len(graph.edges)
    graph.add_chain(profile, permissions, blast)

    assert len(graph.nodes) == node_count
    assert len(graph.edges) == edge_count


def test_graph_serialization_shape():
    finding = make_finding(raw_scopes=["chat:write"])
    profile, permissions, blast = _parts(finding)
    graph = RelationshipGraph()
    graph.add_chain(profile, permissions, blast)

    data = graph.to_dict()
    assert {"nodes", "edges", "stats"} <= data.keys()
    assert all({"id", "type", "label", "attributes"} <= n.keys() for n in data["nodes"])
    assert all({"source", "target", "type"} <= e.keys() for e in data["edges"])


def test_graph_shares_service_node_between_nhis():
    """같은 서비스를 쓰는 NHI 들은 하나의 Service 노드를 공유한다."""
    a = make_finding(raw_scopes=["chat:write"], account={"user": "bot-a"})
    b = make_finding(raw_scopes=["channels:history"], account={"user": "bot-b"})
    b.fingerprint = "sha256:another0011"

    graph = RelationshipGraph()
    for finding in (a, b):
        profile, permissions, blast = _parts(finding)
        graph.add_chain(profile, permissions, blast)

    assert len(graph.nodes_of_type(NodeType.SERVICE)) == 1
    assert len(graph.nodes_of_type(NodeType.NHI)) == 2
