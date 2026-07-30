"""관계 그래프.

    AI Agent → NHI → Credential → Permission → Service → Resource

각 계층을 노드로, 연결을 엣지로 표현한다. 그래프는 두 곳에 쓰인다.
  1. 대시보드 시각화 (`to_dict()` 를 그대로 렌더링할 수 있다)
  2. Blast Radius 계산 — 특정 노드에서 도달 가능한 서비스·자원 수집
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set

from core.nhi_models import BlastRadiusReport, NHIProfile, PermissionProfile
from graph.blast_radius import service_label


class NodeType(str, Enum):
    AI_AGENT = "AI_AGENT"
    NHI = "NHI"
    CREDENTIAL = "CREDENTIAL"
    PERMISSION = "PERMISSION"
    SERVICE = "SERVICE"
    RESOURCE = "RESOURCE"


class EdgeType(str, Enum):
    USES = "USES"              # AI Agent → NHI
    AUTHENTICATES_WITH = "AUTHENTICATES_WITH"  # NHI → Credential
    GRANTS = "GRANTS"          # Credential → Permission
    APPLIES_TO = "APPLIES_TO"  # Permission → Service
    EXPOSES = "EXPOSES"        # Service → Resource


@dataclass(frozen=True)
class Node:
    id: str
    type: NodeType
    label: str
    attributes: tuple = ()   # (key, value) 쌍 — 해시 가능해야 하므로 tuple

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    type: EdgeType

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "target": self.target, "type": self.type.value}


@dataclass
class RelationshipGraph:
    """AI Agent ~ Resource 까지의 관계를 담는 유향 그래프."""

    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    _edge_keys: Set[tuple] = field(default_factory=set, repr=False)

    # ------------------------------------------------------------------
    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(
                id=node_id,
                type=node_type,
                label=label,
                attributes=tuple(sorted((attributes or {}).items())),
            )
        return node_id

    def add_edge(self, source: str, target: str, edge_type: EdgeType) -> None:
        key = (source, target, edge_type)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(Edge(source=source, target=target, type=edge_type))

    # ------------------------------------------------------------------
    def add_chain(
        self,
        profile: NHIProfile,
        permissions: PermissionProfile,
        blast_radius: Optional[BlastRadiusReport] = None,
        *,
        repository: str = "",
    ) -> str:
        """NHI 1건의 전체 관계 사슬을 그래프에 추가하고 NHI 노드 ID 를 반환한다."""
        nhi_id = self.add_node(
            f"nhi:{profile.nhi_id}",
            NodeType.NHI,
            profile.nhi_name,
            {
                "nhi_type": profile.nhi_type.value,
                "provider": profile.provider,
                "owner": profile.owner,
                "is_bot": profile.is_bot,
                "identified": profile.identified,
            },
        )

        if profile.linked_ai_agent:
            agent_id = self.add_node(
                f"agent:{profile.linked_ai_agent}",
                NodeType.AI_AGENT,
                profile.linked_ai_agent,
                {"provider": profile.provider},
            )
            self.add_edge(agent_id, nhi_id, EdgeType.USES)

        credential_id = self.add_node(
            f"credential:{profile.credential_fingerprint}",
            NodeType.CREDENTIAL,
            profile.secret_name or profile.secret_type,
            {
                "secret_type": profile.secret_type,
                "fingerprint": profile.credential_fingerprint,
                "repository": repository,
            },
        )
        self.add_edge(nhi_id, credential_id, EdgeType.AUTHENTICATES_WITH)

        services = (blast_radius.connected_services if blast_radius else None) or [
            service_label(profile.provider)
        ]
        service_ids = [
            self.add_node(f"service:{name}", NodeType.SERVICE, name, {"provider": profile.provider})
            for name in services
        ]

        for permission in permissions.permissions:
            permission_id = self.add_node(
                f"permission:{profile.credential_fingerprint}:{permission.value}",
                NodeType.PERMISSION,
                permission.value,
                {"assumed": permissions.assumed},
            )
            self.add_edge(credential_id, permission_id, EdgeType.GRANTS)
            for service_id in service_ids:
                self.add_edge(permission_id, service_id, EdgeType.APPLIES_TO)

        if blast_radius:
            for sample in blast_radius.resource_samples:
                resource_id = self.add_node(
                    f"resource:{profile.provider}:{sample}",
                    NodeType.RESOURCE,
                    sample,
                    {"provider": profile.provider},
                )
                for service_id in service_ids:
                    self.add_edge(service_id, resource_id, EdgeType.EXPOSES)

        return nhi_id

    # ------------------------------------------------------------------
    def neighbors(self, node_id: str, *, edge_type: Optional[EdgeType] = None) -> List[str]:
        return [
            e.target
            for e in self.edges
            if e.source == node_id and (edge_type is None or e.type is edge_type)
        ]

    def reachable(self, node_id: str) -> Set[str]:
        """해당 노드에서 도달 가능한 전체 노드 (자기 자신 제외)."""
        seen: Set[str] = set()
        queue = deque(self.neighbors(node_id))
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(self.neighbors(current))
        return seen

    def nodes_of_type(self, node_type: NodeType, *, within: Optional[Iterable[str]] = None) -> List[Node]:
        pool = self.nodes.values() if within is None else [
            self.nodes[n] for n in within if n in self.nodes
        ]
        return [n for n in pool if n.type is node_type]

    def path_from(self, node_id: str) -> List[Dict[str, Any]]:
        """노드에서 시작하는 계층 경로를 계층별로 묶어 반환한다."""
        reachable = self.reachable(node_id)
        layers: Dict[str, List[str]] = {}
        for nid in reachable:
            node = self.nodes.get(nid)
            if node is None:
                continue
            layers.setdefault(node.type.value, []).append(node.label)
        return [{"layer": layer, "nodes": sorted(labels)} for layer, labels in layers.items()]

    def stats(self) -> Dict[str, int]:
        counts = {node_type.value: 0 for node_type in NodeType}
        for node in self.nodes.values():
            counts[node.type.value] += 1
        counts["edges"] = len(self.edges)
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats(),
        }
