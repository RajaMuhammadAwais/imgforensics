from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class GraphNode:
    node_id: str
    kind: str
    label: str
    attributes: dict[str, Any]

@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    evidence_ids: list[str]

class EvidenceGraph:
    """Small serializable graph; relationships are hypotheses, not truth claims."""
    def __init__(self) -> None:
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []

    def add_node(self, node_id: str, kind: str, label: str, **attributes: Any) -> None:
        self.nodes.append(GraphNode(node_id, kind, label, attributes))

    def add_edge(self, source: str, target: str, relation: str, evidence_ids: list[str] | None = None) -> None:
        self.edges.append(GraphEdge(source, target, relation, evidence_ids or []))

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": [asdict(n) for n in self.nodes], "edges": [asdict(e) for e in self.edges]}
