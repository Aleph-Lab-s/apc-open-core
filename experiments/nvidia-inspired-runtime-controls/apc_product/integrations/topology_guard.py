from __future__ import annotations

"""Deployment topology validator for agent/tool/provider bypass paths."""

from dataclasses import dataclass
from collections import deque
from typing import Iterable


@dataclass(frozen=True)
class Node:
    node_id: str
    kind: str


@dataclass(frozen=True)
class Edge:
    source: str
    destination: str
    governed: bool
    security_contract: str | None = None


@dataclass(frozen=True)
class BypassFinding:
    path: tuple[str, ...]
    reason: str


class TopologyGuard:
    def __init__(self, nodes: Iterable[Node], edges: Iterable[Edge], *, finality_kinds: tuple[str, ...] = ("finality",)):
        self.nodes = {n.node_id: n for n in nodes}
        self.edges = tuple(edges)
        self.adj: dict[str, list[Edge]] = {}
        for e in self.edges:
            if e.source not in self.nodes or e.destination not in self.nodes:
                raise ValueError("topology references unknown node")
            self.adj.setdefault(e.source, []).append(e)
        self.finality_kinds = frozenset(finality_kinds)

    def ungoverned_paths(self, source: str, sink: str, *, max_paths: int = 100) -> tuple[BypassFinding, ...]:
        if source not in self.nodes or sink not in self.nodes:
            raise ValueError("source or sink is unknown")
        findings: list[BypassFinding] = []
        q = deque([(source, (source,), False)])
        seen = set()
        while q and len(findings) < max_paths:
            node, path, saw_finality = q.popleft()
            if len(path) > len(self.nodes) + 1:
                continue
            finality_seen = saw_finality or self.nodes[node].kind in self.finality_kinds
            if node == sink:
                if not finality_seen:
                    findings.append(BypassFinding(path, "sink reachable without finality enforcement"))
                elif any(not e.governed for e in self._path_edges(path)):
                    findings.append(BypassFinding(path, "path contains an ungoverned edge"))
                continue
            for e in self.adj.get(node, ()):  
                if e.destination in path:
                    continue
                state = (e.destination, path + (e.destination,), finality_seen)
                key = (e.destination, finality_seen, len(path))
                if key not in seen:
                    seen.add(key)
                    q.append(state)
        return tuple(findings)

    def _path_edges(self, path: tuple[str, ...]) -> tuple[Edge, ...]:
        out = []
        for a, b in zip(path, path[1:]):
            match = next((e for e in self.adj.get(a, ()) if e.destination == b), None)
            if match is not None:
                out.append(match)
        return tuple(out)
