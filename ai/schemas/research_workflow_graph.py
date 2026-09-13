"""Research workflow graph schema (Stage R35.2).

A :class:`ResearchWorkflowGraphPlan` is a deterministic, acyclic, ordered
planning graph derived from a research strategy. It answers the owner's
personal-research question:

    "In what dependency order should the conceptual research nodes run?"

Hard boundaries encoded here:

- Planning graph only: nodes are conceptual analysis/planning labels. No
  agent runtime, worker queue, scheduler, dispatch or execution graph is
  represented.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: node codes and edge keys are closed sets; the schema
  rejects self-loops and cycles.
- Bounded, privacy-safe: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

RESEARCH_WORKFLOW_GRAPH_RULE_VERSION = "r35-2"
RULE_VERSION = RESEARCH_WORKFLOW_GRAPH_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

NODE_ANALYZE_ASSET = "ANALYZE_ASSET"
NODE_ANALYZE_IDENTITY = "ANALYZE_IDENTITY"
NODE_ANALYZE_TECHNOLOGY = "ANALYZE_TECHNOLOGY"
NODE_ANALYZE_VERSION = "ANALYZE_VERSION"
NODE_COLLECT_EVIDENCE_PLAN = "COLLECT_EVIDENCE_PLAN"
NODE_REVIEW_HISTORY = "REVIEW_HISTORY"
NODE_HUMAN_REVIEW = "HUMAN_REVIEW"
NODE_STOP = "STOP"

WORKFLOW_NODES: tuple[str, ...] = (
    NODE_ANALYZE_ASSET,
    NODE_ANALYZE_IDENTITY,
    NODE_ANALYZE_TECHNOLOGY,
    NODE_ANALYZE_VERSION,
    NODE_COLLECT_EVIDENCE_PLAN,
    NODE_REVIEW_HISTORY,
    NODE_HUMAN_REVIEW,
    NODE_STOP,
)

EDGE_KEYS: tuple[str, ...] = ("from", "to")

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_NODES = 5
MAX_EDGES = 6
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_nodes(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in WORKFLOW_NODES and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _nodes_acyclic(nodes: list[str], edges: list[dict]) -> bool:
    """Deterministic Kahn-style acyclicity check over bounded edges."""

    incoming = {node: set() for node in nodes}
    outgoing = {node: set() for node in nodes}
    for edge in edges:
        source = edge["from"]
        target = edge["to"]
        if source not in incoming or target not in incoming:
            continue
        if source == target:
            return False
        incoming[target].add(source)
        outgoing[source].add(target)
    ready = sorted(node for node, parents in incoming.items() if not parents)
    seen = 0
    while ready:
        node = ready.pop(0)
        seen += 1
        for child in sorted(outgoing[node]):
            incoming[child].discard(node)
            if not incoming[child]:
                ready.append(child)
        ready.sort()
    return seen == len(incoming)


def _require_edges(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            raise ValueError(f"malformed edge: {item!r}")
        source = _safe_text(item.get("from"))
        target = _safe_text(item.get("to"))
        if source not in WORKFLOW_NODES or target not in WORKFLOW_NODES:
            raise ValueError(f"invalid edge nodes: {item!r}")
        if source == target:
            raise ValueError(f"self-loop edge: {item!r}")
        entry = {"from": source, "to": target}
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    referenced = sorted(
        {edge["from"] for edge in out} | {edge["to"] for edge in out}
    )
    if not _nodes_acyclic(referenced, out):
        raise ValueError("workflow edges must be acyclic")
    return out


def _bounded_edges(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        source = _safe_text(item.get("from"))
        target = _safe_text(item.get("to"))
        if (
            source not in WORKFLOW_NODES
            or target not in WORKFLOW_NODES
            or source == target
        ):
            continue
        entry = {"from": source, "to": target}
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    referenced = sorted(
        {edge["from"] for edge in out} | {edge["to"] for edge in out}
    )
    if not _nodes_acyclic(referenced, out):
        return []
    return out


def sanitize_research_workflow_graph_plan(value: object) -> dict:
    """Project an R35.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "nodes": [],
            "edges": [],
            "entry_nodes": [],
            "terminal_nodes": [],
            "research_only": True,
        }
    nodes = _bounded_nodes(value.get("nodes"), MAX_NODES)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "nodes": nodes,
        "edges": _bounded_edges(value.get("edges"), MAX_EDGES),
        "entry_nodes": _bounded_nodes(
            value.get("entry_nodes"), MAX_NODES
        ),
        "terminal_nodes": _bounded_nodes(
            value.get("terminal_nodes"), MAX_NODES
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchWorkflowGraphPlan(BaseModel):
    """Deterministic ordered research workflow graph (R35.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_WORKFLOW_GRAPH_RULE_VERSION
    nodes: list[str] = Field(default_factory=list)
    edges: list[dict] = Field(default_factory=list)
    entry_nodes: list[str] = Field(default_factory=list)
    terminal_nodes: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_WORKFLOW_GRAPH_RULE_VERSION

    @field_validator("nodes")
    @classmethod
    def _valid_nodes(cls, value: list) -> list[str]:
        nodes = _bounded_nodes(value, MAX_NODES)
        if len(nodes) != len(list(value or ())):
            raise ValueError(f"invalid node code: {value!r}")
        return nodes

    @field_validator("edges")
    @classmethod
    def _valid_edges(cls, value: list) -> list[dict]:
        return _require_edges(value, MAX_EDGES)

    @field_validator("entry_nodes", "terminal_nodes")
    @classmethod
    def _valid_endpoints(cls, value: list) -> list[str]:
        nodes = _bounded_nodes(value, MAX_NODES)
        if len(nodes) != len(list(value or ())):
            raise ValueError(f"invalid endpoint code: {value!r}")
        return nodes

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research workflow graphs are research-only")
        return True


def research_workflow_graph_plan_projection(
    value: ResearchWorkflowGraphPlan,
) -> dict:
    """Serialize a workflow graph plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_WORKFLOW_GRAPH_RULE_VERSION",
    "RULE_VERSION",
    "WORKFLOW_NODES",
    "EDGE_KEYS",
    "NODE_ANALYZE_ASSET",
    "NODE_ANALYZE_IDENTITY",
    "NODE_ANALYZE_TECHNOLOGY",
    "NODE_ANALYZE_VERSION",
    "NODE_COLLECT_EVIDENCE_PLAN",
    "NODE_REVIEW_HISTORY",
    "NODE_HUMAN_REVIEW",
    "NODE_STOP",
    "MAX_NODES",
    "MAX_EDGES",
    "MAX_VALUE_LEN",
    "ResearchWorkflowGraphPlan",
    "sanitize_research_workflow_graph_plan",
    "research_workflow_graph_plan_projection",
]
