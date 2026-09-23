"""Phase 3: bounded objective dependency graph with cycle rejection.

Deterministic: resolve order, cycle detection (A -> B -> A refused BEFORE
execution), and per-dependency state rules.  A REQUIRED dependency that is
not in an acceptable state prevents execution (fail closed); OPTIONAL and
INFORMATIONAL dependencies inform ordering but never authorize or block on
their own.
"""
from __future__ import annotations

from typing import Any, Iterable

from backend.research_agents.campaign.models import (
    CampaignObjective, Dependency, REQUIRED_DEP_ACCEPTABLE,
    REQUIRED_DEP_PERMANENT_FAIL, OBJECTIVE_TERMINAL,
)

# How a dependency affects the dependent objective:
#   satisfied   -> dependent may run (REQUIRED) / is informed (others)
#   waiting     -> dependent must WAIT (prereq not terminal yet)
#   permanently_blocked -> dependent is BLOCKED (prereq terminal-failed)
DEP_EFFECTS: tuple[str, ...] = ("satisfied", "waiting",
                                "permanently_blocked", "informed")


class DependencyCycleError(ValueError):
    """A -> B -> A (or longer) detected before execution."""


def build_graph(objectives: Iterable[CampaignObjective],
                extra: Iterable[Dependency] = ()) -> dict[str, list[Dependency]]:
    """objective_id -> list of dependencies declared on it."""

    graph: dict[str, list[Dependency]] = {}
    for obj in objectives:
        graph.setdefault(obj.objective_id, [])
        for dep in obj.dependencies:
            graph[obj.objective_id].append(dep)
    for dep in extra:
        graph.setdefault(dep.objective_id, []).append(dep)
    return graph


def detect_cycles(graph: dict[str, list[Dependency]]) -> list[str]:
    """Return the first dependency cycle found (empty list = acyclic).

    Iterative DFS with WHITE/GRAY/GRAY-path reporting so A->B->A and
    longer loops are both rejected before any execution.
    """

    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {n: WHITE for n in graph}
    # ensure nodes referenced only as depends_on exist as vertices
    for deps in graph.values():
        for dep in deps:
            color.setdefault(dep.depends_on, WHITE)
            color.setdefault(dep.objective_id, WHITE)

    for start in sorted(color):
        if color[start] != WHITE:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        path: list[str] = []
        while stack:
            node, idx = stack[-1]
            if idx == 0:
                color[node] = GRAY
                path.append(node)
            deps = graph.get(node, [])
            if idx >= len(deps):
                color[node] = BLACK
                path.pop()
                stack.pop()
                continue
            stack[-1] = (node, idx + 1)
            nxt = deps[idx].depends_on
            if nxt == node or color.get(nxt) == GRAY:
                # cycle: slice path from first occurrence of nxt
                try:
                    at = path.index(nxt)
                except ValueError:
                    at = 0
                return path[at:] + [nxt]
            if color.get(nxt, WHITE) == WHITE:
                stack.append((nxt, 0))
    return []


def assert_acyclic(objectives: Iterable[CampaignObjective],
                   extra: Iterable[Dependency] = ()) -> None:
    """Raise DependencyCycleError if the graph contains a cycle (Phase 3)."""

    graph = build_graph(objectives, extra)
    cycle = detect_cycles(graph)
    if cycle:
        raise DependencyCycleError(
            "dependency cycle detected: " + " -> ".join(cycle[:8]))


def resolve_dependencies(
    objective: CampaignObjective,
    by_id: dict[str, CampaignObjective],
) -> dict[str, Any]:
    """Resolve one objective's dependencies against current states.

    Returns:
      {"effect": satisfied|waiting|permanently_blocked|informed,
       "ready": bool, "reasons": [str, ...]}

    Rules (REQUIRED only can block):
      * prereq missing            -> permanently_blocked (fail closed)
      * prereq state in ACCEPTABLE -> satisfied
      * prereq state in PERMANENT_FAIL -> permanently_blocked
      * prereq non-terminal other -> waiting
      * prereq terminal other (e.g. REJECTED) -> permanently_blocked only
        if REQUIRED and not acceptable; REJECTED prereq blocks REQUIRED
        dependents (an acceptable state is REQUIRED_DEP_ACCEPTABLE only).
      * OPTIONAL / INFORMATIONAL -> never block; effect "informed".
    """

    reasons: list[str] = []
    blocking = False
    waiting = False
    for dep in objective.dependencies:
        prereq = by_id.get(dep.depends_on)
        if prereq is None:
            if dep.kind == "REQUIRED":
                blocking = True
                reasons.append(
                    f"required dependency missing: {dep.depends_on}")
            else:
                reasons.append(
                    f"{dep.kind.lower()} dependency missing "
                    f"(ignored): {dep.depends_on}")
            continue
        state = prereq.state
        if dep.kind in ("OPTIONAL", "INFORMATIONAL"):
            reasons.append(
                f"{dep.kind.lower()} {dep.depends_on}={state} "
                "(non-blocking)")
            continue
        # REQUIRED
        if state in REQUIRED_DEP_ACCEPTABLE:
            reasons.append(f"required {dep.depends_on}={state} satisfied")
            continue
        if state in REQUIRED_DEP_PERMANENT_FAIL:
            blocking = True
            reasons.append(
                f"required {dep.depends_on}={state} permanently failed")
            continue
        if state in OBJECTIVE_TERMINAL:
            # terminal but not acceptable (e.g. REJECTED, CANCELLED)
            blocking = True
            reasons.append(
                f"required {dep.depends_on}={state} not acceptable")
            continue
        # non-terminal, not yet acceptable
        waiting = True
        reasons.append(f"required {dep.depends_on}={state} waiting")

    if blocking:
        effect = "permanently_blocked"
        ready = False
    elif waiting:
        effect = "waiting"
        ready = False
    else:
        effect = "satisfied" if any(
            d.kind == "REQUIRED" for d in objective.dependencies
        ) or not objective.dependencies else "informed"
        if not objective.dependencies:
            effect = "satisfied"
        ready = True
    return {"effect": effect, "ready": ready, "reasons": reasons}


def resolve_all(
    objectives: list[CampaignObjective],
) -> dict[str, dict[str, Any]]:
    """Resolve every objective against the full set (order-independent)."""

    assert_acyclic(objectives)
    by_id = {o.objective_id: o for o in objectives}
    return {o.objective_id: resolve_dependencies(o, by_id)
            for o in objectives}


__all__ = [
    "DependencyCycleError", "build_graph", "detect_cycles",
    "assert_acyclic", "resolve_dependencies", "resolve_all",
    "DEP_EFFECTS",
]
