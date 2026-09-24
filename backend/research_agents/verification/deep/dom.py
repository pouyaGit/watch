"""EPIC15 §5/§6/§13 — the deterministic DOM source→sink verifier.

What this is
------------
A **lineage-bound** analysis of a served/recorded document.  It answers:

    *does a DOM source that carries the observed parameter reach a
    dangerous DOM sink inside the served material?*

and it distinguishes, explicitly and separately (§5):

* ``SERVER_SIDE_REFLECTION`` — the controlled marker appears in the
  served bytes (EPIC13's job, unchanged);
* ``DOM_SOURCE`` — a source read (``location.search``, ``location.hash``,
  ``document.URL``, ``document.referrer``, ``window.name``,
  ``postMessage``) that is bound to the observed parameter;
* ``DOM_SINK`` — a dangerous sink (``innerHTML``, ``outerHTML``,
  ``document.write``, ``insertAdjacentHTML``, ``eval``, ``Function``,
  ``setTimeout`` with string semantics, ``srcdoc``, dynamic ``script``
  src) reachable from that bound source;
* ``EXECUTION`` — **never** established here.  No JavaScript is executed,
  so this module can never produce ``PAYLOAD_EXECUTION``.

What this is not
----------------
* It is **not** a JavaScript engine and **not** complete taint tracking.
  The instrumentation is bounded variable-name tracking over the served
  document and its inline scripts, and it is labelled as such
  (``DOM_INSTRUMENTATION_METHOD`` / ``DOM_INSTRUMENTATION_VERSION``).
* A sink observed without a lineage-bound source, or a source whose data
  never reaches a sink, is **not** a DOM sink finding.

The source and sink vocabularies are EPIC12's own closed sets
(``DOM_SOURCE_PATTERNS`` / ``DOM_SINK_PATTERNS``), imported — never
re-declared, never widened here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ai.limits import ceilings as ce
from backend.research_agents.verification.executors import (
    DOM_SINK_PATTERNS, DOM_SOURCE_PATTERNS)

DOM_INSTRUMENTATION_METHOD = "served_document_static_analysis"
DOM_INSTRUMENTATION_VERSION = "epic15-dom-trace-1"

#: flow outcomes (closed vocabulary)
FLOW_LINEAGE = "SOURCE_AND_SINK_LINEAGE"
FLOW_SOURCE_ONLY = "SOURCE_ONLY"
FLOW_SINK_ONLY = "SINK_ONLY"
FLOW_NO_SOURCE = "NO_SOURCE"
FLOW_NO_SINK = "NO_SINK"
FLOW_NO_LINEAGE = "NO_LINEAGE"

FLOW_STATES: tuple[str, ...] = (
    FLOW_LINEAGE, FLOW_SOURCE_ONLY, FLOW_SINK_ONLY, FLOW_NO_SOURCE,
    FLOW_NO_SINK, FLOW_NO_LINEAGE)

#: element kind of the observation, kept separate from evidence type (§5)
KIND_SERVER_SIDE_REFLECTION = "SERVER_SIDE_REFLECTION"
KIND_DOM_SOURCE = "DOM_SOURCE"
KIND_DOM_SINK = "DOM_SINK"
KIND_EXECUTION = "EXECUTION"

OBSERVATION_KINDS: tuple[str, ...] = (
    KIND_SERVER_SIDE_REFLECTION, KIND_DOM_SOURCE, KIND_DOM_SINK,
    KIND_EXECUTION)

#: bound window (characters) in which a sink must consume the bound variable
_LINEAGE_WINDOW = 2000

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"


@dataclass(frozen=True)
class DomTrace:
    """The deterministic result of one served-document DOM trace."""

    kind: str
    flow: str
    source: str = ""
    sink: str = ""
    parameter: str = ""
    variable: str = ""
    evidence: str = ""
    reaches_sink: bool = False
    document_bytes: int = 0
    bounded: bool = False
    inline_scripts: int = 0
    instrumentation_method: str = DOM_INSTRUMENTATION_METHOD
    instrumentation_version: str = DOM_INSTRUMENTATION_VERSION
    reason: str = ""

    @property
    def produces_dom_sink_evidence(self) -> bool:
        """§6: only a lineage-bound source→sink flow is DOM sink evidence."""
        return bool(self.reaches_sink and self.source and self.sink
                    and self.flow == FLOW_LINEAGE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "flow": self.flow,
            "source": self.source,
            "sink": self.sink,
            "parameter": self.parameter,
            "variable": self.variable,
            "evidence": self.evidence,
            "reaches_sink": self.reaches_sink,
            "document_bytes": self.document_bytes,
            "bounded": self.bounded,
            "inline_scripts": self.inline_scripts,
            "instrumentation_method": self.instrumentation_method,
            "instrumentation_version": self.instrumentation_version,
            "reason": self.reason,
        }


def _script_blocks(text: str) -> list[str]:
    return re.findall(r"<script\b[^>]*>(.*?)</script>", text,
                      flags=re.IGNORECASE | re.DOTALL)


def _first_match(patterns, text: str) -> tuple[str, str]:
    for name, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return name, pattern
    return "", ""


def _parameter_bound_to_source(block: str, parameter: str,
                               source_pattern: str) -> tuple[str, str]:
    """Is the observed parameter read into a variable from the source?

    Bounded variable-name tracking: ``<ident> = <expr using the source>``
    where the same expression mentions the observed parameter (or the
    source is a whole-URL source such as ``document.URL`` / ``location.href``
    / ``window.name``, which carries the parameter by construction).
    Returns ``(variable, evidence)``.
    """
    if not parameter:
        return "", ""
    name = re.escape(parameter)
    whole_url = source_pattern in (
        r"location\s*\.\s*href", r"document\s*\.\s*URL",
        r"document\s*\.\s*referrer", r"window\s*\.\s*name")
    assignment = re.compile(
        rf"(?:var|let|const)?\s*({_IDENT})\s*=\s*([^;\n]{{0,240}}?{source_pattern}[^;\n]{{0,240}})",
        re.IGNORECASE)
    for match in assignment.finditer(block):
        variable, expression = match.group(1), match.group(2)
        if re.search(name, expression, flags=re.IGNORECASE) or whole_url:
            return variable, f"{variable}={expression.strip()[:120]}"
    return "", ""


def _sink_consumes_variable(block: str, variable: str,
                            sink_pattern: str) -> tuple[str, str]:
    """Does a dangerous sink consume the bound variable?"""
    if not variable:
        return "", ""
    var = re.escape(variable)
    for match in re.finditer(sink_pattern, block, flags=re.IGNORECASE):
        window = block[match.start():match.start() + _LINEAGE_WINDOW]
        if re.search(rf"\b{var}\b", window, flags=re.IGNORECASE):
            return match.group(0).strip()[:120], window.strip()[:160]
    return "", ""


def trace_dom_flow(document: Any, *, parameter: str = "",
                   marker: str = "") -> DomTrace:
    """Trace a DOM source→sink flow in a served document (§6).

    Deterministic, bounded (``browser_dom_observation_bytes``), and
    explicitly static: no JavaScript runs and no browser exists here.
    """
    raw = str(document or "")
    limit = int(ce.CEILINGS["browser_dom_observation_bytes"])
    text = raw[:limit]
    bounded = len(raw) > limit
    if not text.strip():
        return DomTrace(kind=KIND_DOM_SOURCE, flow=FLOW_NO_SOURCE,
                        parameter=parameter, document_bytes=0,
                        reason="empty_document")
    blocks = _script_blocks(text)
    material = "\n".join(blocks) if blocks else text

    source, source_pattern = _first_match(DOM_SOURCE_PATTERNS, material)
    sink, sink_pattern = _first_match(DOM_SINK_PATTERNS, material)
    common = {
        "parameter": parameter,
        "document_bytes": len(raw),
        "bounded": bounded,
        "inline_scripts": len(blocks),
    }

    if not source and not sink:
        return DomTrace(kind=KIND_DOM_SOURCE, flow=FLOW_NO_SOURCE,
                        reason="no_dom_source_and_no_sink", **common)
    if not source:
        return DomTrace(kind=KIND_DOM_SINK, flow=FLOW_NO_SOURCE, sink=sink,
                        reason="sink_present_without_a_dom_source", **common)
    if not sink:
        return DomTrace(kind=KIND_DOM_SOURCE, flow=FLOW_NO_SINK, source=source,
                        reason="source_present_without_a_dangerous_sink",
                        **common)

    variable = ""
    evidence = ""
    for block in (blocks or [material]):
        variable, binding = _parameter_bound_to_source(
            block, parameter, source_pattern)
        if variable:
            evidence = binding
            break
    if not variable:
        return DomTrace(
            kind=KIND_DOM_SOURCE, flow=FLOW_SOURCE_ONLY, source=source,
            sink=sink, reason=("source_and_sink_present_but_no_bound_"
                               "parameter_lineage"), **common)
    sink_call = ""
    flow_evidence = ""
    for block in (blocks or [material]):
        sink_call, flow_evidence = _sink_consumes_variable(
            block, variable, sink_pattern)
        if sink_call:
            break
    if not sink_call:
        return DomTrace(
            kind=KIND_DOM_SOURCE, flow=FLOW_NO_LINEAGE, source=source,
            sink=sink, variable=variable, evidence=evidence,
            reason="bound_source_does_not_reach_the_sink", **common)
    return DomTrace(
        kind=KIND_DOM_SINK, flow=FLOW_LINEAGE, source=source, sink=sink,
        variable=variable, reaches_sink=True,
        evidence=f"{source}->{variable}->{sink}",
        reason="lineage_bound_source_reaches_sink", **common)


def trace_summary(trace: DomTrace) -> dict[str, Any]:
    """The audit-facing summary of one trace (§14 metadata)."""
    return {
        "kind": trace.kind,
        "flow": trace.flow,
        "source": trace.source,
        "sink": trace.sink,
        "parameter": trace.parameter,
        "reaches_sink": trace.reaches_sink,
        "instrumentation_method": trace.instrumentation_method,
        "instrumentation_version": trace.instrumentation_version,
        "bounded": trace.bounded,
        "document_bytes": trace.document_bytes,
        "reason": trace.reason,
    }
