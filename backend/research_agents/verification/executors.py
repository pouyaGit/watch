"""EPIC12 — bounded executors for typed verification actions.

Executors are the only place in EPIC12 that may produce evidence, and each one
is bounded by construction:

``ReadOnlyEvidenceExecutor``
    Derives evidence from material that already exists (persisted observation
    rows, a recorded response body, a recorded document).  It opens no socket,
    spawns nothing and writes nothing.  This is the capability the runtime
    genuinely has today.

``AuthorizedProbeExecutor``
    Delivers a controlled marker through an **injected transport** that must come
    from the platform's existing authorized execution layer, together with an
    issued authorization reference.  Without both, the action terminates
    ``BLOCKED`` (``transport_unavailable`` / ``authorization_unavailable``) —
    the adapter is wired, the capability is not assumed.

``UnavailableExecutor``
    For actions whose lane does not exist in this runtime (payload delivery,
    browser execution observation, and every reference-chain action).  It always
    returns ``BLOCKED`` with the declared limitation.  It never synthesizes
    execution evidence, and it never turns a refusal into a finding.

Deterministic marker: ``marker_for(action)`` derives the marker from the action
id, so a re-run produces the same marker (no uncontrolled payload mutation).

Honest negative results (§9) are produced when the material *was* available and
the signal was absent — the distinction from ``NOT_TESTED`` is preserved.
"""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import observations as ob
from backend.research_agents.verification.specialists import service as class_svc

# EPIC13: the deterministic reflection detector and context classifier are the
# single implementation of those two decisions.  They are imported lazily by
# the helpers below so that importing this module never depends on the
# acquisition package's import order.
def _detect(body: Any, marker: str) -> Any:
    """Run the EPIC13 reflection detector over a recorded body (bounded)."""
    from backend.research_agents.verification.acquisition import detector as _dt
    return _dt.detect(body, marker)


def _conclusive_absence(detection: Any) -> bool:
    """True only when the marker is absent AND the body was not truncated."""
    from backend.research_agents.verification.acquisition import detector as _dt
    return (getattr(detection, "status", "") == _dt.ABSENT
            and bool(getattr(detection, "conclusive", False)))


def _extended_context_class(body: str, marker: str) -> str:
    """The context classes EPIC12's structural scan cannot express.

    Returns ``""`` for every location EPIC12 already classifies, so its
    existing answers (and the tests that pin them) are unchanged; the classes
    added by EPIC13 (STYLE / JSON / COMMENT / UNKNOWN) are returned with the
    matching ``CONTEXT_*`` constant.
    """
    from backend.research_agents.verification.acquisition import context as _cx
    klass = _cx.classify(str(body or ""), str(marker or ""))
    return {
        _cx.STYLE: CONTEXT_STYLE,
        _cx.JSON_CONTEXT: CONTEXT_JSON,
        _cx.COMMENT: CONTEXT_COMMENT,
        _cx.UNKNOWN: CONTEXT_UNKNOWN,
    }.get(klass, "")

EXECUTOR_RULE_VERSION = "epic12-verification-executor-1"

REASON_TRANSPORT_UNAVAILABLE = "transport_unavailable"
REASON_CAPABILITY_UNAVAILABLE = "capability_unavailable"
REASON_MATERIAL_UNAVAILABLE = "material_unavailable"
REASON_ACTION_NOT_EXECUTABLE = "action_not_executable"
REASON_TRANSPORT_FAILED = "transport_failed"
REASON_AUTHORIZATION_UNAVAILABLE = "authorization_unavailable"

#: Context keys an executor may read (closed set, documented).
CONTEXT_KEYS: tuple[str, ...] = (
    "rows",            # persisted observation/evidence rows (read-only)
    "parameters",      # known parameter names for the target
    "response_body",   # a recorded response body
    "document",        # a recorded HTML/DOM document
    "request_ref",     # reference of the recorded request
    "response_ref",    # reference of the recorded response
    "job_id",
    "transport",       # injected authorized transport callable (or None)
    "marker",          # explicit marker override (tests/fixtures)
    # EPIC16: the deterministic class-classification lane.  The observed
    # material (headers, Location, destination, product/version) is passed
    # nested so no arbitrary header/URL primitive is exposed.
    "vulnerability_class",
    "material",
    "authorization",
    "action_id",
)

#: Context classes the classifier can produce (closed vocabulary, EPIC13 §8).
CONTEXT_HTML_TEXT = "html_text"
CONTEXT_HTML_ATTRIBUTE = "html_attribute"
CONTEXT_JAVASCRIPT = "javascript"
CONTEXT_URL = "url"
# EPIC13 §8 additions: locations EPIC12's structural scan cannot express.
CONTEXT_STYLE = "style"
CONTEXT_JSON = "json"
CONTEXT_COMMENT = "comment"
CONTEXT_UNKNOWN = "unknown"
CONTEXT_DOM = "dom"

CONTEXT_CLASSES: tuple[str, ...] = (
    CONTEXT_HTML_TEXT, CONTEXT_HTML_ATTRIBUTE, CONTEXT_JAVASCRIPT, CONTEXT_URL,
    CONTEXT_DOM,
)

#: Attributes whose value is a URL (a marker there is a URL context).
_URL_ATTRIBUTES: frozenset[str] = frozenset(
    {"href", "src", "action", "formaction", "data", "poster", "cite"})

#: Attributes whose value executes script when it contains the marker.
_JS_ATTRIBUTES: frozenset[str] = frozenset(
    {"onerror", "onload", "onclick", "onmouseover", "onfocus", "oninput",
     "onsubmit", "onbegin", "onstart"})

#: DOM sources that can carry attacker-controlled input.
DOM_SOURCE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("location_search", r"location\s*\.\s*search"),
    ("location_hash", r"location\s*\.\s*hash"),
    ("location_href", r"location\s*\.\s*href"),
    ("document_url", r"document\s*\.\s*URL"),
    ("document_referrer", r"document\s*\.\s*referrer"),
    ("window_name", r"window\s*\.\s*name"),
)

#: DOM sinks that execute or interpret attacker-controlled input.
DOM_SINK_PATTERNS: tuple[tuple[str, str], ...] = (
    ("innerHTML", r"\.\s*innerHTML\s*="),
    ("outerHTML", r"\.\s*outerHTML\s*="),
    ("document_write", r"document\s*\.\s*write\s*\("),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\("),
    ("eval", r"\beval\s*\("),
    ("setTimeout_string", r"setTimeout\s*\(\s*['\"]"),
    ("srcdoc", r"\.\s*srcdoc\s*="),
    ("script_src", r"createElement\s*\(\s*['\"]script['\"]\s*\)"),
)


@dataclass(frozen=True)
class ExecutionResult:
    """The bounded outcome of one action execution."""

    ok: bool
    executor: str
    observations: tuple[ob.VerificationObservation, ...] = ()
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    blocked_reason: str = ""

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_reason)

    @property
    def evidence_types(self) -> tuple[str, ...]:
        out: list[str] = []
        for item in self.observations:
            if item.evidence_type and item.evidence_type not in out:
                out.append(item.evidence_type)
        return tuple(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "executor": self.executor,
            "observation_ids": [o.observation_id for o in self.observations],
            "observation_count": len(self.observations),
            "evidence_types": list(self.evidence_types),
            "result": dict(self.result),
            "error": self.error,
            "blocked_reason": self.blocked_reason,
            "rule_version": EXECUTOR_RULE_VERSION,
        }


def marker_for(action: Any) -> str:
    """Deterministic controlled marker for one action (no randomness)."""
    seed = f"{action.action_id}|{action.candidate_id}|{action.attempt}"
    return "wx" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]


# --------------------------------------------------------------- classifying

def classify_context(body: str, marker: str) -> tuple[str, bool, str]:
    """Classify where the marker lands.  Returns (class, unsafe, reason).

    Deterministic and conservative: an encoded/absent marker is reported as
    *not* an unsafe context rather than guessed into one.
    """
    text = str(body or "")
    if not marker:
        return "", False, "no_marker_supplied"
    if marker not in text:
        if html.escape(marker) in text:
            return "", False, "marker_encoded"
        return "", False, "marker_not_present"
    # EPIC13 §8: locations EPIC12's scan cannot express are classified by the
    # EPIC13 classifier (which itself reuses the platform's own location
    # classifier).  Everything EPIC12 already answers is untouched.
    extended = _extended_context_class(text, marker)
    if extended:
        return extended, False, f"epic13:{extended.lower()}"

    index = text.find(marker)
    head = text[:index]

    # inside a <script> block?
    last_open_script = head.rfind("<script")
    last_close_script = head.rfind("</script")
    if last_open_script > last_close_script:
        return CONTEXT_JAVASCRIPT, True, "marker_inside_script_block"

    # inside a tag (attribute position)?
    last_lt = head.rfind("<")
    last_gt = head.rfind(">")
    if last_lt > last_gt:
        tag = text[last_lt:index]
        attr_match = re.search(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*[\"']?[^\"']*$",
                               tag)
        if attr_match:
            name = attr_match.group(1).lower()
            if name in _JS_ATTRIBUTES:
                return CONTEXT_HTML_ATTRIBUTE, True, f"event_handler:{name}"
            if name in _URL_ATTRIBUTES:
                return CONTEXT_URL, True, f"url_attribute:{name}"
            return CONTEXT_HTML_ATTRIBUTE, True, f"attribute:{name}"
        return CONTEXT_HTML_ATTRIBUTE, True, "attribute_position"

    return CONTEXT_HTML_TEXT, True, "html_text_position"


def dom_flow(document: str, marker: str = "") -> tuple[str, str, str]:
    """Find a DOM source→sink flow.  Returns (source, sink, evidence)."""
    text = str(document or "")
    if not text:
        return "", "", ""
    source_name = source_pattern = ""
    for name, pattern in DOM_SOURCE_PATTERNS:
        if re.search(pattern, text):
            source_name, source_pattern = name, pattern
            break
    if not source_name:
        return "", "", ""
    for name, pattern in DOM_SINK_PATTERNS:
        if re.search(pattern, text):
            return source_name, name, f"{source_name}->{name}"
    return source_name, "", f"{source_name}->no_sink"


# ---------------------------------------------------------------- executors

class BaseExecutor:
    """Common contract: ``supports`` + ``execute`` (bounded, deterministic)."""

    name = "base"

    def supports(self, action_type: str) -> bool:  # pragma: no cover - abstract
        return False

    def execute(self, action: Any, *, context: dict[str, Any]
                ) -> ExecutionResult:  # pragma: no cover - abstract
        raise NotImplementedError


class ReadOnlyEvidenceExecutor(BaseExecutor):
    """Derives evidence from already-recorded material.  No traffic."""

    name = "read_only_evidence"

    def supports(self, action_type: str) -> bool:
        return action_type in (
            ac.PARAMETER_INVENTORY, ac.CHECK_REFLECTION,
            ac.CLASSIFY_REFLECTION_CONTEXT, ac.TRACE_DOM_SOURCE,
            ac.TRACE_DOM_SINK)

    # -- helpers -----------------------------------------------------------

    def _common(self, action: Any, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "action_id": action.action_id,
            "candidate_id": action.candidate_id,
            "objective_id": action.objective_id,
            "scope_ref": action.scope_ref,
            "job_id": str(context.get("job_id") or ""),
            "marker": str(context.get("marker")
                          or action.inputs.get("marker")
                          or marker_for(action)),
            "where": action.target or str(context.get("target") or ""),
            "request_ref": str(context.get("request_ref") or ""),
            "response_ref": str(context.get("response_ref") or ""),
        }

    def _parameters(self, action: Any, context: dict[str, Any]) -> list[str]:
        explicit = context.get("parameters")
        out: list[str] = []
        if isinstance(explicit, (list, tuple, set)):
            out.extend(str(p) for p in explicit if str(p).strip())
        if not out:
            for row in context.get("rows") or []:
                if not isinstance(row, dict):
                    continue
                signal = str(row.get("signal") or "").lower()
                if "parameter_inventory" in signal or "param_inventory" in signal:
                    param = str(row.get("parameter") or row.get("param") or "").strip()
                    if param:
                        out.append(param)
                    detail = str(row.get("detail") or "")
                    out.extend(re.findall(r"\b([A-Za-z_][A-Za-z0-9_\-]{0,40})\b",
                                          detail)[:5])
        ordered: list[str] = []
        for item in out:
            if item and item not in ordered:
                ordered.append(item)
        return ordered

    # -- action implementations -------------------------------------------

    def execute(self, action: Any, *, context: dict[str, Any]) -> ExecutionResult:
        common = self._common(action, context)
        handler = {
            ac.PARAMETER_INVENTORY: self._parameter_inventory,
            ac.CHECK_REFLECTION: self._check_reflection,
            ac.CLASSIFY_REFLECTION_CONTEXT: self._classify_context,
            ac.TRACE_DOM_SOURCE: self._trace_dom,
            ac.TRACE_DOM_SINK: self._trace_dom,
        }.get(action.action_type)
        if handler is None:
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_ACTION_NOT_EXECUTABLE,
                error=f"unsupported action {action.action_type}")
        return handler(action, context, common)

    def _parameter_inventory(self, action: Any, context: dict[str, Any],
                             common: dict[str, Any]) -> ExecutionResult:
        parameters = self._parameters(action, context)
        if not parameters:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.not_tested(
                    signal="parameter_not_tested",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed="no parameter inventory material was available",
                    what_happened="parameter inventory requested",
                    where=common["where"], job_id=common["job_id"],
                    provenance={"executor": self.name,
                                "material": "absent"}),),
                result={"parameters": [], "material": "absent"})
        observations = tuple(
            ob.positive(
                signal="xss_parameter_inventory",
                evidence_type="PARAMETER_OBSERVED",
                action_id=action.action_id, candidate_id=action.candidate_id,
                objective_id=action.objective_id, scope_ref=action.scope_ref,
                observed=f"parameter {name} observed on the target",
                what_happened="parameter inventory derived from recorded rows",
                where=common["where"], under_input=name,
                under_request=common["request_ref"],
                request_ref=common["request_ref"],
                response_ref=common["response_ref"], job_id=common["job_id"],
                provenance={"executor": self.name, "material": "recorded_rows"})
            for name in parameters)
        return ExecutionResult(
            ok=True, executor=self.name, observations=observations,
            result={"parameters": parameters, "material": "recorded_rows"})

    def _check_reflection(self, action: Any, context: dict[str, Any],
                          common: dict[str, Any]) -> ExecutionResult:
        body = context.get("response_body")
        marker = common["marker"]
        if body is None:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.not_tested(
                    signal="reflection_not_tested",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed="no recorded response body was available to "
                                 "check for the marker",
                    what_happened="reflection check requested",
                    where=common["where"], job_id=common["job_id"],
                    provenance={"executor": self.name, "marker": marker,
                                "material": "absent"}),),
                result={"marker": marker, "material": "absent"})
        text = str(body)
        # EPIC13 §7: the deterministic detector replaces the naive substring
        # check, so the chain learns WHERE the marker landed, HOW MANY times,
        # and whether the body was truncated (a truncated absence is not a
        # negative result).
        detection = _detect(text, marker)
        provenance = {"executor": self.name, "marker": marker,
                      "material": "recorded_response",
                      "detector_version": detection.detector_version,
                      "status": detection.status,
                      "occurrence_count": detection.occurrence_count,
                      "offsets": list(detection.offsets),
                      "encoding": detection.encoding,
                      "transformation": detection.transformation,
                      "conclusive": detection.conclusive,
                      "truncated": detection.truncated,
                      "bytes_checked": detection.bytes_checked,
                      "context": detection.context}
        if detection.reflected:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.positive(
                    signal="reflection_observed",
                    evidence_type="REFLECTION_OBSERVED",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    observed=(f"marker {marker} present in the recorded "
                              f"response ({detection.status}, "
                              f"{detection.occurrence_count} occurrence(s))"),
                    what_happened="controlled marker found in the response body",
                    where=common["where"],
                    under_input=str(action.inputs.get("parameter") or ""),
                    under_request=common["request_ref"],
                    marker=marker, request_ref=common["request_ref"],
                    response_ref=common["response_ref"],
                    context=detection.context,
                    job_id=common["job_id"], provenance=provenance),),
                result={"marker": marker, "reflected": True,
                        "occurrence_count": detection.occurrence_count,
                        "context": detection.context,
                        "material": "recorded_response"})
        if _conclusive_absence(detection):
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.negative(
                    signal="reflection_not_observed",
                    action_id=action.action_id, candidate_id=action.candidate_id,
                    objective_id=action.objective_id, scope_ref=action.scope_ref,
                    not_observed=f"marker {marker} was not present in the "
                                 f"recorded response ({detection.bytes_checked} "
                                 f"bytes checked)",
                    what_happened="controlled marker checked against the "
                                  "recorded response body",
                    where=common["where"], under_input=str(
                        action.inputs.get("parameter") or ""),
                    under_request=common["request_ref"],
                    request_ref=common["request_ref"],
                    response_ref=common["response_ref"], job_id=common["job_id"],
                    provenance=provenance),),
                result={"marker": marker, "reflected": False,
                        "material": "recorded_response"})
        # inconclusive (e.g. a truncated body): never negative evidence
        return ExecutionResult(
            ok=True, executor=self.name,
            observations=(ob.not_tested(
                signal="reflection_not_tested",
                action_id=action.action_id, candidate_id=action.candidate_id,
                objective_id=action.objective_id, scope_ref=action.scope_ref,
                not_observed=("the reflection check was inconclusive "
                              f"({detection.reason})"),
                what_happened="controlled marker checked against the recorded "
                              "response body",
                where=common["where"], under_input=str(
                    action.inputs.get("parameter") or ""),
                under_request=common["request_ref"],
                request_ref=common["request_ref"],
                response_ref=common["response_ref"], job_id=common["job_id"],
                provenance=provenance),),
            result={"marker": marker, "reflected": False,
                    "conclusive": False, "material": "recorded_response"})

    def _classify_context(self, action: Any, context: dict[str, Any],
                          common: dict[str, Any]) -> ExecutionResult:
        body = context.get("response_body")
        marker = common["marker"]
        if body is None:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.not_tested(
                    signal="output_context_not_tested",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed="no recorded response body was available to "
                                 "classify",
                    what_happened="reflection context classification requested",
                    where=common["where"], job_id=common["job_id"],
                    provenance={"executor": self.name,
                                "material": "absent"}),),
                result={"material": "absent"})
        context_class, unsafe, reason = classify_context(str(body), marker)
        if not context_class:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.negative(
                    signal="output_context_not_observed",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed="the marker is not present, so no output "
                                 "context could be classified",
                    what_happened="context classification attempted on the "
                                  "recorded response",
                    where=common["where"], marker=marker,
                    response_ref=common["response_ref"],
                    job_id=common["job_id"],
                    provenance={"executor": self.name, "reason": reason,
                                "material": "recorded_response"}),),
                result={"context": "", "unsafe": False, "reason": reason})
        if not unsafe:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.negative(
                    signal="output_context_not_observed",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed=f"reflection lands in a non-executable "
                                 f"{context_class} context ({reason})",
                    what_happened="context classified as safe/encoded",
                    where=common["where"], context=context_class, marker=marker,
                    response_ref=common["response_ref"],
                    job_id=common["job_id"],
                    provenance={"executor": self.name, "reason": reason}),),
                result={"context": context_class, "unsafe": False,
                        "reason": reason})
        return ExecutionResult(
            ok=True, executor=self.name,
            observations=(ob.positive(
                signal="output_context_identified",
                evidence_type="OUTPUT_CONTEXT_IDENTIFIED",
                action_id=action.action_id, candidate_id=action.candidate_id,
                objective_id=action.objective_id, scope_ref=action.scope_ref,
                observed=f"marker reflects into an unsafe {context_class} "
                         f"context ({reason})",
                what_happened="reflection context classified deterministically",
                where=common["where"], under_input=str(
                    action.inputs.get("parameter") or ""),
                context=context_class, marker=marker,
                request_ref=common["request_ref"],
                response_ref=common["response_ref"], job_id=common["job_id"],
                provenance={"executor": self.name, "context_class": context_class,
                            "reason": reason}),),
            result={"context": context_class, "unsafe": True, "reason": reason})

    def _trace_dom(self, action: Any, context: dict[str, Any],
                   common: dict[str, Any]) -> ExecutionResult:
        document = context.get("document")
        marker = common["marker"]
        if document is None:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.not_tested(
                    signal="dom_sink_not_tested",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed="no recorded document was available to trace "
                                 "DOM sources and sinks",
                    what_happened="DOM source/sink trace requested",
                    where=common["where"], job_id=common["job_id"],
                    provenance={"executor": self.name,
                                "material": "absent"}),),
                result={"material": "absent"})
        source, sink, evidence = dom_flow(str(document), marker)
        if source and sink:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.positive(
                    signal="dom_sink_identified",
                    evidence_type="DOM_SINK_IDENTIFIED",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    observed=f"DOM flow {evidence} reaches a dangerous sink",
                    what_happened="DOM source traced into a sink in the "
                                  "recorded document",
                    where=common["where"], under_input=str(
                        action.inputs.get("parameter") or ""),
                    context=CONTEXT_DOM, marker=marker,
                    response_ref=common["response_ref"],
                    job_id=common["job_id"],
                    provenance={"executor": self.name, "source": source,
                                "sink": sink, "flow": evidence}),),
                result={"source": source, "sink": sink, "flow": evidence,
                        "material": "recorded_document"})
        if source:
            return ExecutionResult(
                ok=True, executor=self.name,
                observations=(ob.negative(
                    signal="dom_sink_not_observed",
                    action_id=action.action_id,
                    candidate_id=action.candidate_id,
                    objective_id=action.objective_id,
                    scope_ref=action.scope_ref,
                    not_observed=f"DOM source {source} exists but no dangerous "
                                 f"sink is reachable from it",
                    what_happened="DOM source traced; no sink found",
                    where=common["where"], context=CONTEXT_DOM, marker=marker,
                    job_id=common["job_id"],
                    provenance={"executor": self.name, "source": source,
                                "flow": evidence}),),
                result={"source": source, "sink": "", "flow": evidence})
        return ExecutionResult(
            ok=True, executor=self.name,
            observations=(ob.negative(
                signal="dom_sink_not_observed",
                action_id=action.action_id, candidate_id=action.candidate_id,
                objective_id=action.objective_id, scope_ref=action.scope_ref,
                not_observed="the recorded document has no DOM source that "
                             "carries attacker-controlled input",
                what_happened="DOM source search performed",
                where=common["where"], job_id=common["job_id"],
                provenance={"executor": self.name, "flow": evidence}),),
            result={"source": "", "sink": "", "flow": evidence})


class AuthorizedProbeExecutor(BaseExecutor):
    """Delivers a marker through an INJECTED authorized transport.

    The transport is resolved by the caller from the platform's existing
    authorized execution layer.  When it is absent (or the action carries no
    authorization reference) the action is ``BLOCKED``: the adapter exists, the
    capability is never assumed.
    """

    name = "authorized_probe"

    def supports(self, action_type: str) -> bool:
        return action_type in (ac.SEND_MARKER,)

    def execute(self, action: Any, *, context: dict[str, Any]) -> ExecutionResult:
        transport: Callable[..., Any] | None = context.get("transport")
        if transport is None:
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_TRANSPORT_UNAVAILABLE,
                error="no authorized transport is available for this runtime")
        if not str(action.authorization_id or "").strip():
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_AUTHORIZATION_UNAVAILABLE,
                error="an authorized probe requires an authorization reference")
        marker = str(context.get("marker")
                     or action.inputs.get("marker") or marker_for(action))
        target = action.target or str(context.get("target") or "")
        parameter = str(action.inputs.get("parameter") or "")
        try:
            response = transport(target=target, marker=marker,
                                 parameter=parameter,
                                 authorization_id=action.authorization_id)
        except Exception as exc:  # noqa: BLE001 - a transport failure is a
            # bounded failure, never evidence and never a confirmation
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_TRANSPORT_FAILED,
                error=f"transport_failed:{type(exc).__name__}",
                result={"marker": marker, "target": target})
        payload = dict(response or {})
        body = payload.get("body")
        request_ref = str(payload.get("request_ref") or "")
        response_ref = str(payload.get("response_ref") or "")
        base = {
            "action_id": action.action_id,
            "candidate_id": action.candidate_id,
            "objective_id": action.objective_id,
            "scope_ref": action.scope_ref,
            "job_id": str(context.get("job_id") or ""),
        }
        sent = ob.positive(
            signal="controlled_input_sent", evidence_type="CONTROLLED_INPUT_SENT",
            observed=f"controlled marker {marker} delivered to {target}",
            what_happened="authorized marker delivery performed",
            where=target, under_input=parameter, under_request=request_ref,
            marker=marker, request_ref=request_ref, response_ref=response_ref,
            confidence=ob.CONFIDENCE_OBSERVED,
            provenance={"executor": self.name,
                        "authorization_id": action.authorization_id}, **base)
        observations = [sent]
        if body is None:
            observations.append(ob.not_tested(
                signal="reflection_not_tested", not_observed=(
                    "the transport returned no response body to check"),
                what_happened="marker delivered; response body unavailable",
                where=target, marker=marker, job_id=base["job_id"],
                provenance={"executor": self.name}, **{k: base[k] for k in
                                                       ("action_id",
                                                        "candidate_id",
                                                        "objective_id",
                                                        "scope_ref")}))
        elif marker in str(body):
            observations.append(ob.positive(
                signal="reflection_observed",
                evidence_type="REFLECTION_OBSERVED",
                observed=f"marker {marker} reflected in the live response",
                what_happened="authorized marker delivery and reflection check",
                where=target, under_input=parameter, under_request=request_ref,
                marker=marker, request_ref=request_ref, response_ref=response_ref,
                confidence=ob.CONFIDENCE_OBSERVED,
                provenance={"executor": self.name}, **base))
        else:
            observations.append(ob.negative(
                signal="reflection_not_observed", not_observed=(
                    f"marker {marker} was not present in the live response"),
                what_happened="authorized marker delivery and reflection check",
                where=target, under_input=parameter, under_request=request_ref,
                marker=marker, request_ref=request_ref,
                response_ref=response_ref, job_id=base["job_id"],
                provenance={"executor": self.name}, **{
                    k: base[k] for k in ("action_id", "candidate_id",
                                         "objective_id", "scope_ref")}))
        return ExecutionResult(
            ok=True, executor=self.name, observations=tuple(observations),
            result={"marker": marker, "target": target,
                    "status_code": payload.get("status_code"),
                    "material": "authorized_transport"})


#: Action -> vulnerability class for the read-only classification lane.
CLASS_ACTION_CLASS: dict[str, str] = {
    ac.CHECK_CORS_HEADERS: "CORS",
    ac.CLASSIFY_CORS_ORIGIN_ECHO: "CORS",
    ac.CHECK_CREDENTIALS_MODE: "CORS",
    ac.ASSESS_RESPONSE_SENSITIVITY: "CORS",
    ac.CHECK_REDIRECT_LOCATION: "OPEN_REDIRECT",
    ac.CLASSIFY_REDIRECT_TARGET: "OPEN_REDIRECT",
    ac.CHECK_CALLBACK_INTERACTION: "SSRF",
    ac.CHECK_OBJECT_ACCESS: "IDOR",
}

#: Actions that WOULD need a live request lane and stay unimplemented.  They
#: are listed explicitly so a future lane cannot be wired by accident.
CLASS_ACTION_NETWORK: frozenset[str] = frozenset({
    ac.SEND_ORIGIN_HEADER, ac.SEND_REDIRECT_MARKER, ac.SEND_CALLBACK_URL,
    ac.OBSERVE_SERVER_RESPONSE, ac.ASSESS_SSRF_IMPACT,
})


class ClassClassificationExecutor(BaseExecutor):
    """EPIC16 §14 — the deterministic, offline class-classification lane.

    Consumes *recorded* material (response headers, a Location value, a
    destination, product/version strings) and produces class observations
    through the trusted producer.  It never opens a socket, never sets a
    header, and refuses when the class capability or the authorization is
    absent.
    """

    name = "class_classification"

    def supports(self, action_type: str) -> bool:
        return action_type in CLASS_ACTION_CLASS

    def execute(self, action: Any, *, context: dict[str, Any]
                ) -> ExecutionResult:
        action_type = str(action.action_type or "").upper()
        vulnerability_class = CLASS_ACTION_CLASS.get(action_type, "")
        material = dict(context.get("material") or {})
        authorization = context.get("authorization")
        if not vulnerability_class:
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_ACTION_NOT_EXECUTABLE,
                error=f"no class lane for action {action_type!r}")

        if authorization is None and not getattr(action, "authorized", False):
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_AUTHORIZATION_UNAVAILABLE,
                error="class classification requires a recorded authorization",
                result={"vulnerability_class": vulnerability_class,
                        "action_type": action_type})

        result = class_svc.verify_class(
            vulnerability_class, candidate_id=action.candidate_id,
            scope_ref=action.scope_ref, target=action.target,
            authorization=authorization, material=material,
            action_id=action_type,
            request_ref=str(context.get("request_ref") or ""),
            response_ref=str(context.get("response_ref") or ""))

        if result.outcome == class_svc.OUTCOME_BLOCKED:
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_AUTHORIZATION_UNAVAILABLE,
                error=result.reason, result=result.to_dict())
        if result.outcome == class_svc.OUTCOME_CAPABILITY_UNAVAILABLE:
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_CAPABILITY_UNAVAILABLE,
                error=result.reason, result=result.to_dict())
        if result.outcome == class_svc.OUTCOME_NOT_TESTED:
            return ExecutionResult(
                ok=False, executor=self.name,
                blocked_reason=REASON_MATERIAL_UNAVAILABLE,
                error=result.reason, result=result.to_dict())
        return ExecutionResult(
            ok=True, executor=self.name, observations=result.observations,
            result=result.to_dict())


class UnavailableExecutor(BaseExecutor):
    """Actions whose lane does not exist in this runtime — always BLOCKED."""

    name = "unavailable"

    def supports(self, action_type: str) -> bool:
        return action_type in ac.ACTION_SPECS

    def execute(self, action: Any, *, context: dict[str, Any]) -> ExecutionResult:
        spec = ac.ACTION_SPECS[action.action_type]
        return ExecutionResult(
            ok=False, executor=self.name,
            blocked_reason=REASON_CAPABILITY_UNAVAILABLE,
            error=spec.limitation or "no executor is wired for this action",
            result={"action_type": action.action_type, "safety": spec.safety,
                    "implemented": False})


_EXECUTORS: tuple[BaseExecutor, ...] = (
    ClassClassificationExecutor(),
    ReadOnlyEvidenceExecutor(), AuthorizedProbeExecutor(), UnavailableExecutor())

EXECUTOR_REGISTRY: dict[str, BaseExecutor] = {
    action_type: next(e for e in _EXECUTORS if e.supports(action_type))
    for action_type in ac.ACTION_TYPES
}


def executor_for(action_type: str) -> BaseExecutor:
    executor = EXECUTOR_REGISTRY.get(str(action_type or "").upper())
    if executor is None:
        raise ac.ActionError(f"no executor for action type: {action_type!r}")
    return executor


def execute_action(action: Any, *, context: dict[str, Any] | None = None
                   ) -> ExecutionResult:
    """Execute one action through its executor (never raises for a refusal)."""
    if action.state not in (ac.ACTION_CREATED, ac.ACTION_AUTHORIZED,
                            ac.ACTION_EXECUTING):
        return ExecutionResult(
            ok=False, executor="none",
            blocked_reason=REASON_ACTION_NOT_EXECUTABLE,
            error=f"action is {action.state}; terminal actions never execute")
    if action.target and not ac.target_in_scope(action.target, action.scope_ref):
        return ExecutionResult(
            ok=False, executor="none",
            blocked_reason="target_out_of_scope",
            error="action target is outside the recorded authorized scope")
    executor = executor_for(action.action_type)
    payload = dict(context or {})
    unknown = [k for k in payload if k not in CONTEXT_KEYS]
    if unknown:
        return ExecutionResult(
            ok=False, executor=executor.name,
            blocked_reason=REASON_ACTION_NOT_EXECUTABLE,
            error=f"unknown context keys: {sorted(unknown)}")
    return executor.execute(action, context=payload)


def executor_catalog() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for action_type in ac.ACTION_TYPES:
        spec = ac.ACTION_SPECS[action_type]
        executor = EXECUTOR_REGISTRY[action_type]
        out.append({
            "action_type": action_type,
            "safety": spec.safety,
            "executor": executor.name,
            "implemented": spec.implemented,
            "requires_network": spec.requires_network,
            "requires_authorization": spec.requires_authorization,
            "limitation": spec.limitation,
        })
    return out


__all__ = [
    "AuthorizedProbeExecutor", "BaseExecutor", "CONTEXT_CLASSES", "CONTEXT_DOM",
    "CONTEXT_HTML_ATTRIBUTE", "CONTEXT_HTML_TEXT", "CONTEXT_JAVASCRIPT",
    "CONTEXT_KEYS", "CONTEXT_URL", "DOM_SINK_PATTERNS", "DOM_SOURCE_PATTERNS",
    "CLASS_ACTION_CLASS", "CLASS_ACTION_NETWORK", "ClassClassificationExecutor",
    "EXECUTOR_REGISTRY", "EXECUTOR_RULE_VERSION", "ExecutionResult",
    "ReadOnlyEvidenceExecutor", "REASON_ACTION_NOT_EXECUTABLE",
    "REASON_CAPABILITY_UNAVAILABLE", "REASON_MATERIAL_UNAVAILABLE",
    "REASON_TRANSPORT_UNAVAILABLE", "UnavailableExecutor", "classify_context",
    "dom_flow", "execute_action", "executor_catalog", "executor_for",
    "marker_for",
]
