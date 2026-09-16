"""Stage R74 deterministic external-research-evidence intake (adapter).

R74 is the missing bridge between evidence obtained *outside* Watch and the
existing bounded research loop:

    externally acquired evidence -> intake -> validation/normalization
      -> R68-compatible canonical evidence -> R72 re-evaluation
      -> R73 feedback -> CONTINUE / HUMAN_REVIEW / STOP

The human researcher (or another explicitly authorized external process)
obtains the evidence. Watch never acquires it: this module is an **intake
adapter only**. It is not a scanner, HTTP client, exploitation engine, payload
generator, request executor, authorization mechanism, hypothesis model,
confidence model or planner. It validates, normalizes and bounds an external
evidence package, then feeds the accepted evidence into the existing R72 and
R73 engines.

Architecture / reuse decision (inspected first):

- ``research_feedback_loop.py`` (R73) owns the evidence-effect, source,
  reference-kind and rejection vocabularies and the delta/feedback engine.
  R74 imports those closed vocabularies and calls
  ``evaluate_research_iteration`` instead of re-implementing feedback.
- ``research_decision_readiness_planner.py`` (R72) remains the readiness
  authority: R74 applies R73's authoritative delta to a bounded status
  projection of the R71 plan and calls ``plan_decision_readiness`` again.
- ``research_evidence_acquisition_planner.py`` (R71) remains the acquisition
  authority; its plan shape and requirement statuses are consumed read-only.
- ``research_outcome_planner.py`` (R70) remains the action authority; its
  outcomes provide the raw canonical references used for invalidation
  matching.
- The R68 evidence contract (``evidence_index`` / ``evidence_catalog`` /
  canonical ``kind:value`` references in ``tests/local_e2e/r64_research.py``)
  is the identity model: accepted evidence items must use the existing
  canonical reference vocabulary. Anything outside it is rejected, never
  mapped into a new namespace.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no HTTP client, no socket, no
  subprocess, no shell, no LLM, no Mongo, no target interaction, no
  execution and no authorization semantics.
- Fail-closed: package version, structure, size, hypothesis/requirement
  existence, reference format, source, effect, duplicates, invalidation
  references, ambiguity, observation bounds and sensitive/execution content
  are all validated; rejected items are reported as bounded records and their
  bodies are never persisted.
- No hidden inference: items carry explicit hypothesis, requirement, source
  and effect; nothing is derived from names, priority, confidence or model
  wording.
- Deterministic: canonical sorting, stable ``EI1``... intake ids, no
  timestamps, no randomness; repeated runs are byte-identical.
- Additive and read-only: inputs are never mutated; every result is a new
  dict with rule version ``r74-1``.
- Storage stays in the existing research artifact envelope; no Mongo change.
"""

from __future__ import annotations

import re
from typing import Mapping

from ai.knowledge.research_decision_readiness_planner import (
    RULE_VERSION as SOURCE_READINESS_RULE_VERSION,
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    RULE_VERSION as SOURCE_ACQUISITION_RULE_VERSION,
    SOURCE_AUTHORIZED_TEST_CONTEXT,
    STATUS_AVAILABLE,
    STATUS_MISSING,
)
from ai.knowledge.research_feedback_loop import (
    EFFECT_CONTRADICTS,
    EFFECT_INVALIDATES,
    EFFECT_PROVIDES,
    EVIDENCE_EFFECTS,
    EVIDENCE_REF_KINDS,
    EVIDENCE_SOURCES,
    REJECTION_AMBIGUOUS_EVIDENCE,
    REJECTION_INVALID_SOURCE,
    REJECTION_MALFORMED_EVIDENCE,
    REJECTION_SENSITIVE_EVIDENCE,
    REJECTION_UNKNOWN_HYPOTHESIS,
    REJECTION_UNKNOWN_INVALIDATED_REF,
    REJECTION_UNKNOWN_REQUIREMENT,
    REJECTION_UNSUPPORTED_EFFECT,
    RULE_VERSION as SOURCE_FEEDBACK_RULE_VERSION,
    SOURCE_STORED_RESPONSE,
    evaluate_research_iteration,
)
from ai.knowledge.research_outcome_planner import (
    RULE_VERSION as SOURCE_ACTION_RULE_VERSION,
    SAFETY_BLOCK,
)

RULE_VERSION = "r74-1"
PACKAGE_VERSION = "r74-1"

MAX_PACKAGE_ITEMS = 16
MAX_OBSERVATIONS = 4
MAX_SIGNALS = 4
MAX_INVALIDATES_REFS = 6
MAX_REF_CHARS = 512
MAX_FACT_CHARS = 320
MAX_SIGNAL_CHARS = 64
MAX_REJECTIONS = 16

# ---------------------------------------------------------------------------
# Closed package-status vocabulary
# ---------------------------------------------------------------------------

STATUS_NOT_PROVIDED = "NOT_PROVIDED"
STATUS_ACCEPTED = "ACCEPTED"
STATUS_PARTIAL = "PARTIAL"
STATUS_REJECTED = "REJECTED"

PACKAGE_STATUSES: tuple[str, ...] = (
    STATUS_NOT_PROVIDED,
    STATUS_ACCEPTED,
    STATUS_PARTIAL,
    STATUS_REJECTED,
)

# ---------------------------------------------------------------------------
# Intake source vocabulary (R73 sources + the existing R71 authorized context)
# ---------------------------------------------------------------------------

INTAKE_SOURCES: tuple[str, ...] = EVIDENCE_SOURCES + (
    SOURCE_AUTHORIZED_TEST_CONTEXT,
)

#: Authorized-context observations enter the R73 feedback contract as stored
#: response observations; no authorization model is introduced here.
INTAKE_SOURCE_TO_BUNDLE_SOURCE: dict[str, str] = {
    source: source for source in EVIDENCE_SOURCES
}
INTAKE_SOURCE_TO_BUNDLE_SOURCE[SOURCE_AUTHORIZED_TEST_CONTEXT] = (
    SOURCE_STORED_RESPONSE
)

# ---------------------------------------------------------------------------
# Closed rejection codes (R73 codes reused where identical + intake codes)
# ---------------------------------------------------------------------------

REJECTION_UNSUPPORTED_PACKAGE_VERSION = "UNSUPPORTED_PACKAGE_VERSION"
REJECTION_PACKAGE_TOO_LARGE = "PACKAGE_TOO_LARGE"
REJECTION_INVALID_EVIDENCE_REF = "INVALID_EVIDENCE_REF"
REJECTION_DUPLICATE_EVIDENCE = "DUPLICATE_EVIDENCE"
REJECTION_EXECUTION_INSTRUCTION = "EXECUTION_INSTRUCTION_REJECTED"

INTAKE_REJECTION_CODES: tuple[str, ...] = (
    REJECTION_MALFORMED_EVIDENCE,
    REJECTION_UNSUPPORTED_EFFECT,
    REJECTION_UNKNOWN_HYPOTHESIS,
    REJECTION_UNKNOWN_REQUIREMENT,
    REJECTION_INVALID_EVIDENCE_REF,
    REJECTION_UNKNOWN_INVALIDATED_REF,
    REJECTION_AMBIGUOUS_EVIDENCE,
    REJECTION_SENSITIVE_EVIDENCE,
    REJECTION_INVALID_SOURCE,
    REJECTION_UNSUPPORTED_PACKAGE_VERSION,
    REJECTION_PACKAGE_TOO_LARGE,
    REJECTION_DUPLICATE_EVIDENCE,
    REJECTION_EXECUTION_INSTRUCTION,
)

# ---------------------------------------------------------------------------
# Sensitive / execution-content gates
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"://")
_MONGO_ID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*\S+"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_EXECUTION_RE = re.compile(
    r"(?i)("
    r"\bcurl\b|\bwget\b|\bnmap\b|\bmasscan\b|\bsqlmap\b|\bnuclei\b|"
    r"\bffuf\b|\bgobuster\b|\bnikto\b|\bmetasploit\b|\bmsfconsole\b|"
    r"\bhydra\b|\bhashcat\b|\bburpsuite\b|\bburp\b|"
    r"\bbash\s+-c\b|\bsh\s+-c\b|\bpowershell\b|\bcmd\.exe\b|"
    r"\bpython\s+-c\b|;\s*rm\s|\|\s*sh\b|`[^`]+`|\$\([^)]*\)"
    r")"
)


class EvidenceIntakeError(ValueError):
    """Deterministic, secret-free R74 intake failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Small deterministic helpers (mirrors the previous stages' conventions)
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _safe_text(value: object, limit: int) -> str:
    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:limit]


def _ref_safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    return text[:MAX_REF_CHARS]


def _redact_like_r31(value: object) -> str:
    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:MAX_REF_CHARS]


def _ref_kind(ref: object) -> str:
    return _text(ref).partition(":")[0].strip().lower()


def _ref_value(ref: object) -> str:
    return _text(ref).partition(":")[2].strip()


def _is_canonical_ref(ref: str) -> bool:
    return (
        _ref_kind(ref) in EVIDENCE_REF_KINDS
        and bool(_ref_value(ref))
    )


def _ref_is_sensitive(ref: str) -> bool:
    _, _, value = _text(ref).partition(":")
    return _is_sensitive(value)


def _is_sensitive(text: str) -> bool:
    return bool(
        _URL_RE.search(text)
        or _MONGO_ID_RE.search(text)
        or _IPV4_RE.search(text)
        or _SECRET_RE.search(text)
        or _BEARER_RE.search(text)
    )


def _is_execution_instruction(text: str) -> bool:
    return bool(_EXECUTION_RE.search(text))


# ---------------------------------------------------------------------------
# Previous-state indexes (read-only over R70/R71/R72)
# ---------------------------------------------------------------------------


def _records(readiness_plan: object) -> list[Mapping]:
    block = _block(readiness_plan)
    raw = block.get("records")
    if raw is not None:
        return _mapping_items(raw)
    return _mapping_items(readiness_plan)


def _plans_by_ref(acquisition_plan: object) -> dict[str, Mapping]:
    plans: dict[str, Mapping] = {}
    block = _block(acquisition_plan)
    raw = block.get("plans")
    items = (
        _mapping_items(raw)
        if raw is not None
        else _mapping_items(acquisition_plan)
    )
    for plan in items:
        ref = _text(plan.get("plan_id"))
        if ref:
            plans[ref] = plan
    return plans


def _raw_outcome_refs(action_plan: object) -> set[str]:
    refs: set[str] = set()
    for outcome in _mapping_items(_block(action_plan).get("outcomes")):
        evidence = outcome.get("current_evidence")
        if not isinstance(evidence, Mapping):
            continue
        for entry in _mapping_items(evidence.get("observations")):
            ref = _text(entry.get("ref"))
            if ref and _ref_kind(ref) in EVIDENCE_REF_KINDS:
                refs.add(ref)
    return refs


def _known_indexes(
    hypotheses: object,
    action_plan: object,
    acquisition_plan: object,
    readiness_plan: object,
) -> tuple[set[str], dict[str, set[str]], set[str], set[str], dict[str, Mapping]]:
    records = _records(readiness_plan)
    known_hypotheses: set[str] = set()
    known_requirements: dict[str, set[str]] = {}
    for record in records:
        kinds = {
            _upper(entry.get("requirement_kind"))
            for entry in _mapping_items(record.get("required_evidence"))
            if entry.get("requirement_kind")
        }
        for ref in record.get("hypothesis_refs") or ():
            name = _safe_text(ref, 16)
            if not name:
                continue
            known_hypotheses.add(name)
            known_requirements.setdefault(name, set()).update(kinds)
    if not known_hypotheses:
        for position in range(1, len(_mapping_items(hypotheses)) + 1):
            known_hypotheses.add(f"H{position}")

    raw_refs = _raw_outcome_refs(action_plan)
    redaction_groups: dict[str, set[str]] = {}
    for ref in raw_refs:
        redaction_groups.setdefault(_redact_like_r31(ref), set()).add(ref)
    ambiguous_refs = {
        ref
        for group in redaction_groups.values()
        if len(group) > 1
        for ref in group
    }
    known_refs: set[str] = set(raw_refs)
    for ref in raw_refs:
        known_refs.add(_redact_like_r31(ref))
    plans = _plans_by_ref(acquisition_plan)
    for plan in plans.values():
        for entry in _mapping_items(plan.get("required_evidence")):
            for evidence in _mapping_items(entry.get("evidence")):
                ref = _text(evidence.get("ref"))
                if ref:
                    known_refs.add(ref)
    return (
        known_hypotheses,
        known_requirements,
        known_refs,
        ambiguous_refs,
        plans,
    )


# ---------------------------------------------------------------------------
# Package validation / normalization
# ---------------------------------------------------------------------------


def _validate_refs(
    raw: object,
    *,
    limit: int,
    known_refs: set[str],
    ambiguous_refs: set[str],
) -> tuple[list[str], str | None]:
    if raw is None:
        return [], None
    if not isinstance(raw, (list, tuple)):
        return [], REJECTION_MALFORMED_EVIDENCE
    refs: list[str] = []
    for entry in raw:
        ref = _ref_safe_text(entry)
        if not ref or not _is_canonical_ref(ref):
            return [], REJECTION_INVALID_EVIDENCE_REF
        if len(_text(entry)) > MAX_REF_CHARS:
            return [], REJECTION_INVALID_EVIDENCE_REF
        if _ref_is_sensitive(ref):
            return [], REJECTION_SENSITIVE_EVIDENCE
        if _is_execution_instruction(ref):
            return [], REJECTION_EXECUTION_INSTRUCTION
        if ref not in known_refs:
            return [], REJECTION_UNKNOWN_INVALIDATED_REF
        if ref in ambiguous_refs:
            return [], REJECTION_AMBIGUOUS_EVIDENCE
        if ref not in refs:
            refs.append(ref)
        if len(refs) >= limit:
            break
    return refs, None


def _validate_observations(
    item: Mapping,
) -> tuple[list[dict], str | None]:
    raw = item.get("observations")
    if raw is None:
        raw = []
    if not isinstance(raw, (list, tuple)):
        return [], REJECTION_MALFORMED_EVIDENCE
    if len(raw) > MAX_OBSERVATIONS:
        return [], REJECTION_MALFORMED_EVIDENCE
    observations: list[dict] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            return [], REJECTION_MALFORMED_EVIDENCE
        ref = _ref_safe_text(entry.get("ref"))
        fact = _safe_text(entry.get("fact"), MAX_FACT_CHARS)
        if not ref or not _is_canonical_ref(ref):
            return [], REJECTION_INVALID_EVIDENCE_REF
        if len(_text(entry.get("ref"))) > MAX_REF_CHARS:
            return [], REJECTION_INVALID_EVIDENCE_REF
        if (
            _ref_is_sensitive(ref)
            or _is_sensitive(fact)
            or _is_execution_instruction(ref)
            or _is_execution_instruction(fact)
        ):
            code = (
                REJECTION_SENSITIVE_EVIDENCE
                if _ref_is_sensitive(ref) or _is_sensitive(fact)
                else REJECTION_EXECUTION_INSTRUCTION
            )
            return [], code
        if not any(existing["ref"] == ref for existing in observations):
            observations.append({"ref": ref, "fact": fact})
        if len(observations) >= MAX_OBSERVATIONS:
            break
    primary = _ref_safe_text(item.get("evidence_ref"))
    if primary:
        if not _is_canonical_ref(primary):
            return [], REJECTION_INVALID_EVIDENCE_REF
        if len(_text(item.get("evidence_ref"))) > MAX_REF_CHARS:
            return [], REJECTION_INVALID_EVIDENCE_REF
        if _ref_is_sensitive(primary) or _is_execution_instruction(primary):
            code = (
                REJECTION_SENSITIVE_EVIDENCE
                if _ref_is_sensitive(primary)
                else REJECTION_EXECUTION_INSTRUCTION
            )
            return [], code
        if not any(existing["ref"] == primary for existing in observations):
            observations.append({"ref": primary, "fact": ""})
    return observations[:MAX_OBSERVATIONS], None


def _validate_signals(item: Mapping) -> tuple[list[dict], str | None]:
    raw = item.get("derived_signals")
    if raw is None:
        return [], None
    if not isinstance(raw, (list, tuple)):
        return [], REJECTION_MALFORMED_EVIDENCE
    if len(raw) > MAX_SIGNALS:
        return [], REJECTION_MALFORMED_EVIDENCE
    signals: list[dict] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            return [], REJECTION_MALFORMED_EVIDENCE
        name = _safe_text(entry.get("signal"), MAX_SIGNAL_CHARS)
        detail = _safe_text(entry.get("detail"), MAX_FACT_CHARS)
        if not name:
            return [], REJECTION_MALFORMED_EVIDENCE
        if _is_sensitive(name) or _is_sensitive(detail):
            return [], REJECTION_SENSITIVE_EVIDENCE
        if _is_execution_instruction(name) or _is_execution_instruction(detail):
            return [], REJECTION_EXECUTION_INSTRUCTION
        if not any(existing["signal"] == name for existing in signals):
            signals.append({"signal": name, "detail": detail})
        if len(signals) >= MAX_SIGNALS:
            break
    return signals, None


def _normalize_item(
    raw: object,
    *,
    known_hypotheses: set[str],
    known_requirements: Mapping[str, set[str]],
    known_refs: set[str],
    ambiguous_refs: set[str],
) -> tuple[dict | None, str | None]:
    if not isinstance(raw, Mapping):
        return None, REJECTION_MALFORMED_EVIDENCE
    hypothesis_ref = _safe_text(raw.get("hypothesis_ref"), 16)
    if not hypothesis_ref or hypothesis_ref not in known_hypotheses:
        return None, REJECTION_UNKNOWN_HYPOTHESIS
    effect = _upper(raw.get("effect"))
    if effect not in EVIDENCE_EFFECTS:
        return None, REJECTION_UNSUPPORTED_EFFECT
    source = _upper(raw.get("source"))
    if source not in INTAKE_SOURCES:
        return None, REJECTION_INVALID_SOURCE
    requirement_kind = _upper(raw.get("requirement_kind"))
    if effect != EFFECT_INVALIDATES:
        if not requirement_kind:
            return None, REJECTION_UNKNOWN_REQUIREMENT
        if requirement_kind not in known_requirements.get(
            hypothesis_ref, set()
        ):
            return None, REJECTION_UNKNOWN_REQUIREMENT
        if raw.get("invalidates_refs"):
            return None, REJECTION_MALFORMED_EVIDENCE

    observations, code = _validate_observations(raw)
    if code:
        return None, code
    signals, code = _validate_signals(raw)
    if code:
        return None, code
    invalidates: list[str] = []
    if effect == EFFECT_INVALIDATES:
        invalidates, code = _validate_refs(
            raw.get("invalidates_refs"),
            limit=MAX_INVALIDATES_REFS,
            known_refs=known_refs,
            ambiguous_refs=ambiguous_refs,
        )
        if code:
            return None, code
        if not invalidates:
            return None, REJECTION_MALFORMED_EVIDENCE
        if requirement_kind and requirement_kind not in known_requirements.get(
            hypothesis_ref, set()
        ):
            return None, REJECTION_UNKNOWN_REQUIREMENT
    elif not observations and not signals:
        return None, REJECTION_MALFORMED_EVIDENCE

    return (
        {
            "hypothesis_ref": hypothesis_ref,
            "requirement_kind": requirement_kind,
            "effect": effect,
            "source": source,
            "bundle_source": INTAKE_SOURCE_TO_BUNDLE_SOURCE[source],
            "observations": observations,
            "derived_signals": signals,
            "invalidates_refs": invalidates,
        },
        None,
    )


def _signature(item: Mapping) -> tuple:
    return (
        item["hypothesis_ref"],
        item["requirement_kind"],
        item["effect"],
        tuple(sorted(entry["ref"] for entry in item["observations"])),
        tuple(sorted(item["invalidates_refs"])),
    )


def _canonical_key(item: Mapping) -> tuple:
    return (
        item["hypothesis_ref"],
        item["requirement_kind"],
        item["effect"],
        tuple(sorted(entry["ref"] for entry in item["observations"])),
        tuple(sorted(item["invalidates_refs"])),
        item["source"],
    )


def normalize_evidence_package(
    package: object,
    *,
    hypotheses: object = None,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
) -> dict:
    """Validate and normalize one bounded external evidence package."""

    if package is None:
        return {
            "package_status": STATUS_NOT_PROVIDED,
            "accepted_items": [],
            "rejections": [],
            "package_rejections": [],
            "bundle": {"items": []},
        }
    if not isinstance(package, Mapping):
        return {
            "package_status": STATUS_REJECTED,
            "accepted_items": [],
            "rejections": [],
            "package_rejections": [{"code": REJECTION_MALFORMED_EVIDENCE}],
            "bundle": {"items": []},
        }
    version = _text(package.get("package_version"))
    if version != PACKAGE_VERSION:
        return {
            "package_status": STATUS_REJECTED,
            "accepted_items": [],
            "rejections": [],
            "package_rejections": [
                {"code": REJECTION_UNSUPPORTED_PACKAGE_VERSION}
            ],
            "bundle": {"items": []},
        }
    raw_items = package.get("items")
    if not isinstance(raw_items, (list, tuple)):
        return {
            "package_status": STATUS_REJECTED,
            "accepted_items": [],
            "rejections": [],
            "package_rejections": [{"code": REJECTION_MALFORMED_EVIDENCE}],
            "bundle": {"items": []},
        }
    if len(raw_items) > MAX_PACKAGE_ITEMS:
        return {
            "package_status": STATUS_REJECTED,
            "accepted_items": [],
            "rejections": [],
            "package_rejections": [{"code": REJECTION_PACKAGE_TOO_LARGE}],
            "bundle": {"items": []},
        }

    (
        known_hypotheses,
        known_requirements,
        known_refs,
        ambiguous_refs,
        _,
    ) = _known_indexes(hypotheses, action_plan, acquisition_plan, readiness_plan)

    accepted: list[dict] = []
    rejections: list[dict] = []
    seen: set[tuple] = set()
    for position, raw in enumerate(raw_items, start=1):
        item, code = _normalize_item(
            raw,
            known_hypotheses=known_hypotheses,
            known_requirements=known_requirements,
            known_refs=known_refs,
            ambiguous_refs=ambiguous_refs,
        )
        if item is None:
            rejections.append(
                {"index": position, "code": code or REJECTION_MALFORMED_EVIDENCE}
            )
            continue
        signature = _signature(item)
        if signature in seen:
            rejections.append(
                {"index": position, "code": REJECTION_DUPLICATE_EVIDENCE}
            )
            continue
        seen.add(signature)
        accepted.append(item)

    accepted.sort(key=_canonical_key)
    for position, item in enumerate(accepted, start=1):
        item["intake_id"] = f"EI{position}"

    if not raw_items:
        package_status = STATUS_ACCEPTED
    elif not accepted:
        package_status = STATUS_REJECTED
    elif rejections:
        package_status = STATUS_PARTIAL
    else:
        package_status = STATUS_ACCEPTED

    bundle_items = [
        {
            "hypothesis_ref": item["hypothesis_ref"],
            "requirement_kind": item["requirement_kind"],
            "effect": item["effect"],
            "source": item["bundle_source"],
            "observations": [dict(entry) for entry in item["observations"]],
            "derived_signals": [
                dict(entry) for entry in item["derived_signals"]
            ],
            "invalidates_refs": list(item["invalidates_refs"]),
        }
        for item in accepted
    ]
    return {
        "package_status": package_status,
        "accepted_items": accepted,
        "rejections": rejections[:MAX_REJECTIONS],
        "package_rejections": [],
        "bundle": {"items": bundle_items},
    }


# ---------------------------------------------------------------------------
# Re-evaluation (R72 readiness authority + R73 feedback authority)
# ---------------------------------------------------------------------------


def _project_updated_acquisition_plan(
    acquisition_plan: object, feedback: Mapping
) -> dict:
    """Apply R73's authoritative deltas to the R71 plan status projection."""

    block = _block(acquisition_plan)
    raw_plans = block.get("plans")
    if raw_plans is None:
        raw_plans = acquisition_plan
    plans = {
        _text(plan.get("plan_id")): plan
        for plan in _mapping_items(raw_plans)
        if plan.get("plan_id")
    }
    delta_by_plan: dict[str, list[Mapping]] = {}
    for iteration in _mapping_items(feedback.get("iterations")):
        plan_ref = _text(iteration.get("plan_ref"))
        for delta in _mapping_items(iteration.get("evidence_delta")):
            delta_by_plan.setdefault(plan_ref, []).append(delta)

    updated_plans: list[dict] = []
    for plan_ref, plan in plans.items():
        copy = {key: value for key, value in plan.items() if key != "required_evidence"}
        entries: list[dict] = []
        for entry in _mapping_items(plan.get("required_evidence")):
            entries.append(dict(entry))
        for delta in delta_by_plan.get(plan_ref, []):
            kind = _upper(delta.get("requirement_kind"))
            to_status = _upper(delta.get("to_status"))
            if to_status not in (STATUS_AVAILABLE, STATUS_MISSING):
                continue
            for entry in entries:
                if _upper(entry.get("requirement_kind")) == kind:
                    entry["status"] = to_status
        copy["required_evidence"] = entries
        updated_plans.append(copy)
    updated = dict(block)
    updated["plans"] = updated_plans
    return updated


def _readiness_records(result: Mapping) -> list[Mapping]:
    return _mapping_items(result.get("records"))


def _transitions(
    before_records: list[Mapping], after_records: list[Mapping]
) -> list[dict]:
    before_by_ref = {
        _text(record.get("plan_ref")): record for record in before_records
    }
    transitions: list[dict] = []
    for record in after_records:
        plan_ref = _text(record.get("plan_ref"))
        previous = before_by_ref.get(plan_ref)
        if previous is None:
            continue
        before_sufficiency = _upper(previous.get("sufficiency_state"))
        before_decision = _upper(previous.get("decision_state"))
        after_sufficiency = _upper(record.get("sufficiency_state"))
        after_decision = _upper(record.get("decision_state"))
        if (
            before_sufficiency == after_sufficiency
            and before_decision == after_decision
        ):
            continue
        transitions.append(
            {
                "plan_ref": plan_ref,
                "before_sufficiency": before_sufficiency,
                "after_sufficiency": after_sufficiency,
                "before_decision": before_decision,
                "after_decision": after_decision,
            }
        )
    return transitions


def intake_and_reevaluate(
    package: object = None,
    *,
    hypotheses: object = None,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
) -> dict:
    """Validate external evidence, then re-evaluate readiness and feedback.

    ``reevaluation.acquisition_after`` exposes the projected R71 plan with the
    authoritative R73 delta applied, so successive evidence rounds can chain
    without re-deriving anything (prior accepted evidence is retained).
    """

    intake = normalize_evidence_package(
        package,
        hypotheses=hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )

    feedback = evaluate_research_iteration(
        hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
        new_evidence=intake["bundle"],
    )

    before = _block(readiness_plan)
    if not _readiness_records(before):
        before = plan_decision_readiness(action_plan, acquisition_plan)
    updated_plan = _project_updated_acquisition_plan(
        acquisition_plan, feedback
    )
    after = plan_decision_readiness(action_plan, updated_plan)
    transitions = _transitions(
        _readiness_records(before), _readiness_records(after)
    )

    before_summary = _block(before.get("summary"))
    after_summary = _block(after.get("summary"))
    feedback_summary = _block(feedback.get("summary"))
    return {
        "rule_version": RULE_VERSION,
        "package_version": PACKAGE_VERSION,
        "package_status": intake["package_status"],
        "accepted_external_evidence": len(intake["accepted_items"]),
        "accepted_items": intake["accepted_items"],
        "rejections": intake["rejections"],
        "package_rejections": intake["package_rejections"],
        "bundle": intake["bundle"],
        "reevaluation": {
            "readiness_before_summary": before_summary,
            "readiness_after": after,
            "acquisition_after": updated_plan,
            "transitions": transitions,
            "feedback": feedback,
        },
        "summary": {
            "rule_version": RULE_VERSION,
            "package_status": intake["package_status"],
            "accepted_external_evidence": len(intake["accepted_items"]),
            "rejected_items": len(intake["rejections"]),
            "transitions": len(transitions),
            "top_readiness_before": _upper(
                before_summary.get("top_sufficiency_state")
            ),
            "top_readiness_after": _upper(
                after_summary.get("top_sufficiency_state")
            ),
            "top_feedback_state": _upper(
                feedback_summary.get("top_feedback_state")
            ),
            "top_current_state": _upper(
                feedback_summary.get("top_current_state")
            ),
            "top_next_iteration": _upper(
                feedback_summary.get("top_next_iteration")
            ),
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
        },
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "PACKAGE_VERSION",
    "SOURCE_ACTION_RULE_VERSION",
    "SOURCE_ACQUISITION_RULE_VERSION",
    "SOURCE_READINESS_RULE_VERSION",
    "SOURCE_FEEDBACK_RULE_VERSION",
    "MAX_PACKAGE_ITEMS",
    "MAX_OBSERVATIONS",
    "MAX_SIGNALS",
    "MAX_INVALIDATES_REFS",
    "MAX_REF_CHARS",
    "MAX_FACT_CHARS",
    "MAX_SIGNAL_CHARS",
    "MAX_REJECTIONS",
    "STATUS_NOT_PROVIDED",
    "STATUS_ACCEPTED",
    "STATUS_PARTIAL",
    "STATUS_REJECTED",
    "PACKAGE_STATUSES",
    "INTAKE_SOURCES",
    "INTAKE_SOURCE_TO_BUNDLE_SOURCE",
    "INTAKE_REJECTION_CODES",
    "REJECTION_UNSUPPORTED_PACKAGE_VERSION",
    "REJECTION_PACKAGE_TOO_LARGE",
    "REJECTION_INVALID_EVIDENCE_REF",
    "REJECTION_DUPLICATE_EVIDENCE",
    "REJECTION_EXECUTION_INSTRUCTION",
    "REJECTION_MALFORMED_EVIDENCE",
    "REJECTION_UNSUPPORTED_EFFECT",
    "REJECTION_UNKNOWN_HYPOTHESIS",
    "REJECTION_UNKNOWN_REQUIREMENT",
    "REJECTION_UNKNOWN_INVALIDATED_REF",
    "REJECTION_AMBIGUOUS_EVIDENCE",
    "REJECTION_SENSITIVE_EVIDENCE",
    "REJECTION_INVALID_SOURCE",
    "EvidenceIntakeError",
    "normalize_evidence_package",
    "intake_and_reevaluate",
]
