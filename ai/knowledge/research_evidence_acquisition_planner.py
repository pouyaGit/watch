"""Stage R71 deterministic research evidence acquisition planner (pure engine).

Consumes the validated R70 outcome/action plan and derives, for every ranked
research action, a bounded evidence acquisition plan:

    evidence -> hypothesis -> evidence gap -> R70 action -> acquisition plan

It answers the human-researcher question:

    "What evidence should the researcher acquire next to resolve this
     hypothesis, what evidence already exists, what would the acquired
     evidence change, what is the safest acquisition order, and when do we
     stop?"

This is a **planning signal only, and it is plan-only**. It never executes an
acquisition, never contacts a target, never scans, never crawls, never sends a
request, never calls an LLM, never touches Mongo and never renders a
probability, exploitability, severity or CVSS judgement. It contains no
payloads, exploit strings, bypass techniques, scanner commands or request
bodies. Acquisition steps describe *what stored evidence to review or what
evidence to obtain in an authorized context*, never *how to attack*.

Composition decision (existing R31 planners inspected first):

- ``ai/knowledge/hunt_action_planner.py`` (R31.12),
  ``ai/knowledge/evidence_acquisition_planner.py`` (R31.13) and
  ``ai/knowledge/evidence_prioritization_planner.py`` (R31.14) plan evidence
  acquisition for Asset<->CVE hunt candidates and are coupled to the
  R31.10/R31.11/R31.12 projection shape and gap vocabulary
  (``GAP_VERSION``, ``GAP_HTTP``, ...). They cannot consume a validated LLM
  research hypothesis or an R70 action without inventing a foreign mapping.
- R71 therefore does **not** fork or duplicate that framework. It composes
  with it: the shared acquisition-method vocabulary is imported from R31.13
  (``COMPONENT_IDENTITY_LOOKUP`` for component mapping, ``HTTP_BEHAVIOR_REVIEW``
  for endpoint behaviour) and extended with the research-category methods the
  R31 chain does not have; the closed-vocabulary, bounded-text, redaction,
  deterministic-ordering and plan-only conventions are mirrored exactly; the
  category mapping, gap vocabulary and safety block are imported from the R70
  action planner so R70 remains the single source of truth for the gap.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no persistence, no execution.
- No recomputation: the R70 action's ``action_id``, ``gap_id``, ``category``,
  ``hypothesis_refs``, ``evidence_states`` and safety context are consumed
  read-only. The planner never re-derives an R70 gap, ranking or action.
- Existing evidence first: every required-evidence item is checked against the
  evidence the R70 outcome already carries (canonical observations and derived
  Watch signals). An item with matching evidence is marked ``AVAILABLE`` and
  is never requested again; only ``MISSING`` items produce acquisition steps.
  The planner never claims evidence exists unless a canonical reference is
  actually present.
- Deterministic and explainable: requirement ordering is documented bounded
  factor points (information gain, risk, reuse, prerequisite) and repeated
  runs are byte-identical. No probabilities, randomness or timestamps.
- Closed vocabularies: sources, requirement kinds, statuses, decision-impact
  states, methods and safety flags are closed sets; no free-form generated
  procedures exist.
- Additive and read-only: inputs are never mutated; every result is a new dict
  with rule version ``r71-1``.
- Every plan forces ``confirmation_state = NOT_CONFIRMED`` and carries an
  explicit safe stopping condition; decision impact is a prediction of what
  evidence would change, never a claim that anything happened.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ai.knowledge.evidence_acquisition_planner import (
    COMPONENT_IDENTITY_LOOKUP,
    HTTP_BEHAVIOR_REVIEW,
)
from ai.knowledge.research_outcome_planner import (
    CATEGORY_ORDER,
    RULE_VERSION as SOURCE_ACTION_RULE_VERSION,
    SAFETY_BLOCK,
    gap_id_for,
)
from ai.knowledge.security_skills.library import SIGNAL_SKILLS, skill_by_id

RULE_VERSION = "r71-1"

MAX_PLANS = 8
MAX_HYPOTHESES_PER_PLAN = 8
MAX_REQUIRED_EVIDENCE = 6
MAX_EVIDENCE_PER_REQUIREMENT = 2
MAX_AVAILABLE_EVIDENCE = 6
MAX_MISSING_EVIDENCE = 6
MAX_HYPOTHESIS_MISSING_EVIDENCE = 6
MAX_SOURCES = 6
MAX_STEPS = 6
MAX_TEXT_CHARS = 320
MAX_SKILL_EVIDENCE = 3

# ---------------------------------------------------------------------------
# Closed acquisition-source vocabulary (bounded source types)
# ---------------------------------------------------------------------------

SOURCE_EXISTING_SNAPSHOT = "EXISTING_SNAPSHOT"
SOURCE_EXISTING_EVIDENCE = "EXISTING_EVIDENCE"
SOURCE_AUTHORIZED_TEST_CONTEXT = "AUTHORIZED_TEST_CONTEXT"
SOURCE_RESPONSE_OBSERVATION = "RESPONSE_OBSERVATION"
SOURCE_DOCUMENTATION = "DOCUMENTATION"
SOURCE_COMPONENT_METADATA = "COMPONENT_METADATA"
SOURCE_VERSION_MAPPING = "VERSION_MAPPING"
SOURCE_HUMAN_REVIEW = "HUMAN_REVIEW"

ACQUISITION_SOURCES: tuple[str, ...] = (
    SOURCE_EXISTING_SNAPSHOT,
    SOURCE_EXISTING_EVIDENCE,
    SOURCE_AUTHORIZED_TEST_CONTEXT,
    SOURCE_RESPONSE_OBSERVATION,
    SOURCE_DOCUMENTATION,
    SOURCE_COMPONENT_METADATA,
    SOURCE_VERSION_MAPPING,
    SOURCE_HUMAN_REVIEW,
)

#: Risk of the acquisition activity itself (not of the hypothesis). Bounded
#: qualitative ranks; reviewed stored evidence is the lowest-risk source, an
#: authorized human-run comparison context is the only medium-risk source.
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

RISK_RANK: dict[str, int] = {
    RISK_LOW: 0,
    RISK_MEDIUM: 1,
    RISK_HIGH: 2,
}

SOURCE_RISK: dict[str, str] = {
    SOURCE_EXISTING_EVIDENCE: RISK_LOW,
    SOURCE_EXISTING_SNAPSHOT: RISK_LOW,
    SOURCE_DOCUMENTATION: RISK_LOW,
    SOURCE_COMPONENT_METADATA: RISK_LOW,
    SOURCE_VERSION_MAPPING: RISK_LOW,
    SOURCE_RESPONSE_OBSERVATION: RISK_LOW,
    SOURCE_HUMAN_REVIEW: RISK_LOW,
    SOURCE_AUTHORIZED_TEST_CONTEXT: RISK_MEDIUM,
}

#: Stable within-risk ordering (review of already-collected material first,
#: then structured metadata, then generic documentation, human escalation
#: last).
SOURCE_ORDER: dict[str, int] = {
    SOURCE_EXISTING_EVIDENCE: 0,
    SOURCE_EXISTING_SNAPSHOT: 1,
    SOURCE_RESPONSE_OBSERVATION: 2,
    SOURCE_COMPONENT_METADATA: 3,
    SOURCE_VERSION_MAPPING: 4,
    SOURCE_DOCUMENTATION: 5,
    SOURCE_AUTHORIZED_TEST_CONTEXT: 6,
    SOURCE_HUMAN_REVIEW: 7,
}

#: Human review is the bounded escalation fallback, not the highest-gain
#: acquisition; it is ordered after narrower methods regardless of the
#: requirement's own information-gain tier.
HUMAN_REVIEW_INFORMATION_GAIN = 5

SOURCE_OPERATIONS: dict[str, str] = {
    SOURCE_EXISTING_EVIDENCE: (
        "verify against the hypothesis's selected evidence whether this "
        "requirement is already satisfied and reuse it; never re-acquire "
        "evidence that is already available"
    ),
    SOURCE_EXISTING_SNAPSHOT: (
        "review the bounded read-only snapshot records for stored evidence "
        "that satisfies this requirement; no new request is made"
    ),
    SOURCE_RESPONSE_OBSERVATION: (
        "review stored response, redirect, status or error observations for "
        "evidence that satisfies this requirement; no new request is made"
    ),
    SOURCE_AUTHORIZED_TEST_CONTEXT: (
        "identify whether an authorized, program-scoped comparison context "
        "already exists in which a human may obtain this evidence; this plan "
        "does not perform it"
    ),
    SOURCE_DOCUMENTATION: (
        "consult offline documentation or component references for this "
        "requirement"
    ),
    SOURCE_COMPONENT_METADATA: (
        "correlate stored technology and component metadata for this "
        "requirement"
    ),
    SOURCE_VERSION_MAPPING: (
        "correlate the observed version with offline version-to-component "
        "mappings for this requirement"
    ),
    SOURCE_HUMAN_REVIEW: (
        "escalate this requirement to human review to decide whether the "
        "evidence can be obtained safely and within authorization"
    ),
}

# ---------------------------------------------------------------------------
# Closed requirement-status vocabulary (existing-evidence-first distinction)
# ---------------------------------------------------------------------------

STATUS_AVAILABLE = "AVAILABLE"
STATUS_MISSING = "MISSING"
REQUIREMENT_STATUSES: tuple[str, ...] = (STATUS_AVAILABLE, STATUS_MISSING)

# ---------------------------------------------------------------------------
# Closed decision-impact vocabulary
# ---------------------------------------------------------------------------

IMPACT_SUPPORTS = "SUPPORTS"
IMPACT_WEAKENS = "WEAKENS"
IMPACT_RESOLVES = "RESOLVES"
IMPACT_REMAINS_UNRESOLVED = "REMAINS_UNRESOLVED"

DECISION_IMPACT_STATES: tuple[str, ...] = (
    IMPACT_SUPPORTS,
    IMPACT_WEAKENS,
    IMPACT_RESOLVES,
    IMPACT_REMAINS_UNRESOLVED,
)

#: Prediction only: what the acquired evidence would change. No result has
#: occurred and nothing is confirmed by this mapping.
DECISION_IMPACT: dict[str, str] = {
    "if_confirming_evidence_obtained": IMPACT_SUPPORTS,
    "if_contradicting_evidence_obtained": IMPACT_WEAKENS,
    "if_required_evidence_complete": IMPACT_RESOLVES,
    "if_evidence_cannot_be_acquired": IMPACT_REMAINS_UNRESOLVED,
}

# ---------------------------------------------------------------------------
# Closed acquisition-method vocabulary (R31.13 methods reused where shared)
# ---------------------------------------------------------------------------

AUTHORIZATION_BEHAVIOR_REVIEW = "AUTHORIZATION_BEHAVIOR_REVIEW"
FETCH_BEHAVIOR_REVIEW = "FETCH_BEHAVIOR_REVIEW"
RESPONSE_CONTEXT_REVIEW = "RESPONSE_CONTEXT_REVIEW"
QUERY_BEHAVIOR_REVIEW = "QUERY_BEHAVIOR_REVIEW"
TOKEN_ARTIFACT_REVIEW = "TOKEN_ARTIFACT_REVIEW"
OAUTH_ARTIFACT_REVIEW = "OAUTH_ARTIFACT_REVIEW"
ADDITIONAL_EVIDENCE_REVIEW = "ADDITIONAL_EVIDENCE_REVIEW"

ACQUISITION_METHODS: tuple[str, ...] = (
    AUTHORIZATION_BEHAVIOR_REVIEW,
    FETCH_BEHAVIOR_REVIEW,
    RESPONSE_CONTEXT_REVIEW,
    QUERY_BEHAVIOR_REVIEW,
    TOKEN_ARTIFACT_REVIEW,
    OAUTH_ARTIFACT_REVIEW,
    COMPONENT_IDENTITY_LOOKUP,
    HTTP_BEHAVIOR_REVIEW,
    ADDITIONAL_EVIDENCE_REVIEW,
)

# ---------------------------------------------------------------------------
# Bounded reference-kind sets
# ---------------------------------------------------------------------------

STRUCTURAL_REF_KINDS: tuple[str, ...] = (
    "program",
    "snapshot",
    "path",
    "parameter",
    "technology",
    "version",
    "record",
)

CORROBORATING_REF_KINDS: tuple[str, ...] = (
    "response",
    "authorization",
    "redirect",
    "session",
    "token",
    "algorithm",
    "header",
    "error",
    "status",
)

_OBJECT_REFERENCE_RE = re.compile(
    r"\{[a-z0-9_-]+\}|:[a-z]+id(?=/|$)|/\d{2,}(?:/|$)", re.IGNORECASE
)

_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

CATEGORY_ALIASES: dict[str, str] = {
    "BOLA": "IDOR",
    "IDOR_BOLA": "IDOR",
    "IDOR/BOLA": "IDOR",
}


class ResearchEvidenceAcquisitionError(ValueError):
    """Deterministic, secret-free R71 planning failure."""


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _safe_text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    """Bound and redact credential-like text before it enters a plan."""

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


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_strings(value: object, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _safe_text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _coerce_count(value: object, default: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    if value < 0:
        return default
    return min(value, maximum)


def _requirement(
    kind: str,
    description: str,
    *,
    ref_kinds: Sequence[str] = (),
    watch_signals: Sequence[str] = (),
    value_re: re.Pattern | None = None,
    information_gain: int = 10,
) -> dict:
    return {
        "kind": kind,
        "description": description,
        "ref_kinds": tuple(ref_kinds),
        "watch_signals": tuple(watch_signals),
        "value_re": value_re,
        "information_gain": information_gain,
    }


# ---------------------------------------------------------------------------
# Category/gap -> acquisition specification (closed, deterministic)
# ---------------------------------------------------------------------------

_AUTHORIZED_ONLY = (SOURCE_AUTHORIZED_TEST_CONTEXT,)
_HUMAN_ONLY: tuple[str, ...] = ()

_GAP_SPECS: dict[str, dict] = {
    "OBJECT_AUTHORIZATION": {
        "category": "IDOR",
        "skill_id": "idor-bola",
        "acquisition_method": AUTHORIZATION_BEHAVIOR_REVIEW,
        "evidence_gap": (
            "object identity plus authorization/ownership behavior evidence"
        ),
        "acquisition_goal": (
            "Acquire stored object-ownership and authorization-outcome "
            "evidence to determine whether the referenced object is "
            "authorization-scoped per authorized principal."
        ),
        "expected_result": (
            "Stored records either associate the same object reference with "
            "different authorization outcomes across authorized principals or "
            "show ownership binding; otherwise the object reference stays "
            "structural and the hypothesis stays NOT_CONFIRMED."
        ),
        "stopping_condition": (
            "If neither stored authorization/ownership evidence nor an "
            "authorized comparison context can be identified, stop: keep the "
            "hypothesis NOT_CONFIRMED, record the gap, and do not test any "
            "live principal or object."
        ),
        "requirements": (
            _requirement(
                "OBJECT_REFERENCE",
                "an observed object-reference path (for example a route "
                "segment placeholder)",
                ref_kinds=("path",),
                value_re=_OBJECT_REFERENCE_RE,
                information_gain=15,
            ),
            _requirement(
                "AUTHORIZATION_OUTCOME",
                "stored authorization/denial outcomes for the same object "
                "reference across authorized principals",
                ref_kinds=("authorization", "response", "status", "error"),
                information_gain=20,
            ),
            _requirement(
                "OWNERSHIP_BINDING",
                "stored ownership/principal binding evidence for the "
                "referenced object",
                ref_kinds=("authorization", "response", "session"),
                information_gain=20,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch object-reference signal for this category",
                watch_signals=("IDOR",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "OBJECT_REFERENCE": (SOURCE_EXISTING_SNAPSHOT,),
            "AUTHORIZATION_OUTCOME": (
                SOURCE_RESPONSE_OBSERVATION,
            )
            + _AUTHORIZED_ONLY,
            "OWNERSHIP_BINDING": (SOURCE_RESPONSE_OBSERVATION,),
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "SERVER_SIDE_FETCH": {
        "category": "SSRF",
        "skill_id": "ssrf",
        "acquisition_method": FETCH_BEHAVIOR_REVIEW,
        "evidence_gap": (
            "server-side fetch behavior plus controlled-destination evidence"
        ),
        "acquisition_goal": (
            "Acquire stored server-side fetch behavior and destination-control "
            "evidence to determine whether the observed input influences "
            "server-side request behavior."
        ),
        "expected_result": (
            "Stored records either show a server-side fetch, callback, "
            "redirect or internal-network indicator tied to the input or show "
            "destination/allowlist handling; otherwise reachability and "
            "influence remain indistinguishable."
        ),
        "stopping_condition": (
            "If no stored fetch or destination-control evidence exists and no "
            "authorized context is available, stop: keep the hypothesis "
            "NOT_CONFIRMED and record the gap."
        ),
        "requirements": (
            _requirement(
                "INPUT_SURFACE",
                "an observed URL/host-shaped parameter or path that may "
                "influence a server-side fetch",
                ref_kinds=("parameter", "path"),
                information_gain=10,
            ),
            _requirement(
                "FETCH_BEHAVIOR",
                "stored server-side fetch/callback behavior evidence tied to "
                "the input",
                ref_kinds=("response", "redirect", "error"),
                information_gain=20,
            ),
            _requirement(
                "DESTINATION_CONTROL",
                "stored destination or allowlist handling evidence for the "
                "input",
                ref_kinds=("response", "redirect", "error"),
                information_gain=20,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch server-side-fetch signal for this category",
                watch_signals=("SSRF",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "INPUT_SURFACE": (SOURCE_EXISTING_SNAPSHOT,),
            "FETCH_BEHAVIOR": (SOURCE_RESPONSE_OBSERVATION,),
            "DESTINATION_CONTROL": (
                SOURCE_RESPONSE_OBSERVATION,
            )
            + _AUTHORIZED_ONLY,
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "REFLECTION_CONTEXT": {
        "category": "XSS",
        "skill_id": "xss",
        "acquisition_method": RESPONSE_CONTEXT_REVIEW,
        "evidence_gap": "reflection plus execution-context evidence",
        "acquisition_goal": (
            "Acquire stored reflection, context and encoding evidence to "
            "determine whether the observed input reaches an executable "
            "response context."
        ),
        "expected_result": (
            "Stored response evidence either shows the input reflected into a "
            "specific context together with the encoding applied or shows it "
            "is not reflected; without it the input remains only an input."
        ),
        "stopping_condition": (
            "If no stored reflection/context evidence exists and no "
            "authorized context is available, stop: keep the hypothesis "
            "NOT_CONFIRMED and record the gap."
        ),
        "requirements": (
            _requirement(
                "INPUT_SURFACE",
                "an observed parameter or path input that may reach a "
                "response",
                ref_kinds=("parameter", "path"),
                information_gain=10,
            ),
            _requirement(
                "RESPONSE_CONTEXT",
                "stored response evidence showing whether the input is "
                "reflected and in which context",
                ref_kinds=("response", "header"),
                information_gain=20,
            ),
            _requirement(
                "ENCODING",
                "stored evidence of the encoding/escaping applied to the "
                "reflected value",
                ref_kinds=("response", "header"),
                information_gain=20,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch reflection-context signal for this category",
                watch_signals=("XSS",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "INPUT_SURFACE": (SOURCE_EXISTING_SNAPSHOT,),
            "RESPONSE_CONTEXT": (SOURCE_RESPONSE_OBSERVATION,),
            "ENCODING": (
                SOURCE_RESPONSE_OBSERVATION,
                SOURCE_DOCUMENTATION,
            ),
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "QUERY_BEHAVIOR": {
        "category": "SQLI",
        "skill_id": "sqli",
        "acquisition_method": QUERY_BEHAVIOR_REVIEW,
        "evidence_gap": (
            "input influence plus database/query behavior evidence"
        ),
        "acquisition_goal": (
            "Acquire stored database-behavior and reproducibility evidence to "
            "determine whether the observed input influences database query "
            "behavior."
        ),
        "expected_result": (
            "Stored records either show database errors or response "
            "differences tied to the input, reproducibly, or show uniform "
            "behavior; without it parameter presence is not query influence."
        ),
        "stopping_condition": (
            "If no stored database-behavior evidence exists and no authorized "
            "context is available, stop: keep the hypothesis NOT_CONFIRMED "
            "and record the gap."
        ),
        "requirements": (
            _requirement(
                "INPUT_SURFACE",
                "an observed parameter or path input that may reach a "
                "database query",
                ref_kinds=("parameter", "path"),
                information_gain=10,
            ),
            _requirement(
                "QUERY_RESPONSE",
                "stored database error or response-difference evidence tied "
                "to the input",
                ref_kinds=("response", "error", "status"),
                information_gain=20,
            ),
            _requirement(
                "REPRODUCIBILITY",
                "stored evidence that the observed behavior repeats in the "
                "same conditions",
                ref_kinds=("response", "status", "error"),
                information_gain=20,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch database-behavior signal for this category",
                watch_signals=("SQLI",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "INPUT_SURFACE": (SOURCE_EXISTING_SNAPSHOT,),
            "QUERY_RESPONSE": (SOURCE_RESPONSE_OBSERVATION,),
            "REPRODUCIBILITY": (
                SOURCE_RESPONSE_OBSERVATION,
            )
            + _AUTHORIZED_ONLY,
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "TOKEN_VALIDATION": {
        "category": "JWT",
        "skill_id": "jwt",
        "acquisition_method": TOKEN_ARTIFACT_REVIEW,
        "evidence_gap": (
            "actual JWT structure/token evidence plus validation "
            "characteristics"
        ),
        "acquisition_goal": (
            "Acquire an observed token artifact and stored validation "
            "evidence to determine whether real JWT artifacts with "
            "validation-relevant characteristics exist."
        ),
        "expected_result": (
            "Stored records either show token structure, claims and algorithm "
            "or acceptance/rejection behavior, or show no token artifact; "
            "without one the surface is not established as JWT-related."
        ),
        "stopping_condition": (
            "If no token artifact or validation evidence exists in stored "
            "records and no authorized context is available, stop: keep the "
            "hypothesis NOT_CONFIRMED and record the gap."
        ),
        "requirements": (
            _requirement(
                "TOKEN_ARTIFACT",
                "an observed JWT/token artifact with structure, claim or "
                "algorithm evidence",
                ref_kinds=("jwt", "token", "algorithm", "header", "cookie"),
                information_gain=20,
            ),
            _requirement(
                "VALIDATION_ARTIFACT",
                "stored evidence of how the token is accepted or rejected",
                ref_kinds=("response", "status", "error", "authorization"),
                information_gain=20,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch token-validation signal for this category",
                watch_signals=("JWT",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "TOKEN_ARTIFACT": (
                SOURCE_EXISTING_SNAPSHOT,
                SOURCE_RESPONSE_OBSERVATION,
            ),
            "VALIDATION_ARTIFACT": (
                SOURCE_RESPONSE_OBSERVATION,
                SOURCE_DOCUMENTATION,
            ),
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "OAUTH_FLOW_ARTIFACTS": {
        "category": "OAUTH",
        "skill_id": "oauth",
        "acquisition_method": OAUTH_ARTIFACT_REVIEW,
        "evidence_gap": (
            "actual OAuth/OIDC flow artifact plus redirect/token/state "
            "evidence"
        ),
        "acquisition_goal": (
            "Acquire observed OAuth/OIDC flow artifacts and stored redirect/"
            "token/state handling evidence to determine whether a real flow "
            "is present and how it is validated."
        ),
        "expected_result": (
            "Stored records either show authorize/token/redirect_uri/state/"
            "nonce/assertion artifacts and their handling, or show none; "
            "without artifacts the surface is not an established flow."
        ),
        "stopping_condition": (
            "If no OAuth/OIDC artifact or validation evidence exists in "
            "stored records and no authorized context is available, stop: "
            "keep the hypothesis NOT_CONFIRMED and record the gap."
        ),
        "requirements": (
            _requirement(
                "FLOW_ARTIFACT",
                "an observed OAuth/OIDC flow artifact (authorize, token, "
                "redirect_uri, state, nonce or assertion) with surrounding "
                "flow evidence, not a parameter name alone",
                ref_kinds=(
                    "response",
                    "redirect",
                    "token",
                    "header",
                    "session",
                ),
                information_gain=20,
            ),
            _requirement(
                "REDIRECT_HANDLING",
                "stored redirect_uri/state/nonce validation evidence",
                ref_kinds=("response", "redirect", "error"),
                information_gain=20,
            ),
            _requirement(
                "VALIDATION_ARTIFACT",
                "stored token or assertion acceptance/rejection evidence",
                ref_kinds=("response", "status", "error", "authorization"),
                information_gain=20,
            ),
        ),
        "source_targets": {
            "FLOW_ARTIFACT": (
                SOURCE_EXISTING_SNAPSHOT,
                SOURCE_RESPONSE_OBSERVATION,
            ),
            "REDIRECT_HANDLING": (
                SOURCE_RESPONSE_OBSERVATION,
                SOURCE_DOCUMENTATION,
            ),
            "VALIDATION_ARTIFACT": (
                SOURCE_RESPONSE_OBSERVATION,
                SOURCE_DOCUMENTATION,
            ),
        },
    },
    "COMPONENT_MAPPING": {
        "category": "CVE_RESEARCH",
        "skill_id": "cve-research",
        "acquisition_method": COMPONENT_IDENTITY_LOOKUP,
        "evidence_gap": (
            "technology plus exact version plus component-mapping plus "
            "applicability evidence"
        ),
        "acquisition_goal": (
            "Acquire an observed technology/version association and offline "
            "component metadata to determine the exact component-version "
            "mapping before any CVE applicability review."
        ),
        "expected_result": (
            "Stored evidence either binds the observed version to a specific "
            "component/product, enabling offline CVE correlation, or leaves "
            "the version unassociated and therefore not CVE-researchable."
        ),
        "stopping_condition": (
            "If the component-version association cannot be established from "
            "stored evidence or offline metadata, stop: keep the version "
            "observation unmapped and the hypothesis NOT_CONFIRMED."
        ),
        "requirements": (
            _requirement(
                "TECHNOLOGY_IDENTITY",
                "an observed technology identity",
                ref_kinds=("technology",),
                information_gain=15,
            ),
            _requirement(
                "VERSION_IDENTITY",
                "an observed version string",
                ref_kinds=("version",),
                information_gain=15,
            ),
            _requirement(
                "COMPONENT_BINDING",
                "stored evidence binding the version to a specific "
                "component/product",
                ref_kinds=("record",),
                information_gain=15,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch CVE-research signal for this category",
                watch_signals=("CVE_RESEARCH",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "TECHNOLOGY_IDENTITY": (SOURCE_EXISTING_SNAPSHOT,),
            "VERSION_IDENTITY": (SOURCE_EXISTING_SNAPSHOT,),
            "COMPONENT_BINDING": (
                SOURCE_COMPONENT_METADATA,
                SOURCE_VERSION_MAPPING,
                SOURCE_DOCUMENTATION,
            ),
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "ENDPOINT_BEHAVIOR": {
        "category": "RECON",
        "skill_id": "api-security",
        "acquisition_method": HTTP_BEHAVIOR_REVIEW,
        "evidence_gap": (
            "endpoint purpose, behavior, authentication or response evidence"
        ),
        "acquisition_goal": (
            "Acquire stored endpoint purpose, method/authentication and "
            "response-behavior evidence to determine what the observed "
            "surface actually does."
        ),
        "expected_result": (
            "Stored records either show the method, authentication "
            "requirement and response behavior of the path, or leave it as a "
            "structural path with no established purpose."
        ),
        "stopping_condition": (
            "If no method/authentication/response evidence exists in stored "
            "records and no authorized context is available, stop: keep the "
            "observation structural and the hypothesis NOT_CONFIRMED."
        ),
        "requirements": (
            _requirement(
                "ENDPOINT_PURPOSE",
                "an observed path/endpoint identity",
                ref_kinds=("path", "url", "endpoint"),
                information_gain=10,
            ),
            _requirement(
                "METHOD_AUTH",
                "stored evidence of the HTTP method and authentication "
                "requirement for the endpoint",
                ref_kinds=("record", "response", "authorization", "status"),
                information_gain=15,
            ),
            _requirement(
                "RESPONSE_BEHAVIOR",
                "stored response/status/error evidence describing endpoint "
                "behavior",
                ref_kinds=("response", "status", "error", "header"),
                information_gain=20,
            ),
            _requirement(
                "WATCH_SIGNAL",
                "a Watch endpoint-behavior signal for this category",
                watch_signals=("RECON",),
                information_gain=15,
            ),
        ),
        "source_targets": {
            "ENDPOINT_PURPOSE": (
                SOURCE_EXISTING_SNAPSHOT,
                SOURCE_DOCUMENTATION,
            ),
            "METHOD_AUTH": (
                SOURCE_RESPONSE_OBSERVATION,
            )
            + _AUTHORIZED_ONLY
            + (SOURCE_DOCUMENTATION,),
            "RESPONSE_BEHAVIOR": (SOURCE_RESPONSE_OBSERVATION,),
            "WATCH_SIGNAL": _HUMAN_ONLY,
        },
    },
    "ADDITIONAL_EVIDENCE": {
        "category": "",
        "skill_id": "",
        "acquisition_method": ADDITIONAL_EVIDENCE_REVIEW,
        "evidence_gap": "additional evidence tied to the stated uncertainty",
        "acquisition_goal": (
            "Acquire the stored evidence that directly addresses the "
            "hypothesis's stated uncertainty, starting with what is already "
            "available."
        ),
        "expected_result": (
            "Existing or stored evidence either directly addresses the "
            "stated uncertainty or leaves it unresolved."
        ),
        "stopping_condition": (
            "If no relevant evidence exists in stored records and human "
            "review cannot identify an authorized source, stop: keep the "
            "hypothesis NOT_CONFIRMED and record the gap."
        ),
        "requirements": (
            _requirement(
                "SUPPORTING_OBSERVATION",
                "any existing structural observation tied to the stated "
                "uncertainty",
                ref_kinds=STRUCTURAL_REF_KINDS,
                information_gain=10,
            ),
            _requirement(
                "CORROBORATING_OBSERVATION",
                "any existing non-structural behavior observation tied to "
                "the stated uncertainty",
                ref_kinds=CORROBORATING_REF_KINDS,
                information_gain=20,
            ),
        ),
        "source_targets": {
            "SUPPORTING_OBSERVATION": (SOURCE_EXISTING_SNAPSHOT,),
            "CORROBORATING_OBSERVATION": (SOURCE_RESPONSE_OBSERVATION,),
        },
    },
}


def _normalized_gap_id(action: Mapping) -> str:
    gap_id = _upper(action.get("gap_id"))
    if gap_id in _GAP_SPECS:
        return gap_id
    category = _normalized_category(action.get("category"))
    mapped = gap_id_for(category)
    return mapped if mapped in _GAP_SPECS else "ADDITIONAL_EVIDENCE"


def _normalized_category(value: object) -> str:
    category = _upper(value)
    return CATEGORY_ALIASES.get(category, category)


def _category_rank(category: str) -> int:
    return (
        CATEGORY_ORDER.index(category)
        if category in CATEGORY_ORDER
        else len(CATEGORY_ORDER)
    )


def _ref_kind_and_value(ref: str) -> tuple[str, str]:
    kind, _, value = _text(ref).partition(":")
    return kind.lower(), value


def _collect_outcome_evidence(outcome: Mapping) -> tuple[list[dict], list[dict]]:
    evidence = outcome.get("current_evidence")
    if not isinstance(evidence, Mapping):
        return [], []
    observations = [
        dict(entry)
        for entry in (evidence.get("observations") or ())
        if isinstance(entry, Mapping)
    ]
    signals = [
        dict(entry)
        for entry in (evidence.get("derived_signals") or ())
        if isinstance(entry, Mapping)
    ]
    return observations, signals


def _match_requirement(
    requirement: Mapping,
    observations: Sequence[Mapping],
    signals: Sequence[Mapping],
) -> list[dict]:
    """Bounded evidence entries that actually satisfy one requirement."""

    matched: list[dict] = []
    ref_kinds = set(requirement.get("ref_kinds") or ())
    value_re = requirement.get("value_re")
    for observation in observations:
        kind, value = _ref_kind_and_value(observation.get("ref"))
        if kind not in ref_kinds:
            continue
        if value_re is not None and not value_re.search(value):
            continue
        ref = _safe_text(observation.get("ref"), 512)
        fact = _safe_text(observation.get("fact"), MAX_TEXT_CHARS)
        if ref:
            matched.append({"ref": ref, "fact": fact})
        if len(matched) >= MAX_EVIDENCE_PER_REQUIREMENT:
            return matched
    watch_signals = {name.upper() for name in requirement.get("watch_signals") or ()}
    if watch_signals:
        for signal in signals:
            name = _upper(signal.get("signal"))
            if name not in watch_signals:
                continue
            entry = {
                "signal": name,
                "detail": _safe_text(signal.get("detail"), MAX_TEXT_CHARS),
            }
            if entry not in matched:
                matched.append(entry)
            if len(matched) >= MAX_EVIDENCE_PER_REQUIREMENT:
                break
    return matched


def _build_steps(
    spec: Mapping,
    statuses: Mapping[str, str],
) -> list[dict]:
    """Existing evidence first, then bounded gain/risk/prerequisite steps."""

    requirements = list(spec["requirements"])
    source_targets = spec["source_targets"]
    steps: list[dict] = [
        {
            "step": 1,
            "source": SOURCE_EXISTING_EVIDENCE,
            "operation": SOURCE_OPERATIONS[SOURCE_EXISTING_EVIDENCE],
            "requirement_kinds": [
                req["kind"]
                for req in requirements
                if statuses.get(req["kind"]) == STATUS_AVAILABLE
            ],
            "expected": (
                "confirm the available/missing split against the evidence "
                "already selected by the hypotheses"
            ),
            "risk": SOURCE_RISK[SOURCE_EXISTING_EVIDENCE],
            "information_gain": 0,
            "depends_on": [],
        }
    ]
    candidates: list[tuple[int, int, int, int, Mapping, str]] = []
    for position, requirement in enumerate(requirements):
        kind = requirement["kind"]
        if statuses.get(kind) != STATUS_MISSING:
            continue
        sources = list(source_targets.get(kind) or ()) + [SOURCE_HUMAN_REVIEW]
        for source in dict.fromkeys(sources):
            gain = (
                HUMAN_REVIEW_INFORMATION_GAIN
                if source == SOURCE_HUMAN_REVIEW
                else int(requirement["information_gain"])
            )
            candidates.append(
                (
                    -gain,
                    RISK_RANK[SOURCE_RISK[source]],
                    SOURCE_ORDER[source],
                    position,
                    requirement,
                    source,
                )
            )
    candidates.sort(key=lambda item: item[:4])
    for _, _, _, _, requirement, source in candidates[: MAX_STEPS - 1]:
        steps.append(
            {
                "step": len(steps) + 1,
                "source": source,
                "operation": SOURCE_OPERATIONS[source],
                "requirement_kinds": [requirement["kind"]],
                "expected": _safe_text(requirement["description"]),
                "risk": SOURCE_RISK[source],
                "information_gain": (
                    HUMAN_REVIEW_INFORMATION_GAIN
                    if source == SOURCE_HUMAN_REVIEW
                    else int(requirement["information_gain"])
                ),
                "depends_on": [1],
            }
        )
    return steps


def _build_plan(
    action: Mapping,
    outcomes_by_ref: Mapping[str, Mapping],
    position: int,
) -> dict:
    gap_id = _normalized_gap_id(action)
    spec = _GAP_SPECS[gap_id]
    category = _normalized_category(action.get("category")) or spec["category"]
    action_ref = _safe_text(action.get("action_id"), 16) or f"A{position}"

    hypothesis_refs = _bounded_strings(
        action.get("hypothesis_refs"), MAX_HYPOTHESES_PER_PLAN, 16
    )
    hypothesis_count = _coerce_count(
        action.get("hypothesis_count"),
        len(hypothesis_refs),
        MAX_HYPOTHESES_PER_PLAN,
    )

    observations: list[dict] = []
    signals: list[dict] = []
    hypothesis_missing: list[str] = []
    for ref in hypothesis_refs:
        outcome = outcomes_by_ref.get(ref)
        if not isinstance(outcome, Mapping):
            continue
        found_observations, found_signals = _collect_outcome_evidence(outcome)
        observations.extend(found_observations)
        signals.extend(found_signals)
        for item in outcome.get("hypothesis_missing_evidence") or ():
            text = _safe_text(item, 160)
            if text and text not in hypothesis_missing:
                hypothesis_missing.append(text)

    required_evidence: list[dict] = []
    available_evidence: list[dict] = []
    missing_evidence: list[dict] = []
    statuses: dict[str, str] = {}
    for requirement in list(spec["requirements"])[:MAX_REQUIRED_EVIDENCE]:
        matched = _match_requirement(requirement, observations, signals)
        status = STATUS_AVAILABLE if matched else STATUS_MISSING
        statuses[requirement["kind"]] = status
        required_evidence.append(
            {
                "requirement_kind": requirement["kind"],
                "description": requirement["description"],
                "status": status,
                "information_gain": int(requirement["information_gain"]),
                "evidence": matched,
            }
        )
        if status == STATUS_AVAILABLE:
            available_evidence.append(
                {
                    "requirement_kind": requirement["kind"],
                    "evidence": matched,
                }
            )
        else:
            missing_evidence.append(
                {
                    "requirement_kind": requirement["kind"],
                    "description": requirement["description"],
                }
            )

    steps = _build_steps(spec, statuses)
    acquisition_sources: list[str] = []
    for step in steps:
        if step["source"] not in acquisition_sources:
            acquisition_sources.append(step["source"])

    if missing_evidence:
        expected_result = spec["expected_result"]
        information_gain = max(
            int(entry["information_gain"])
            for entry in required_evidence
            if entry["status"] == STATUS_MISSING
        )
    else:
        expected_result = (
            "No new acquisition is required: every required evidence item is "
            "already available; keep the hypothesis NOT_CONFIRMED until a "
            "human interprets the available evidence."
        )
        information_gain = 0
    acquisition_risk = RISK_LOW
    for step in steps:
        if RISK_RANK[step["risk"]] > RISK_RANK[acquisition_risk]:
            acquisition_risk = step["risk"]

    skill_id = _text(spec.get("skill_id"))
    skill = skill_by_id(skill_id) if skill_id else None
    skill_required_evidence = (
        _bounded_strings(skill.get("required_evidence"), MAX_SKILL_EVIDENCE, 160)
        if isinstance(skill, Mapping)
        else []
    )

    return {
        "plan_id": "",
        "order": 0,
        "action_ref": action_ref,
        "gap_id": gap_id,
        "category": category,
        "hypothesis_refs": hypothesis_refs,
        "hypothesis_count": hypothesis_count,
        "skill_refs": [skill_id] if skill_id and skill else [],
        "skill_required_evidence": skill_required_evidence,
        "acquisition_method": spec["acquisition_method"],
        "evidence_gap": (
            _safe_text(action.get("evidence_gap"))
            or spec["evidence_gap"]
        ),
        "acquisition_goal": spec["acquisition_goal"],
        "required_evidence": required_evidence,
        "currently_available_evidence": available_evidence[
            :MAX_AVAILABLE_EVIDENCE
        ],
        "missing_evidence": missing_evidence[:MAX_MISSING_EVIDENCE],
        "hypothesis_missing_evidence": hypothesis_missing[
            :MAX_HYPOTHESIS_MISSING_EVIDENCE
        ],
        "acquisition_sources": acquisition_sources[:MAX_SOURCES],
        "acquisition_steps": steps,
        "expected_result": expected_result,
        "decision_impact": dict(DECISION_IMPACT),
        "decision_impact_note": (
            "Prediction only: no evidence has been acquired, no result has "
            "occurred, and nothing is confirmed."
        ),
        "stopping_condition": spec["stopping_condition"],
        "acquisition_priority": {
            "information_gain": information_gain,
            "acquisition_risk": acquisition_risk,
            "reuse_hypotheses": hypothesis_count,
            "order_key": [
                information_gain,
                RISK_RANK[acquisition_risk],
                hypothesis_count,
                _category_rank(category),
            ],
        },
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def build_evidence_acquisition_plans(action_plan: object = None) -> list[dict]:
    """One bounded acquisition plan per R70 action (input order).

    ``action_plan`` is the R70 ``plan_research_actions`` result dict (or a
    bare list of R70 actions). Actions are consumed read-only; an action whose
    hypotheses have no matching R70 outcome fails safe: every requirement is
    ``MISSING`` because no evidence can be verified.
    """

    block = _block(action_plan)
    raw_actions = block.get("actions")
    action_items = (
        _mapping_items(raw_actions)
        if raw_actions is not None
        else _mapping_items(action_plan)
    )
    outcomes_by_ref: dict[str, Mapping] = {}
    for outcome in _mapping_items(block.get("outcomes")):
        ref = _safe_text(outcome.get("hypothesis_ref"), 16)
        if ref:
            outcomes_by_ref[ref] = outcome
    return [
        _build_plan(action, outcomes_by_ref, position)
        for position, action in enumerate(action_items, start=1)
    ]


def order_evidence_acquisition_plans(plans: object = None) -> list[dict]:
    """Deterministic ordering: gain desc, risk asc, reuse desc, category."""

    ordered = [dict(plan) for plan in _mapping_items(plans)]
    ordered.sort(
        key=lambda plan: (
            -int(
                (plan.get("acquisition_priority") or {}).get(
                    "information_gain", 0
                )
            ),
            RISK_RANK.get(
                _upper(
                    (plan.get("acquisition_priority") or {}).get(
                        "acquisition_risk"
                    )
                ),
                len(RISK_RANK),
            ),
            -int(
                (plan.get("acquisition_priority") or {}).get(
                    "reuse_hypotheses", 0
                )
            ),
            _category_rank(_normalized_category(plan.get("category"))),
            _text(plan.get("gap_id")),
            _text(plan.get("action_ref")),
        )
    )
    return ordered


def summarize_evidence_acquisition(plans: object = None) -> dict:
    """Bounded acquisition-plan summary (counts, bands, top plan)."""

    items = list(_mapping_items(plans))
    available = 0
    missing = 0
    for plan in items:
        for requirement in plan.get("required_evidence") or ():
            status = _upper(requirement.get("status"))
            if status == STATUS_AVAILABLE:
                available += 1
            elif status == STATUS_MISSING:
                missing += 1
    risk_bands = {RISK_LOW: 0, RISK_MEDIUM: 0, RISK_HIGH: 0}
    for plan in items:
        risk = _upper(
            (plan.get("acquisition_priority") or {}).get("acquisition_risk")
        )
        if risk in risk_bands:
            risk_bands[risk] += 1
    top = items[0] if items else {}
    return {
        "rule_version": RULE_VERSION,
        "plan_count": len(items),
        "covered_actions": len(
            {_text(plan.get("action_ref")) for plan in items if plan.get("action_ref")}
        ),
        "covered_hypotheses": sum(
            int(plan.get("hypothesis_count") or 0) for plan in items
        ),
        "requirements_available": available,
        "requirements_missing": missing,
        "risk_bands": risk_bands,
        "top_plan_id": _safe_text(top.get("plan_id"), 16),
        "top_acquisition_goal": _text(top.get("acquisition_goal")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def plan_evidence_acquisition(
    action_plan: object = None, *, limit: int = MAX_PLANS
) -> dict:
    """Build, order and bound the R71 evidence acquisition plan."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ResearchEvidenceAcquisitionError("limit must be an integer")
    if limit < 0:
        raise ResearchEvidenceAcquisitionError("limit must be >= 0")

    plans = order_evidence_acquisition_plans(
        build_evidence_acquisition_plans(action_plan)
    )
    limited = plans[:limit]
    for position, plan in enumerate(limited, start=1):
        plan["plan_id"] = f"P{position}"
        plan["order"] = position
    block = _block(action_plan)
    return {
        "rule_version": RULE_VERSION,
        "source_action_rule_version": (
            _safe_text(block.get("rule_version"), 32)
            or SOURCE_ACTION_RULE_VERSION
        ),
        "plans": limited,
        "summary": summarize_evidence_acquisition(limited),
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "SOURCE_ACTION_RULE_VERSION",
    "MAX_PLANS",
    "MAX_HYPOTHESES_PER_PLAN",
    "MAX_REQUIRED_EVIDENCE",
    "MAX_EVIDENCE_PER_REQUIREMENT",
    "MAX_AVAILABLE_EVIDENCE",
    "MAX_MISSING_EVIDENCE",
    "MAX_SOURCES",
    "MAX_STEPS",
    "MAX_TEXT_CHARS",
    "MAX_SKILL_EVIDENCE",
    "ACQUISITION_SOURCES",
    "SOURCE_EXISTING_SNAPSHOT",
    "SOURCE_EXISTING_EVIDENCE",
    "SOURCE_AUTHORIZED_TEST_CONTEXT",
    "SOURCE_RESPONSE_OBSERVATION",
    "SOURCE_DOCUMENTATION",
    "SOURCE_COMPONENT_METADATA",
    "SOURCE_VERSION_MAPPING",
    "SOURCE_HUMAN_REVIEW",
    "SOURCE_OPERATIONS",
    "SOURCE_RISK",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "RISK_RANK",
    "STATUS_AVAILABLE",
    "STATUS_MISSING",
    "REQUIREMENT_STATUSES",
    "IMPACT_SUPPORTS",
    "IMPACT_WEAKENS",
    "IMPACT_RESOLVES",
    "IMPACT_REMAINS_UNRESOLVED",
    "DECISION_IMPACT_STATES",
    "DECISION_IMPACT",
    "ACQUISITION_METHODS",
    "AUTHORIZATION_BEHAVIOR_REVIEW",
    "FETCH_BEHAVIOR_REVIEW",
    "RESPONSE_CONTEXT_REVIEW",
    "QUERY_BEHAVIOR_REVIEW",
    "TOKEN_ARTIFACT_REVIEW",
    "OAUTH_ARTIFACT_REVIEW",
    "ADDITIONAL_EVIDENCE_REVIEW",
    "STRUCTURAL_REF_KINDS",
    "CORROBORATING_REF_KINDS",
    "CATEGORY_ALIASES",
    "ResearchEvidenceAcquisitionError",
    "build_evidence_acquisition_plans",
    "order_evidence_acquisition_plans",
    "summarize_evidence_acquisition",
    "plan_evidence_acquisition",
]
