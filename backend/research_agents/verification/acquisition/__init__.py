"""EPIC13 — Active Evidence Acquisition v1.

EPIC12 answers *what evidence is missing*.  This package answers the next
question: **can the runtime safely acquire that evidence from the authorized
target?**

    CANDIDATE
      → VERIFICATION CHAIN            (EPIC12)
      → MISSING EVIDENCE              (EPIC12)
      → SELECT AUTHORIZED ACTION      (acquisition.plan)
      → EXECUTE CONTROLLED REQUEST    (acquisition.executor + transport)
      → STRUCTURED OBSERVATION        (EPIC12 observations)
      → EPIC11 EVIDENCE CLASSIFICATION (finding.integrity)
      → CHAIN RE-EVALUATION           (EPIC12 engine)
      → CONFIRMED / NOT_CONFIRMED / PENDING / BLOCKED

Hard rules this package enforces, each with tests:

* **No new network primitive.**  No ``requests``, ``urllib.request``,
  ``httpx``, ``socket``, ``subprocess`` or ``curl`` exists anywhere in the
  package (AST-asserted).  Requests go to a transport the *platform* provides.
* **Authorization is checked twice** — when the action is planned and again
  immediately before it executes.
* **Bounds are read-throughs of the platform ceilings**, never wider, and a
  bound of zero means "not available in this runtime" rather than "exhausted".
* **Markers are inert** (``[A-Z0-9_]`` only), deterministic, unique per action
  and persisted with the action.  The layer never generates an exploit payload.
* **Reflection is not a vulnerability.**  The detector reports where a marker
  landed; it never says XSS, never says execution, and never infers a DOM sink
  from a server-side reflection.
* **Transport failure is not negative evidence.**  A timeout, a refused
  connection, an out-of-scope redirect or a truncated body produces no negative
  evidence at all — the chain stays unresolved instead of being told something
  false.
* **Negative results are first-class**: a conclusive absence is recorded and
  advances the chain to a negative terminal state rather than pending forever.
* **EPIC11 stays authoritative** and **EPIC12 stays authoritative**: this layer
  only acquires and reports; the verdict is the EPIC11 gate over the rows.

Current honest state: the platform's live execution gate is closed
(``LIVE_TRAFFIC_ENABLED = False``, B1/B2 deferred), so
:class:`~.transport.PlatformAuthorizedTransport` reports
``TRANSPORT_UNAVAILABLE`` and acquisition terminates as
``TRANSPORT_UNAVAILABLE`` — planned, refused, recorded, never faked.
"""
from __future__ import annotations

from .capabilities import (CAPABILITY_RULE_VERSION, CONTRACTS,
                           CapabilityContract, capability_matrix, contract_for,
                           state_for)
from .context import (CONTEXT_CLASSES, DOM_ANALYSIS_UNAVAILABLE,
                      classification_document, classify)
from .detector import ReflectionDetection, detect, detector_document
from .executor import (ACQUISITION_ACTIONS, ACQUISITION_RESULTS,
                       AcquisitionOutcome, authorization_allows,
                       evidence_excerpt, replay_fingerprint, run_acquisition,
                       scrub_response_headers)
from .limits import (ACQUISITION_RULE_VERSION, DEFAULT_LIMITS, LimitError,
                     limits_document, limits_for)
from .markers import MarkerError, marker_document, marker_for, validate
from .plan import (AcquisitionPlan, AcquisitionRequirement, build_action,
                   plan_acquisition, requirements_from_chain)
from .replay import ReplayLedger
from .requests import ParameterRef, RequestError, build_request, request_line
from .service import (AcquisitionRun, acquisition_document,
                      run_acquisition_for_candidate)
from .transport import (AcquisitionRequest, AcquisitionResponse,
                        InjectedTransport, PlatformAuthorizedTransport,
                        UnavailableTransport, transport_document,
                        transport_for)

__all__ = [
    "ACQUISITION_ACTIONS", "ACQUISITION_RESULTS", "ACQUISITION_RULE_VERSION",
    "AcquisitionOutcome", "AcquisitionPlan", "AcquisitionRequest",
    "AcquisitionRequirement", "AcquisitionResponse", "AcquisitionRun",
    "CAPABILITY_RULE_VERSION", "CONTRACTS", "CONTEXT_CLASSES",
    "CapabilityContract", "DEFAULT_LIMITS", "DOM_ANALYSIS_UNAVAILABLE",
    "InjectedTransport", "LimitError", "MarkerError",
    "ParameterRef", "PlatformAuthorizedTransport", "ReflectionDetection",
    "ReplayLedger", "RequestError", "UnavailableTransport",
    "acquisition_document", "authorization_allows", "build_action",
    "build_request", "capability_matrix", "classification_document",
    "classify", "contract_for", "detect", "detector_document",
    "evidence_excerpt", "limits_document", "limits_for", "marker_document",
    "marker_for", "plan_acquisition", "replay_fingerprint",
    "request_line", "requirements_from_chain", "run_acquisition",
    "run_acquisition_for_candidate", "scrub_response_headers", "state_for",
    "transport_document", "transport_for", "validate",
]
