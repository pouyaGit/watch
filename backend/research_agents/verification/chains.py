"""EPIC12 — deterministic per-vulnerability verification chains.

A *verification chain* is the ordered set of stages a vulnerability class must
pass through before a finding may be called confirmed.  The chain is a
**planner/explainer**, never an authority:

* evidence types and stage numbers are read from the closed EPIC11 vocabulary
  (:mod:`backend.research_agents.finding.integrity.taxonomy`);
* the confirmation requirement is *derived* from the EPIC11 contract
  (:mod:`backend.research_agents.finding.integrity.contracts`) at call time, so
  a chain can never drift from — or weaken — the authoritative contract;
* the verdict is produced by the EPIC11 gate
  (:mod:`backend.research_agents.finding.integrity.gate`), never here.

Chain capability states (never silently upgraded):

``FULL``
    Every stage has a wired, bounded verification action (XSS only, this Epic).
``CONTRACT_ONLY``
    Stages, required evidence and allowed actions are defined; no executor is
    wired.  Running one yields ``BLOCKED`` with ``chain_not_implemented``.
``NOT_IMPLEMENTED``
    No chain is defined; callers fall back to the EPIC11 contract alone.

Nothing in this module executes anything, reads the network or reads a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import taxonomy as tx

CHAIN_RULE_VERSION = "epic12-verification-chain-1"

# --------------------------------------------------------------- capability

CAPABILITY_FULL = "FULL"
CAPABILITY_LIMITED = "LIMITED"
CAPABILITY_CONTRACT_ONLY = "CONTRACT_ONLY"
CAPABILITY_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

#: EPIC16: the capability vocabulary a chain may declare.  LIMITED means the
#: deterministic verification of the chain's observable stages is implemented
#: while its active acquisition is not available in this runtime.
CAPABILITY_LEVELS: tuple[str, ...] = (
    CAPABILITY_FULL, CAPABILITY_LIMITED, CAPABILITY_CONTRACT_ONLY,
    CAPABILITY_NOT_IMPLEMENTED)

CAPABILITY_STATES: tuple[str, ...] = (
    CAPABILITY_FULL, CAPABILITY_CONTRACT_ONLY, CAPABILITY_NOT_IMPLEMENTED)

# ------------------------------------------------------------ stage states

STAGE_SATISFIED = "SATISFIED"
STAGE_MISSING = "MISSING"
STAGE_NOT_TESTED = "NOT_TESTED"
STAGE_CONTRADICTED = "CONTRADICTED"
STAGE_NOT_APPLICABLE = "NOT_APPLICABLE"

STAGE_STATES: tuple[str, ...] = (
    STAGE_SATISFIED, STAGE_MISSING, STAGE_NOT_TESTED, STAGE_CONTRADICTED,
    STAGE_NOT_APPLICABLE)

# Deterministic reasons a conditional stage may be ruled not applicable.  A
# reason is *recorded*, never inferred silently: the stage then shows as
# ``NOT_APPLICABLE`` (never as ``SATISFIED``) in the projection.
NOT_APPLICABLE_REFLECTED_ONLY = "not_applicable_reflected_only"
NOT_APPLICABLE_NO_DOM_SOURCE = "not_applicable_no_dom_source"


@dataclass(frozen=True)
class ChainStage:
    """One ordered stage of a verification chain."""

    key: str
    label: str
    order: int
    stage: int
    claim_type: str
    #: any-of groups; every group must be covered by at least one unique item
    required_groups: tuple[tuple[str, ...], ...] = ()
    allowed_actions: tuple[str, ...] = ()
    expectation: str = ""
    failure_conditions: tuple[str, ...] = ()
    #: conditional stages may be ruled not-applicable by an explicit rule
    conditional: bool = False
    applies_when: str = ""
    #: a stage whose evidence the confirmation contract itself requires
    required_for_confirmation: bool = False

    @property
    def required_evidence_types(self) -> tuple[str, ...]:
        out: list[str] = []
        for group in self.required_groups:
            for t in group:
                if t not in out:
                    out.append(t)
        return tuple(out)

    @property
    def stage_label(self) -> str:
        return tx.STAGE_LABELS.get(self.stage, "auxiliary")

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "order": self.order,
            "stage": self.stage,
            "stage_label": self.stage_label,
            "claim_type": self.claim_type,
            "required_evidence_types": list(self.required_evidence_types),
            "required_groups": [list(g) for g in self.required_groups],
            "allowed_actions": list(self.allowed_actions),
            "expectation": self.expectation,
            "failure_conditions": list(self.failure_conditions),
            "conditional": self.conditional,
            "applies_when": self.applies_when,
            "required_for_confirmation": self.required_for_confirmation,
        }


@dataclass(frozen=True)
class VerificationChain:
    """The ordered verification chain for one vulnerability class."""

    vulnerability_class: str
    stages: tuple[ChainStage, ...]
    capability: str = CAPABILITY_CONTRACT_ONLY
    reference: bool = False
    limitations: tuple[str, ...] = ()
    rule_version: str = CHAIN_RULE_VERSION

    # ---------------------------------------------------------------- views

    @property
    def chain_id(self) -> str:
        return f"chain-{self.vulnerability_class.lower()}"

    @property
    def contract(self) -> ct.VulnerabilityContract:
        """The authoritative EPIC11 contract for this class."""
        return ct.contract_for(self.vulnerability_class)

    @property
    def contract_id(self) -> str:
        return self.contract.contract_id

    @property
    def confirmation_claim(self):
        """The EPIC11 confirmation claim — the chain never restates it."""
        return self.contract.confirmation_claim

    @property
    def confirmation_requires(self) -> tuple[tuple[str, ...], ...]:
        """The evidence groups the confirmation claim needs (() if none).

        CVE_RESEARCH declares no confirmation claim, so an empty tuple is the
        honest answer there — never an exception.
        """
        if not _has_confirmation_claim(self):
            return ()
        return tuple(self.confirmation_claim.required_groups)

    @property
    def requires_authorization(self) -> bool:
        """Authorization needed to confirm (a research chain needs none)."""
        if not _has_confirmation_claim(self):
            return bool(self.contract.require_authorization_for_confirmation)
        return bool(self.contract.require_authorization_for_confirmation
                    or self.confirmation_claim.requires_authorization)

    @property
    def min_unique_observations(self) -> int:
        if not _has_confirmation_claim(self):
            return 0
        return int(self.confirmation_claim.min_unique_observations)

    @property
    def implemented(self) -> bool:
        return self.capability == CAPABILITY_FULL

    def stage(self, key: str) -> ChainStage | None:
        for item in self.stages:
            if item.key == key:
                return item
        return None

    def ordered(self) -> tuple[ChainStage, ...]:
        return tuple(sorted(self.stages, key=lambda s: s.order))

    @property
    def required_stages(self) -> tuple[ChainStage, ...]:
        return tuple(s for s in self.ordered()
                     if s.required_for_confirmation and not s.conditional)

    @property
    def confirmation_stage_keys(self) -> tuple[str, ...]:
        return tuple(s.key for s in self.ordered()
                     if s.required_for_confirmation)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "rule_version": self.rule_version,
            "vulnerability_class": self.vulnerability_class,
            "capability": self.capability,
            "reference": self.reference,
            "implemented": self.implemented,
            "contract_id": self.contract_id,
            "confirmation_claim": _has_confirmation_claim(self),
            "confirmation_requires": [list(g) for g in self.confirmation_requires],
            "confirmation_stage_keys": list(self.confirmation_stage_keys),
            "requires_authorization": self.requires_authorization,
            "min_unique_observations": self.min_unique_observations,
            "stages": [s.to_dict() for s in self.ordered()],
            "limitations": list(self.limitations),
        }


# ============================================================== XSS (FULL)

XSS_LIMITATIONS: tuple[str, ...] = (
    "parameter discovery is not vulnerability confirmation",
    "a reflected parameter is not automatically XSS",
    "confirmation requires the EPIC11 confirmation claim (stage-3 evidence "
    "plus payload-execution/exploitability evidence, min "
    f"{ct.XSS.confirmation_claim.min_unique_observations} unique "
    "observations, authorized scope)",
    "the DOM sink stage applies to the DOM variant; for a reflected-only "
    "hypothesis it is recorded NOT_APPLICABLE with an explicit rule, never "
    "silently satisfied",
)

XSS_CHAIN = VerificationChain(
    vulnerability_class="XSS",
    capability=CAPABILITY_FULL,
    limitations=XSS_LIMITATIONS,
    stages=(
        ChainStage(
            key="parameter",
            label="Parameter / Input Discovery",
            order=1,
            stage=tx.STAGE_OBSERVED,
            claim_type="parameter_observed",
            required_groups=((tx.PARAMETER_OBSERVED,),),
            allowed_actions=("PARAMETER_INVENTORY", "SEND_MARKER"),
            expectation="an actual parameter on an actual authorized target",
            failure_conditions=("no_parameter_observed",
                                "parameter_not_in_authorized_scope"),
            required_for_confirmation=True,
        ),
        ChainStage(
            key="reflection",
            label="Reflection",
            order=2,
            stage=tx.STAGE_REFLECTION,
            claim_type="reflection_observed",
            required_groups=((tx.REFLECTION_OBSERVED,),),
            allowed_actions=("SEND_MARKER", "CHECK_REFLECTION"),
            expectation="an attacker-controlled marker observed in the "
                        "response or DOM",
            failure_conditions=("reflection_not_observed",
                                "marker_not_attacker_controlled"),
            required_for_confirmation=True,
        ),
        ChainStage(
            key="context",
            label="Context Classification",
            order=3,
            stage=tx.STAGE_REFLECTION,
            claim_type="output_context_unsafe",
            required_groups=((tx.OUTPUT_CONTEXT_IDENTIFIED,),),
            allowed_actions=("CLASSIFY_REFLECTION_CONTEXT",),
            expectation="an explicitly classified reflection context "
                        "(html_text / html_attribute / javascript / url / dom)",
            failure_conditions=("context_unclassified",
                                "context_encoded_or_safe"),
            required_for_confirmation=True,
        ),
        ChainStage(
            key="sink",
            label="Sink / Execution Path",
            order=4,
            stage=tx.STAGE_REFLECTION,
            claim_type="output_context_unsafe",
            required_groups=((tx.DOM_SINK_IDENTIFIED,),),
            allowed_actions=("TRACE_DOM_SOURCE", "TRACE_DOM_SINK"),
            expectation="a dangerous DOM sink reachable from controlled input "
                        "(DOM variant)",
            failure_conditions=("sink_not_reachable", "source_not_controlled"),
            conditional=True,
            applies_when="dom_variant",
            required_for_confirmation=False,
        ),
        ChainStage(
            key="execution",
            label="Execution",
            order=5,
            stage=tx.STAGE_EXPLOITABILITY,
            claim_type="payload_execution",
            required_groups=((tx.PAYLOAD_EXECUTION,),),
            allowed_actions=("DELIVER_CONTROLLED_PAYLOAD", "OBSERVE_EXECUTION"),
            expectation="observable controlled execution",
            failure_conditions=("payload_did_not_execute",
                                "execution_not_observable"),
            required_for_confirmation=True,
        ),
        ChainStage(
            key="exploitability",
            label="Exploitability",
            order=6,
            stage=tx.STAGE_EXPLOITABILITY,
            claim_type="vulnerability_confirmed",
            required_groups=((tx.EXPLOITABILITY_ESTABLISHED,),),
            allowed_actions=("OBSERVE_EXECUTION",),
            expectation="attacker-controlled input produces security-relevant "
                        "behaviour",
            failure_conditions=("exploitability_not_established",),
            required_for_confirmation=True,
        ),
    ),
)


# ================================================== reference chains (design)
# Contract-only: the stages, required evidence and allowed actions are
# defined so a shallow observation can never be mistaken for confirmation.
# No executor is wired; running one yields BLOCKED/chain_not_implemented.

CORS_CHAIN = VerificationChain(
    vulnerability_class="CORS",
    capability=CAPABILITY_LIMITED,
    reference=False,
    limitations=(
        "a CORS header is not automatically exploitable CORS",
        "an Access-Control-Allow-Origin value alone never confirms",
        "EPIC16 wires the read-only classification stages "
        "(CHECK_CORS_HEADERS / CLASSIFY_CORS_ORIGIN_ECHO / "
        "CHECK_CREDENTIALS_MODE / ASSESS_RESPONSE_SENSITIVITY); supplying a "
        "controlled Origin (SEND_ORIGIN_HEADER) needs a live request lane "
        "this runtime does not have",
    ),
    stages=(
        ChainStage(
            key="origin_supplied", label="Origin Supplied", order=1,
            stage=tx.STAGE_CONTROLLED, claim_type="controlled_input_tested",
            required_groups=((tx.CONTROLLED_INPUT_SENT,),),
            allowed_actions=("SEND_ORIGIN_HEADER",),
            expectation="an attacker-controlled Origin was supplied",
            required_for_confirmation=True),
        ChainStage(
            key="acao_observed", label="ACAO Behaviour Observed", order=2,
            stage=tx.STAGE_OBSERVED, claim_type="url_observed",
            required_groups=((tx.RESPONSE_OBSERVED,),),
            allowed_actions=("CHECK_CORS_HEADERS",),
            expectation="Access-Control-Allow-Origin behaviour recorded for "
                        "that exact Origin",
            required_for_confirmation=True),
        ChainStage(
            key="arbitrary_origin_accepted",
            label="Arbitrary Origin Accepted", order=3,
            stage=tx.STAGE_REFLECTION, claim_type="reflection_observed",
            required_groups=((tx.OUTPUT_CONTEXT_IDENTIFIED,),),
            allowed_actions=("CLASSIFY_CORS_ORIGIN_ECHO",),
            expectation="an arbitrary attacker-controlled origin is echoed or "
                        "wildcard-accepted",
            failure_conditions=("origin_not_accepted",
                                "allowlist_rejected_origin"),
            required_for_confirmation=True),
        ChainStage(
            key="credentials_evaluated", label="Credential Behaviour",
            order=4, stage=tx.STAGE_EXPLOITABILITY,
            claim_type="payload_execution",
            required_groups=((tx.PAYLOAD_EXECUTION,),),
            allowed_actions=("CHECK_CREDENTIALS_MODE",),
            expectation="Access-Control-Allow-Credentials evaluated against a "
                        "credentialed response",
            failure_conditions=("credentials_not_allowed",
                                "wildcard_with_credentials_rejected"),
            required_for_confirmation=True),
        ChainStage(
            key="sensitive_response_available",
            label="Sensitive Response Availability", order=5,
            stage=tx.STAGE_IMPACT, claim_type="impact_established",
            required_groups=((tx.IMPACT_ESTABLISHED,),),
            allowed_actions=("ASSESS_RESPONSE_SENSITIVITY",),
            expectation="a sensitive, credentialed response readable "
                        "cross-origin",
            required_for_confirmation=True),
        ChainStage(
            key="browser_exploitability",
            label="Browser-Relevant Exploitability", order=6,
            stage=tx.STAGE_EXPLOITABILITY, claim_type="vulnerability_confirmed",
            required_groups=((tx.EXPLOITABILITY_ESTABLISHED,),),
            allowed_actions=("OBSERVE_EXECUTION",),
            expectation="browser-relevant cross-origin read demonstrated",
            required_for_confirmation=True),
    ),
)

OPEN_REDIRECT_CHAIN = VerificationChain(
    vulnerability_class="OPEN_REDIRECT",
    capability=CAPABILITY_LIMITED,
    reference=False,
    limitations=(
        "a redirect parameter is not automatically an open redirect",
        "a 302 response alone never confirms",
        "EPIC16 wires the read-only classification stages "
        "(CHECK_REDIRECT_LOCATION / CLASSIFY_REDIRECT_TARGET); actively "
        "supplying a destination (SEND_REDIRECT_MARKER) needs a live request "
        "lane this runtime does not have",
    ),
    stages=(
        ChainStage(
            key="redirect_input", label="Redirect Input", order=1,
            stage=tx.STAGE_OBSERVED, claim_type="parameter_observed",
            required_groups=((tx.PARAMETER_OBSERVED,),),
            allowed_actions=("PARAMETER_INVENTORY",),
            expectation="a redirect-shaped parameter on an authorized target",
            required_for_confirmation=True),
        ChainStage(
            key="controlled_destination", label="Controlled Destination",
            order=2, stage=tx.STAGE_CONTROLLED,
            claim_type="controlled_input_tested",
            required_groups=((tx.CONTROLLED_INPUT_SENT,),),
            allowed_actions=("SEND_REDIRECT_MARKER",),
            expectation="an attacker-controlled destination was supplied",
            required_for_confirmation=True),
        ChainStage(
            key="redirect_observed", label="Redirect Behaviour Observed",
            order=3, stage=tx.STAGE_REFLECTION,
            claim_type="reflection_observed",
            required_groups=((tx.RESPONSE_OBSERVED,),),
            allowed_actions=("CHECK_REDIRECT_LOCATION",),
            expectation="a redirect to the supplied destination was observed",
            failure_conditions=("no_redirect_observed",
                                "redirect_to_internal_only"),
            required_for_confirmation=True),
        ChainStage(
            key="destination_attacker_controlled",
            label="Destination Attacker-Controlled", order=4,
            stage=tx.STAGE_EXPLOITABILITY, claim_type="payload_execution",
            required_groups=((tx.PAYLOAD_EXECUTION,),),
            allowed_actions=("CLASSIFY_REDIRECT_TARGET",),
            expectation="the terminal destination is attacker-controlled, not "
                        "an allowlisted host",
            required_for_confirmation=True),
        ChainStage(
            key="terminal_redirect_confirmed",
            label="Terminal Redirect Confirmed", order=5,
            stage=tx.STAGE_EXPLOITABILITY, claim_type="vulnerability_confirmed",
            required_groups=((tx.EXPLOITABILITY_ESTABLISHED,),),
            allowed_actions=("OBSERVE_EXECUTION",),
            expectation="the off-scope destination is actually reached",
            required_for_confirmation=True),
    ),
)

SSRF_CHAIN = VerificationChain(
    vulnerability_class="SSRF",
    capability=CAPABILITY_LIMITED,
    reference=False,
    limitations=(
        "a URL-shaped parameter is not SSRF",
        "no server-side request evidence means no SSRF claim",
        "EPIC16 wires the destination-policy evaluation "
        "(CHECK_CALLBACK_INTERACTION classifies an observed destination "
        "against the SSRF policy) and refuses every internal destination; "
        "SEND_CALLBACK_URL needs a live request lane, and no SSRF probing of "
        "internal infrastructure is ever performed",
    ),
    stages=(
        ChainStage(
            key="url_input", label="URL-like Input", order=1,
            stage=tx.STAGE_OBSERVED, claim_type="parameter_observed",
            required_groups=((tx.PARAMETER_OBSERVED,),),
            allowed_actions=("PARAMETER_INVENTORY",),
            expectation="a URL-accepting parameter on an authorized target",
            required_for_confirmation=True),
        ChainStage(
            key="server_side_request", label="Server-Side Request Evidence",
            order=2, stage=tx.STAGE_CONTROLLED,
            claim_type="controlled_input_tested",
            required_groups=((tx.CONTROLLED_INPUT_SENT,),),
            allowed_actions=("SEND_CALLBACK_URL",),
            expectation="a controlled destination URL was submitted",
            required_for_confirmation=True),
        ChainStage(
            key="controlled_interaction",
            label="Controlled Destination Interaction", order=3,
            stage=tx.STAGE_REFLECTION, claim_type="reflection_observed",
            required_groups=((tx.RESPONSE_OBSERVED,),),
            allowed_actions=("CHECK_CALLBACK_INTERACTION",),
            expectation="the controlled destination recorded an inbound "
                        "server-side request",
            failure_conditions=("no_inbound_request_observed",),
            required_for_confirmation=True),
        ChainStage(
            key="observable_server_behaviour",
            label="Observable Server-Side Behaviour", order=4,
            stage=tx.STAGE_EXPLOITABILITY, claim_type="payload_execution",
            required_groups=((tx.PAYLOAD_EXECUTION,),),
            allowed_actions=("OBSERVE_SERVER_RESPONSE",),
            expectation="response timing/content changes attributable to the "
                        "controlled destination",
            required_for_confirmation=True),
        ChainStage(
            key="security_impact", label="Security-Relevant Impact", order=5,
            stage=tx.STAGE_IMPACT, claim_type="impact_established",
            required_groups=((tx.IMPACT_ESTABLISHED,),),
            allowed_actions=("ASSESS_SSRF_IMPACT",),
            expectation="access to an internal/privileged resource was "
                        "demonstrated",
            required_for_confirmation=True),
        ChainStage(
            key="ssrf_confirmed", label="Confirmation", order=6,
            stage=tx.STAGE_EXPLOITABILITY, claim_type="vulnerability_confirmed",
            required_groups=((tx.EXPLOITABILITY_ESTABLISHED,),),
            allowed_actions=("OBSERVE_EXECUTION",),
            expectation="the EPIC11 confirmation claim is supported by "
                        "server-side evidence",
            required_for_confirmation=True),
    ),
)

# EPIC16 §11.  IDOR/BOLA verification needs a SECOND authorized identity and
# object-ownership semantics.  This runtime has neither, so every stage stays
# contract-only and the chain refuses to claim a cross-object access it never
# performed.
IDOR_CHAIN = VerificationChain(
    vulnerability_class="IDOR",
    capability=CAPABILITY_CONTRACT_ONLY,
    reference=True,
    limitations=(
        "an object reference is not IDOR",
        "verification requires a second authorized identity: this runtime "
        "has no identity-switching capability (CHECK_OBJECT_ACCESS refuses)",
        "no cross-object access may be claimed without an unauthorized "
        "object-access observation",
    ),
    stages=(
        ChainStage(
            key="object_reference", label="Object Reference Identified",
            order=1, stage=tx.STAGE_OBSERVED,
            claim_type="object_reference_observed",
            required_groups=((tx.PARAMETER_OBSERVED,),),
            allowed_actions=("PARAMETER_INVENTORY",),
            expectation="an object reference on the authorized target",
            required_for_confirmation=True),
        ChainStage(
            key="second_context", label="Second Authorized Context", order=2,
            stage=tx.STAGE_CONTROLLED, claim_type="controlled_input_tested",
            required_groups=((tx.CONTROLLED_INPUT_SENT,),),
            allowed_actions=("CHECK_OBJECT_ACCESS",),
            expectation="a second, separately authorized identity available "
                        "for the object",
            failure_conditions=("no_second_context",),
            required_for_confirmation=True),
        ChainStage(
            key="object_access_attempted", label="Object Access Attempted",
            order=3, stage=tx.STAGE_REFLECTION,
            claim_type="cross_object_access_observed",
            required_groups=((tx.RESPONSE_OBSERVED,),),
            allowed_actions=("CHECK_OBJECT_ACCESS",),
            expectation="the second context attempted to read the object",
            failure_conditions=("access_denied",),
            required_for_confirmation=True),
        ChainStage(
            key="unauthorized_access", label="Unauthorized Object Access",
            order=4, stage=tx.STAGE_EXPLOITABILITY,
            claim_type="payload_execution",
            required_groups=((tx.PAYLOAD_EXECUTION,),),
            allowed_actions=("CHECK_OBJECT_ACCESS",),
            expectation="the object was returned to a context that does not "
                        "own it",
            required_for_confirmation=True),
        ChainStage(
            key="idor_impact", label="Impact", order=5,
            stage=tx.STAGE_IMPACT, claim_type="impact_established",
            required_groups=((tx.IMPACT_ESTABLISHED,),),
            allowed_actions=(),
            expectation="a security-relevant impact attributable to the "
                        "access",
            required_for_confirmation=True),
        ChainStage(
            key="idor_confirmed", label="Confirmation", order=6,
            stage=tx.STAGE_EXPLOITABILITY, claim_type="vulnerability_confirmed",
            required_groups=((tx.EXPLOITABILITY_ESTABLISHED,),),
            allowed_actions=("OBSERVE_EXECUTION",),
            expectation="the EPIC11 confirmation claim is supported",
            required_for_confirmation=True),
    ),
)

# EPIC16 §12.  CVE research stays research: the contract has NO confirmation
# claim, so applicability evidence can never turn into a confirmed
# vulnerability here.
CVE_RESEARCH_CHAIN = VerificationChain(
    vulnerability_class="CVE_RESEARCH",
    capability=CAPABILITY_CONTRACT_ONLY,
    reference=True,
    limitations=(
        "a CVE match is not vulnerability confirmation",
        "no exploitability evidence exists in this runtime for CVE classes",
        "the EPIC11 CVE_RESEARCH contract declares no confirmation claim",
    ),
    stages=(
        ChainStage(
            key="product_identified", label="Product Identified", order=1,
            stage=tx.STAGE_OBSERVED, claim_type="technology_observed",
            required_groups=((tx.RESPONSE_OBSERVED,),),
            allowed_actions=("PARAMETER_INVENTORY",),
            expectation="a technology fingerprint for the target",
            required_for_confirmation=False),
        ChainStage(
            key="version_identified", label="Version Identified", order=2,
            stage=tx.STAGE_OBSERVED, claim_type="technology_observed",
            required_groups=((tx.RESPONSE_OBSERVED,),),
            allowed_actions=(),
            expectation="an explicit version string",
            required_for_confirmation=False),
        ChainStage(
            key="applicability_evidence", label="Applicability Evidence",
            order=3, stage=tx.STAGE_OBSERVED,
            claim_type="knowledge_correlation",
            required_groups=((tx.KNOWLEDGE_REFERENCE,),),
            allowed_actions=(),
            expectation="a knowledge reference matching the observed product "
                        "and version",
            failure_conditions=("version_not_affected",
                                "applicability_unresolved"),
            required_for_confirmation=False),
        ChainStage(
            key="affected_version_confirmed",
            label="Affected Version Confirmed", order=4,
            stage=tx.STAGE_OBSERVED, claim_type="knowledge_correlation",
            required_groups=((tx.KNOWLEDGE_REFERENCE,),),
            allowed_actions=(),
            expectation="the observed version is inside the affected range",
            required_for_confirmation=False),
    ),
)

#: Reference chains for the classes the Epic deliberately does not implement.
REFERENCE_CHAINS: tuple[VerificationChain, ...] = (
    IDOR_CHAIN, CVE_RESEARCH_CHAIN)

#: Classes with a declared future chain but no implementation yet.
FUTURE_CLASSES: tuple[str, ...] = (
    "SQLI", "COMMAND_INJECTION", "SSTI", "AUTH_BYPASS", "OAUTH", "JWT",
)

CHAINS: dict[str, VerificationChain] = {
    "XSS": XSS_CHAIN,
    "CORS": CORS_CHAIN,
    "OPEN_REDIRECT": OPEN_REDIRECT_CHAIN,
    "SSRF": SSRF_CHAIN,
    "IDOR": IDOR_CHAIN,
    "CVE_RESEARCH": CVE_RESEARCH_CHAIN,
}

_ALIASES: dict[str, str] = {
    "REFLECTED_XSS": "XSS",
    "STORED_XSS": "XSS",
    "DOM_XSS": "XSS",
    "CROSS_SITE_SCRIPTING": "XSS",
    "OPEN_REDIRECT": "OPEN_REDIRECT",
    "UNVALIDATED_REDIRECT": "OPEN_REDIRECT",
    "CORS_MISCONFIGURATION": "CORS",
    "SSRF": "SSRF",
    "IDOR": "IDOR",
    "BOLA": "IDOR",
    "IDOR_BOLA": "IDOR",
    "OBJECT_LEVEL_AUTHORIZATION": "IDOR",
    "CVE": "CVE_RESEARCH",
    "CVE_RESEARCH": "CVE_RESEARCH",
}


def normalize_class(vulnerability_class: Any) -> str:
    """Uppercase, alias-resolved class name (never invents a class)."""
    text = str(vulnerability_class or "").strip().upper().replace("-", "_")
    text = "_".join(text.split())
    return _ALIASES.get(text, text)


def chain_for(vulnerability_class: Any) -> VerificationChain | None:
    """The chain for a class, or ``None`` when none is defined.

    ``None`` means the caller must fall back to the EPIC11 contract alone —
    never to a fabricated chain.
    """
    return CHAINS.get(normalize_class(vulnerability_class))


def capability_for(vulnerability_class: Any) -> str:
    chain = chain_for(vulnerability_class)
    return chain.capability if chain is not None else CAPABILITY_NOT_IMPLEMENTED


def _has_confirmation_claim(chain: VerificationChain) -> bool:
    """True when the class's contract declares a confirmation claim.

    CVE_RESEARCH deliberately declares none, so this is a question with a
    legitimate "no" answer — never an exception.
    """
    try:
        return chain.confirmation_claim is not None
    except KeyError:
        return False


def implemented_classes() -> tuple[str, ...]:
    """Classes whose chain is genuinely verifiable here (FULL or LIMITED)."""
    return tuple(sorted(k for k, c in CHAINS.items()
                        if c.capability in (CAPABILITY_FULL,
                                            CAPABILITY_LIMITED)))


def capability_matrix() -> list[dict[str, Any]]:
    """EPIC16 §2/§25: the honest per-class capability matrix."""
    out: list[dict[str, Any]] = []
    for name, chain in sorted(CHAINS.items()):
        out.append({
            "vulnerability_class": name,
            "chain": chain.chain_id,
            "capability": chain.capability,
            "stages": len(chain.stages),
            "confirmation_claim": _has_confirmation_claim(chain),
            "limitations": list(chain.limitations),
        })
    for name in FUTURE_CLASSES:
        out.append({
            "vulnerability_class": name,
            "chain": "",
            "capability": CAPABILITY_NOT_IMPLEMENTED,
            "stages": 0,
            "confirmation_claim": False,
            "limitations": ["no chain declared"],
        })
    return out


def chain_catalog() -> list[dict[str, Any]]:
    """Projection of every declared chain (implemented + reference)."""
    out: list[dict[str, Any]] = []
    for key in sorted(CHAINS):
        chain = CHAINS[key]
        entry = chain.to_dict()
        entry["stage_count"] = len(chain.stages)
        out.append(entry)
    for cls in FUTURE_CLASSES:
        out.append({
            "chain_id": f"chain-{cls.lower()}",
            "rule_version": CHAIN_RULE_VERSION,
            "vulnerability_class": cls,
            "capability": CAPABILITY_NOT_IMPLEMENTED,
            "reference": False,
            "implemented": False,
            "stage_count": 0,
            "stages": [],
            "limitations": [
                "no verification chain defined in EPIC12",
                "future specialist integration point",
            ],
        })
    return out


def action_types_for(vulnerability_class: Any) -> tuple[str, ...]:
    chain = chain_for(vulnerability_class)
    if chain is None:
        return ()
    out: list[str] = []
    for stage in chain.ordered():
        for action in stage.allowed_actions:
            if action not in out:
                out.append(action)
    return tuple(out)


def evidence_types_for(vulnerability_class: Any) -> tuple[str, ...]:
    """Every EPIC11 evidence type this chain can require."""
    chain = chain_for(vulnerability_class)
    if chain is None:
        contract = ct.contract_for(vulnerability_class)
        return contract.confirmation_claim.required_evidence_types
    out: list[str] = []
    for stage in chain.ordered():
        for t in stage.required_evidence_types:
            if t not in out:
                out.append(t)
    return tuple(out)


__all__ = [
    "CAPABILITY_CONTRACT_ONLY", "CAPABILITY_FULL", "CAPABILITY_NOT_IMPLEMENTED",
    "CAPABILITY_STATES", "CHAINS", "CHAIN_RULE_VERSION", "CORS_CHAIN",
    "ChainStage", "FUTURE_CLASSES", "NOT_APPLICABLE_NO_DOM_SOURCE",
    "NOT_APPLICABLE_REFLECTED_ONLY", "OPEN_REDIRECT_CHAIN", "REFERENCE_CHAINS",
    "SSRF_CHAIN", "STAGE_CONTRADICTED", "STAGE_MISSING",
    "STAGE_NOT_APPLICABLE", "STAGE_NOT_TESTED", "STAGE_SATISFIED",
    "STAGE_STATES", "VerificationChain", "XSS_CHAIN", "action_types_for",
    "capability_for", "chain_catalog", "chain_for", "evidence_types_for",
    "implemented_classes", "normalize_class",
]
