from __future__ import annotations

import hashlib
from typing import Iterable

from pydantic import ValidationError

from ai.schemas.xss import XSSCase
from ai.schemas.xss_finding import XSSFinding
from ai.schemas.xss_verification import (
    AttemptStatus,
    ReflectionLocation,
    SourceToSinkStep,
    StoredXSSPhase,
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
    VerificationPlan,
    WAFObservation,
    WAFObservationKind,
    XSSVerificationAudit,
    XSSVerificationResult,
    build_verification_attempt,
)
from ai.verification import VerificationExecutor
from ai.researcher.xss_orchestrator import XSSAnalysisResult


# Statuses that may produce an XSSFinding. INCONCLUSIVE is
# recorded in the audit only, never as a finding.
_PRODUCES_FINDING_STATUSES = frozenset({"POTENTIAL", "CONFIRMED"})


# Reflection locations that count as "meaningful" for the
# POTENTIAL path. Plain HTML_BODY reflection (escaped or
# inert) is a separate, weaker condition; it is recorded
# but does not on its own yield POTENTIAL.
_MEANINGFUL_REFLECTION_LOCATIONS = frozenset(
    {
        ReflectionLocation.HTML_ATTRIBUTE,
        ReflectionLocation.JAVASCRIPT_STRING,
        ReflectionLocation.SCRIPT_BLOCK,
        ReflectionLocation.URL,
    }
)


# Deterministic, documented confidence mapping. The
# existing XSSFinding.confidence field has no documented
# semantics; this is the smallest deterministic mapping
# that reflects how strong the evidence is. The mapping is
# intentionally conservative: CONFIRMED is high but not
# 1.0 to leave headroom for "we were wrong", and
# INCONCLUSIVE is low because the verifier could not prove
# the case either way.
_STATUS_TO_CONFIDENCE: dict[str, float] = {
    "CONFIRMED": 0.95,
    "POTENTIAL": 0.50,
    "INCONCLUSIVE": 0.20,
}


class XSSVerifier:
    """
    Deterministic, evidence-bound XSS verifier.

    The verifier consumes the orchestrator's
    :class:`XSSAnalysisResult`, builds a plan of
    :class:`VerificationAttempt`s from the LLM's payload
    candidates, runs them through an injected
    :class:`VerificationExecutor`, and produces zero or
    more :class:`XSSFinding`s. The verifier never:

    - calls an LLM,
    - accesses the network,
    - generates or synthesizes payloads,
    - trusts LLM-suggested case status or rationale,
    - trusts executor booleans for CONFIRMED.

    The executor is treated as an evidence provider, not
    as an authority. The executor can be buggy. The
    verifier rejects structurally inconsistent evidence
    independently of the executor's self-reported
    booleans.

    Status rules (status decision table):

    - ``POTENTIAL``: HTTP reflection at a meaningful
      location, AND the executor's
      ``observed_correlation_token`` matches the
      attempt's ``correlation_token`` string. No WAF
      block/transform. No stored-XSS round trip
      required (single observation is enough for
      POTENTIAL but never for CONFIRMED).
    - ``CONFIRMED`` (reflected): the above POTENTIAL
      conditions for the HTTP attempt AND a paired
      browser attempt (same ``logical_pair_id``) whose
      structured runtime channel contains the attempt's
      ``correlation_token`` string AND whose
      source-to-sink chain's parameter step binds
      exactly to ``attempt.parameter``,
      ``attempt.parameter_location``, and
      ``attempt.endpoint``. The HTTP and browser
      attempts must share ``method`` (enforced via the
      shared ``logical_pair_id``).
    - ``CONFIRMED`` (DOM): browser attempt only. The
      case's ``xss_type`` is ``"dom"`` and the plan
      builder does not create a paired HTTP attempt.
      The chain binding above and the structured
      runtime token observation are still required.
    - ``CONFIRMED`` (mutation): browser attempt only.
      The case's ``xss_type`` is ``"mutation"`` and the
      plan builder does not create a paired HTTP
      attempt. The same browser preconditions as DOM
      apply.
    - ``CONFIRMED`` (stored): a paired HTTP attempt
      (same ``logical_pair_id``) whose evidence
      satisfies ``_http_path_confirms``, AND SUBMIT and
      READ phase observations in the stored browser
      evidence with matching observed correlation tokens
      equal to the stored attempt's
      ``correlation_token``, AND the browser runtime
      independently observed the token in a structured
      channel. A single stored observation yields at
      most ``POTENTIAL``.
    - ``INCONCLUSIVE``: any other combination. This
      includes transport failure, executor error,
      evidence-attempt binding mismatch, WAF block or
      transform, executor-reported reflection without
      independent token match, browser execution
      without an independently observable correlation
      token, DOM/mutation execution without the browser
      preconditions, reflected execution with no
      matching HTTP pair, and stored XSS without a
      complete round trip.

    ``NOT_VULNERABLE`` is NEVER produced. The current
    evidence schema does not capture the structured
    two-control observations that a reliable negative
    result would require. A future schema extension can
    introduce ``NOT_VULNERABLE``; today, the verifier
    returns ``INCONCLUSIVE`` when no positive evidence
    is found.
    """

    def __init__(self, executor: VerificationExecutor) -> None:
        if executor is None or not hasattr(executor, "execute"):
            raise TypeError(
                "executor must implement VerificationExecutor.execute"
            )
        self.executor = executor

    def verify(
        self,
        analysis: XSSAnalysisResult,
        *,
        plan: VerificationPlan | None = None,
    ) -> XSSVerificationResult:
        # Defensive deep copies of the inputs the verifier
        # receives, consistent with the orchestrator's H1
        # pattern. The verifier does not mutate any field of
        # the analysis it was handed.
        owned_analysis_context = analysis.context.model_copy(
            deep=True
        )
        owned_analysis_llm = analysis.llm_result.model_copy(
            deep=True
        )
        owned_case = analysis.case.model_copy(deep=True)
        owned_analysis = XSSAnalysisResult(
            case=owned_case,
            context=owned_analysis_context,
            llm_result=owned_analysis_llm,
            stage=analysis.stage,
            audit=analysis.audit.model_copy(deep=True),
        )

        chosen_plan = plan or self._build_plan_from_analysis(
            owned_analysis
        )

        # First pass: execute every attempt and assemble a
        # by-attempt_id evidence map. Browser classification
        # needs to look up the HTTP attempt/evidence for the
        # same logical_pair_id; the map is the only way to
        # find that pair without trusting list position.
        evidence_by_attempt: dict[str, VerificationEvidence] = {}
        for attempt in chosen_plan.attempts:
            evidence = self._safe_execute(attempt)
            evidence = self._enforce_evidence_binding(
                attempt, evidence
            )
            evidence_by_attempt[attempt.attempt_id] = evidence

        evidence_list = [
            evidence_by_attempt[a.attempt_id]
            for a in chosen_plan.attempts
        ]

        # Pre-compute the HTTP attempt and evidence for every
        # logical pair. The browser path uses these to
        # enforce HTTP/browser pairing for reflected XSS.
        # The maps are keyed by ``logical_pair_id`` and
        # only populated for plans where the HTTP attempt
        # exists (DOM and mutation have no HTTP attempt, so
        # the lookup returns ``None``). Pairing is by
        # ``logical_pair_id`` only; list position is never
        # used.
        http_evidence_by_pair: dict[str, VerificationEvidence] = {}
        http_attempt_by_pair: dict[str, VerificationAttempt] = {}
        for attempt in chosen_plan.attempts:
            if attempt.mode != VerificationMode.HTTP_REFLECTION:
                continue
            existing = http_evidence_by_pair.get(
                attempt.logical_pair_id
            )
            # If two HTTP attempts share a logical pair
            # (which should not happen in the current plan
            # builder) prefer the one that confirms; this is
            # a safety net, not a primary signal.
            candidate = evidence_by_attempt[attempt.attempt_id]
            if existing is None or self._http_path_confirms(
                attempt=attempt, evidence=candidate
            ):
                http_evidence_by_pair[attempt.logical_pair_id] = (
                    candidate
                )
                http_attempt_by_pair[attempt.logical_pair_id] = (
                    attempt
                )

        case_xss_type = (owned_case.xss_type or "").strip().lower()

        findings: list[XSSFinding] = []
        for attempt in chosen_plan.attempts:
            evidence = evidence_by_attempt[attempt.attempt_id]
            paired_http_evidence = (
                http_evidence_by_pair.get(attempt.logical_pair_id)
                if attempt.mode == VerificationMode.BROWSER_EXECUTION
                else None
            )
            paired_http_attempt = (
                http_attempt_by_pair.get(attempt.logical_pair_id)
                if attempt.mode == VerificationMode.BROWSER_EXECUTION
                else None
            )
            status = self._classify(
                attempt=attempt,
                evidence=evidence,
                case_xss_type=case_xss_type,
                paired_http_evidence=paired_http_evidence,
                paired_http_attempt=paired_http_attempt,
            )
            if status in _PRODUCES_FINDING_STATUSES:
                findings.append(
                    self._build_finding(
                        case=owned_case,
                        attempt=attempt,
                        evidence=evidence,
                        status=status,
                    )
                )

        audit = self._build_audit(evidence_list, chosen_plan)

        return XSSVerificationResult(
            case_id=owned_case.case_id,
            attempts=list(chosen_plan.attempts),
            evidence=evidence_list,
            findings=findings,
            audit=audit,
        )

    def _build_plan_from_analysis(
        self,
        analysis: XSSAnalysisResult,
    ) -> VerificationPlan:
        """
        Build a plan from the orchestrator's LLM payload
        candidates. One HTTP-reflection attempt and one
        browser-execution attempt per LLM payload. The
        case's xss_type influences mode selection: DOM and
        mutation cases rely on browser execution, so the
        HTTP reflection attempt is skipped for them.

        For ``xss_type == "stored"`` the browser attempt is
        built with ``phase="stored"`` from the start, so
        its ``attempt_id`` and ``correlation_token`` are
        derived against the final phase and are internally
        self-consistent.

        Note: ``verification_ideas`` are NOT turned into
        attempts. The verifier cannot safely derive an
        attempt from a free-form verification idea; these
        remain research metadata for the orchestrator.
        """

        case = analysis.case
        xss_type = (case.xss_type or "").strip().lower()
        is_dom_flavour = xss_type in {"dom", "mutation"}
        is_stored = xss_type == "stored"

        attempts: list[VerificationAttempt] = []
        for suggested in analysis.llm_result.suggested_payloads:
            if not is_dom_flavour:
                attempts.append(
                    build_verification_attempt(
                        case_id=case.case_id,
                        endpoint=case.endpoint,
                        method=case.method,
                        parameter=case.parameter,
                        parameter_location=(
                            case.parameter_location
                        ),
                        payload=suggested.pattern,
                        payload_origin=suggested.origin,
                        knowledge_ids=list(
                            suggested.knowledge_ids
                        ),
                        source_ids=list(suggested.source_ids),
                        based_on_pattern=suggested.based_on_pattern,
                        mode=VerificationMode.HTTP_REFLECTION,
                        phase="http",
                    )
                )
            # Stored XSS uses phase="stored" for the browser
            # attempt from the start, so the attempt_id and
            # correlation_token are derived against the
            # final phase.
            browser_phase = "stored" if is_stored else "browser"
            attempts.append(
                build_verification_attempt(
                    case_id=case.case_id,
                    endpoint=case.endpoint,
                    method=case.method,
                    parameter=case.parameter,
                    parameter_location=(
                        case.parameter_location
                    ),
                    payload=suggested.pattern,
                    payload_origin=suggested.origin,
                    knowledge_ids=list(
                        suggested.knowledge_ids
                    ),
                    source_ids=list(suggested.source_ids),
                    based_on_pattern=suggested.based_on_pattern,
                    mode=VerificationMode.BROWSER_EXECUTION,
                    phase=browser_phase,
                )
            )

        return VerificationPlan(attempts=attempts)

    def _safe_execute(
        self,
        attempt: VerificationAttempt,
    ) -> VerificationEvidence:
        try:
            raw = self.executor.execute(attempt)
        except ValidationError as exc:
            return self._error_evidence(attempt, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._error_evidence(attempt, repr(exc))

        # The executor may return a dict (legacy) or a
        # fully-constructed VerificationEvidence. The
        # verifier requires the structured model; if the
        # executor returns anything else, treat the attempt
        # as an executor error.
        if not isinstance(raw, VerificationEvidence):
            return self._error_evidence(
                attempt,
                "executor returned a non-VerificationEvidence "
                f"object: {type(raw).__name__}",
            )
        return raw

    @staticmethod
    def _enforce_evidence_binding(
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
    ) -> VerificationEvidence:
        """
        Verify that the evidence's identifiers match the
        attempt that was issued. A mismatch means the
        executor returned evidence for a different attempt
        (or fabricated identifiers); such evidence cannot
        produce a CONFIRMED verdict. The verifier downgrades
        the evidence to ERROR rather than trusting it.

        The phase field is NOT part of the binding: phase
        is metadata, not a security boundary.
        """

        mismatches: list[str] = []
        if evidence.attempt_id != attempt.attempt_id:
            mismatches.append(
                f"attempt_id:{evidence.attempt_id!r}!="
                f"{attempt.attempt_id!r}"
            )
        if evidence.request_url != attempt.endpoint:
            mismatches.append(
                f"request_url:{evidence.request_url!r}!="
                f"{attempt.endpoint!r}"
            )
        if evidence.request_method != attempt.method:
            mismatches.append(
                f"request_method:{evidence.request_method!r}!="
                f"{attempt.method!r}"
            )
        if mismatches:
            return XSSVerifier._error_evidence(
                attempt,
                "evidence_attempt_binding_mismatch: "
                + "; ".join(mismatches),
            )
        return evidence

    @staticmethod
    def _error_evidence(
        attempt: VerificationAttempt,
        reason: str,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=AttemptStatus.ERROR,
            request_url=attempt.endpoint,
            request_method=attempt.method,
            request_headers_redacted={},
            response_status=None,
            response_headers_redacted={},
            response_body_truncated=None,
            waf_observations=[],
            error_reason=reason,
        )

    def _classify(
        self,
        *,
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
        case_xss_type: str,
        paired_http_evidence: VerificationEvidence | None = None,
        paired_http_attempt: VerificationAttempt | None = None,
    ) -> str:
        """
        Map (attempt, evidence) to a security status.

        The verifier treats the executor as an evidence
        provider, not as an authority. Booleans on the
        evidence schema are advisory; the verifier
        independently matches the attempt's
        ``correlation_token`` against
        ``observed_correlation_token`` and against the
        structured runtime channels.

        ``paired_http_evidence`` and ``paired_http_attempt``
        are the HTTP attempt/evidence for the same
        ``logical_pair_id`` (or ``None`` if no HTTP attempt
        exists for the pair, e.g. DOM XSS). For
        reflected/mutation XSS the browser CONFIRMED verdict
        requires both the browser preconditions and a
        confirming paired HTTP attempt/evidence.
        """

        # Rule 1: transport failures.
        if evidence.attempt_status in (
            AttemptStatus.TIMEOUT,
            AttemptStatus.ERROR,
            AttemptStatus.FAILED,
        ):
            return "INCONCLUSIVE"

        # WAF block / transform: the payload may never
        # have reached the server unmodified. Only
        # structured BLOCK/TRANSFORM observations force
        # INCONCLUSIVE; INFO is metadata.
        if evidence.attempt_status in (
            AttemptStatus.WAF_BLOCKED,
            AttemptStatus.WAF_TRANSFORMED,
        ):
            return "INCONCLUSIVE"
        for waf in evidence.waf_observations:
            if waf.kind in (
                WAFObservationKind.BLOCK,
                WAFObservationKind.TRANSFORM,
            ):
                return "INCONCLUSIVE"

        # From here the attempt must have succeeded.
        if evidence.attempt_status != AttemptStatus.SUCCEEDED:
            return "INCONCLUSIVE"

        # Rule 2: stored XSS requires a complete
        # SUBMIT/READ round trip with matching observed
        # correlation tokens equal to the attempt's
        # correlation_token. A single stored observation
        # cannot produce CONFIRMED.
        if (attempt.phase or "").strip().lower() == "stored":
            return self._classify_stored(
                attempt=attempt,
                evidence=evidence,
                case_xss_type=case_xss_type,
                paired_http_evidence=paired_http_evidence,
                paired_http_attempt=paired_http_attempt,
            )

        # Rule 3: DOM / mutation cases rely on the browser
        # path only. ``paired_http_evidence`` is None for
        # DOM cases (no HTTP attempt exists for the pair).
        if attempt.mode == VerificationMode.BROWSER_EXECUTION:
            return self._classify_browser(
                attempt=attempt,
                evidence=evidence,
                case_xss_type=case_xss_type,
                paired_http_evidence=paired_http_evidence,
                paired_http_attempt=paired_http_attempt,
            )

        # Rule 4: HTTP reflection path. POTENTIAL only
        # when reflection is meaningful AND the executor's
        # observed_correlation_token matches the attempt's
        # correlation_token. CONFIRMED is never produced
        # for an HTTP attempt; CONFIRMED requires the
        # paired browser attempt to also independently
        # confirm.
        if self._http_path_confirms(
            attempt=attempt, evidence=evidence
        ):
            return "POTENTIAL"
        return "INCONCLUSIVE"

    def _classify_browser(
        self,
        *,
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
        case_xss_type: str,
        paired_http_evidence: VerificationEvidence | None = None,
        paired_http_attempt: VerificationAttempt | None = None,
    ) -> str:
        """
        Browser classification.

        DOM and mutation XSS are browser-only: the case's
        ``xss_type`` is in ``{"dom", "mutation"}`` and the
        plan builder does not create a paired HTTP attempt.
        The browser path runs without an HTTP pair.

        All other xss_types (reflected and any other
        non-DOM/non-mutation) require a paired HTTP
        attempt and evidence that share the same
        ``logical_pair_id``, AND the HTTP evidence must
        satisfy ``_http_path_confirms``. Without the
        pair, the browser evidence alone can never
        produce CONFIRMED.
        """

        normalized_xss_type = (case_xss_type or "").strip().lower()
        is_dom_flavour = normalized_xss_type in {"dom", "mutation"}

        if not is_dom_flavour:
            # Reflected and other non-DOM/non-mutation cases
            # require a paired HTTP attempt/evidence. The
            # paired values were looked up by
            # ``logical_pair_id`` in ``verify()``; their
            # absence here means the plan has no matching
            # HTTP attempt, which the verifier treats as
            # INCONCLUSIVE.
            if (
                paired_http_attempt is None
                or paired_http_evidence is None
            ):
                return "INCONCLUSIVE"
            if not self._http_path_confirms(
                attempt=paired_http_attempt,
                evidence=paired_http_evidence,
            ):
                return "INCONCLUSIVE"

        ok, _reason = self._browser_preconditions_met(
            attempt=attempt, evidence=evidence
        )
        if not ok:
            return "INCONCLUSIVE"
        return "CONFIRMED"

    def _browser_preconditions_met(
        self,
        *,
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
    ) -> tuple[bool, str]:
        """
        Evaluate every browser-path precondition in one
        place and return ``(ok, reason)``. The decision
        table is single-source-of-truth; ``_classify_browser``
        is a thin wrapper. The order is:

        1. Browser evidence is present.
        2. The source-to-sink chain structurally binds to
           the attempt (parameter name, location, endpoint).
        3. The correlation token is independently observed
           in a structured runtime channel.
        4. The executor's structured observed_correlation_token
           matches the attempt's token exactly.

        A failure at any step yields ``(False, reason)``.
        The reason is informational; the verdict is
        INCONCLUSIVE regardless.
        """

        browser = evidence.browser
        if browser is None:
            return False, "no browser observation"

        if not self._chain_attempt_bound(
            chain=browser.source_to_sink, attempt=attempt
        ):
            return False, "chain not bound to attempt"

        if not self._runtime_token_observed(
            token=attempt.correlation_token,
            browser=browser,
        ):
            return False, "token not in runtime channel"

        if not self._token_matches(
            expected=attempt.correlation_token,
            observed=browser.observed_correlation_token,
        ):
            return (
                False,
                "browser.observed_correlation_token does not "
                "match attempt.correlation_token",
            )

        return True, "ok"

    def _classify_stored(
        self,
        *,
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
        case_xss_type: str,
        paired_http_evidence: VerificationEvidence | None = None,
        paired_http_attempt: VerificationAttempt | None = None,
    ) -> str:
        """
        Stored XSS classification.

        The stored plan builder creates the browser attempt
        with ``phase="stored"`` from the start, so its
        ``attempt_id`` and ``correlation_token`` are
        derived against the final phase and are
        internally self-consistent.

        CONFIRMED requires:

        1. A paired HTTP attempt and evidence were issued
           for the same ``logical_pair_id`` AND the HTTP
           evidence satisfies ``_http_path_confirms`` for
           the paired HTTP attempt. The check is on the
           HTTP attempt/evidence, NEVER on the stored
           browser attempt/evidence.
        2. A SUBMIT phase observation and a READ phase
           observation, both referring to the same
           attempt_id, both with
           ``observed_correlation_token`` equal to the
           attempt's correlation_token.
        3. The browser runtime independently observed the
           correlation_token in a structured channel.

        Otherwise, at most POTENTIAL. A single stored
        observation can never produce CONFIRMED.
        """

        if (
            paired_http_attempt is None
            or paired_http_evidence is None
        ):
            return "INCONCLUSIVE"

        # The HTTP check is on the PAIRED HTTP attempt and
        # PAIRED HTTP evidence, never on the stored
        # browser attempt/evidence. The stored browser
        # attempt's correlation_token differs from the
        # paired HTTP attempt's correlation_token by
        # construction, and the browser evidence's
        # ``reflection`` field is not the HTTP-side
        # reflection.
        if not self._http_path_confirms(
            attempt=paired_http_attempt,
            evidence=paired_http_evidence,
        ):
            # For stored XSS, a single observation can
            # still be POTENTIAL if the HTTP path confirms.
            return "INCONCLUSIVE"

        phases = evidence.stored_phases
        submit = [
            p
            for p in phases
            if p.phase == StoredXSSPhase.SUBMIT
            and p.attempt_id == attempt.attempt_id
        ]
        read = [
            p
            for p in phases
            if p.phase == StoredXSSPhase.READ
            and p.attempt_id == attempt.attempt_id
        ]
        if not submit or not read:
            # Single-phase observation: at most POTENTIAL.
            return "POTENTIAL"

        if not all(
            self._token_matches(
                expected=attempt.correlation_token,
                observed=p.observed_correlation_token,
            )
            for p in (submit + read)
        ):
            return "POTENTIAL"

        if evidence.browser is not None and not self._runtime_token_observed(
            token=attempt.correlation_token,
            browser=evidence.browser,
        ):
            return "POTENTIAL"

        return "CONFIRMED"

    def _http_path_confirms(
        self,
        *,
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
    ) -> bool:
        """
        The single-source-of-truth HTTP-side check. A
        meaningful reflection AND the executor's
        observed_correlation_token matches the attempt's
        correlation_token. Both plain HTTP classification
        and stored XSS classification route through this
        predicate so the rule cannot drift between paths.
        """

        if not evidence.reflection.reflected:
            return False
        if (
            evidence.reflection.location
            not in _MEANINGFUL_REFLECTION_LOCATIONS
        ):
            return False
        return self._token_matches(
            expected=attempt.correlation_token,
            observed=evidence.reflection.observed_correlation_token,
        )

    @staticmethod
    def _token_matches(
        *,
        expected: str,
        observed: str | None,
    ) -> bool:
        """
        Compare the attempt's correlation token against
        the executor's observed value. Exact string
        equality only. The executor is untrusted; the
        verifier does not normalise, lowercase, or
        otherwise massage either value.
        """

        if observed is None:
            return False
        return observed == expected

    @staticmethod
    def _runtime_token_observed(
        *,
        token: str,
        browser,
    ) -> bool:
        """
        The verifier independently matches the attempt's
        correlation token in a structured runtime channel
        (``dom_changes``, ``console_messages``,
        ``network_requests``, ``storage_writes``).

        The token must be a complete substring of an entry
        in at least one channel. Searching the executor's
        self-reported booleans is not sufficient.
        """

        if not token:
            return False
        channels = (
            browser.dom_changes,
            browser.console_messages,
            browser.network_requests,
            browser.storage_writes,
        )
        for channel in channels:
            for entry in channel:
                if isinstance(entry, str) and token in entry:
                    return True
        return False

    @staticmethod
    def _chain_attempt_bound(
        *,
        chain: list[SourceToSinkStep],
        attempt: VerificationAttempt,
    ) -> bool:
        """
        A source-to-sink chain is only valid for the
        attempt under verification when the chain's
        parameter step binds exactly to
        ``attempt.parameter``,
        ``attempt.parameter_location``, and
        ``attempt.endpoint``. The verifier does not rely
        on free-form descriptions.

        The chain must additionally satisfy the structural
        rule :meth:`SourceToSinkStep.is_well_formed_chain`
        (the schema validator enforces the same rule at
        construction time; this is a defence-in-depth
        re-check).
        """

        if not SourceToSinkStep.is_well_formed_chain(chain):
            return False
        parameter_step = chain[0]
        if parameter_step.kind != "parameter":
            return False
        if parameter_step.parameter_name != attempt.parameter:
            return False
        if (
            parameter_step.parameter_location
            != attempt.parameter_location
        ):
            return False
        if parameter_step.endpoint != attempt.endpoint:
            return False
        return True

    def _build_finding(
        self,
        *,
        case: XSSCase,
        attempt: VerificationAttempt,
        evidence: VerificationEvidence,
        status: str,
    ) -> XSSFinding:
        confidence = _STATUS_TO_CONFIDENCE[status]

        waf_obs = [
            f"{w.kind.value}:{w.note}" for w in evidence.waf_observations
        ]

        reflection_evidence: list[str] = []
        if evidence.reflection.reflected:
            reflection_evidence.append(
                f"reflected={evidence.reflection.location.value} "
                f"matched_correlation_token="
                f"{evidence.reflection.matched_correlation_token}"
            )
            if (
                evidence.reflection.observed_correlation_token
                is not None
            ):
                reflection_evidence.append(
                    "observed_correlation_token="
                    f"{evidence.reflection.observed_correlation_token!r}"
                )
            if evidence.reflection.context_before is not None:
                reflection_evidence.append(
                    "context_before="
                    f"{evidence.reflection.context_before!r}"
                )
            if evidence.reflection.context_after is not None:
                reflection_evidence.append(
                    "context_after="
                    f"{evidence.reflection.context_after!r}"
                )

        verification_evidence: list[str] = []
        verification_evidence.append(
            f"attempt_id={attempt.attempt_id} "
            f"mode={attempt.mode.value} "
            f"attempt_status={evidence.attempt_status.value}"
        )
        if evidence.browser is not None:
            browser = evidence.browser
            verification_evidence.append(
                f"browser.executed_script={browser.executed_script} "
                f"browser.correlation_token_in_runtime="
                f"{browser.correlation_token_in_runtime}"
            )
            if browser.observed_correlation_token is not None:
                verification_evidence.append(
                    "browser.observed_correlation_token="
                    f"{browser.observed_correlation_token!r}"
                )
            if browser.source_to_sink:
                kinds = [step.kind for step in browser.source_to_sink]
                verification_evidence.append(
                    f"browser.source_to_sink_kinds="
                    f"{','.join(kinds)}"
                )
        if evidence.stored_phases:
            verification_evidence.append(
                "stored_phases="
                f"{','.join(p.phase.value for p in evidence.stored_phases)}"
            )

        knowledge_refs: list[str] = []
        if attempt.payload_origin == "knowledge":
            knowledge_refs.extend(attempt.knowledge_ids)
        # model_generated items carry no knowledge
        # attribution by design.

        # finding_id is deterministic: SHA-256 of
        # case_id + attempt_id + status.
        finding_id = self._deterministic_finding_id(
            case_id=case.case_id,
            attempt_id=attempt.attempt_id,
            status=status,
        )

        return XSSFinding(
            finding_id=finding_id,
            case_id=case.case_id,
            target=case.target,
            endpoint=case.endpoint,
            method=case.method,
            parameter=attempt.parameter,
            parameter_location=attempt.parameter_location,
            xss_type=case.xss_type,
            context_type=case.context.type,
            status=status,
            confidence=confidence,
            payload_reference=attempt.payload,
            verification_mode=attempt.mode.value,
            attempt_id=attempt.attempt_id,
            reflection_evidence=reflection_evidence,
            verification_evidence=verification_evidence,
            browser_verified=(
                evidence.browser is not None
                and evidence.browser.executed_script
            ),
            waf_observations=waf_obs,
            knowledge_references=knowledge_refs,
            remediation_notes=[],
        )

    @staticmethod
    def _deterministic_finding_id(
        *,
        case_id: str,
        attempt_id: str,
        status: str,
    ) -> str:
        digest = hashlib.sha256(
            f"{case_id}|{attempt_id}|{status}".encode("utf-8")
        ).hexdigest()
        return "xf-" + digest[:32]

    def _build_audit(
        self,
        evidence_list: Iterable[VerificationEvidence],
        plan: VerificationPlan,
    ) -> XSSVerificationAudit:
        succeeded = 0
        failed = 0
        timeout = 0
        waf_blocked = 0
        waf_transformed = 0
        error = 0
        has_browser = False
        has_reflection = False

        for evidence in evidence_list:
            status = evidence.attempt_status
            if status == AttemptStatus.SUCCEEDED:
                succeeded += 1
            elif status == AttemptStatus.FAILED:
                failed += 1
            elif status == AttemptStatus.TIMEOUT:
                timeout += 1
            elif status == AttemptStatus.WAF_BLOCKED:
                waf_blocked += 1
            elif status == AttemptStatus.WAF_TRANSFORMED:
                waf_transformed += 1
            elif status == AttemptStatus.ERROR:
                error += 1
            if (
                evidence.browser is not None
                and evidence.browser.executed_script
            ):
                has_browser = True
            if evidence.reflection.reflected:
                has_reflection = True

        notes: list[str] = []
        if not plan.attempts:
            notes.append(
                "no_attempts: orchestrator produced no "
                "payload candidates."
            )

        return XSSVerificationAudit(
            attempt_count=len(plan.attempts),
            succeeded_count=succeeded,
            failed_count=failed,
            timeout_count=timeout,
            waf_blocked_count=waf_blocked,
            waf_transformed_count=waf_transformed,
            error_count=error,
            has_browser_execution_evidence=has_browser,
            has_reflection_evidence=has_reflection,
            notes=notes,
        )


__all__ = [
    "XSSVerifier",
]
