from __future__ import annotations

from typing import Protocol

from ai.schemas.xss_verification import (
    VerificationAttempt,
    VerificationEvidence,
)


class VerificationExecutor(Protocol):
    """
    Boundary between the XSSVerifier and the real world.

    The executor is the only component that performs HTTP
    fetches and browser-equivalent runtime work. The
    verifier never touches the network and never drives a
    browser directly. A real implementation lives outside
    the AI layer (browser automation, headless runtime,
    HTTP client); a fake implementation is used in unit
    tests.

    The executor is responsible for redacting request and
    response headers (``Cookie`` and ``Authorization``
    must not appear in the returned evidence) and for
    reporting any WAF observations it detected.
    """

    def execute(
        self,
        attempt: VerificationAttempt,
    ) -> VerificationEvidence: ...


from ai.schemas.xss_verification import (  # noqa: E402,F401
    AttemptStatus,
    BrowserExecutionObservation,
    ReflectionLocation,
    ReflectionObservation,
    SourceToSinkStep,
    StoredXSSPhase,
    StoredXSSPhaseObservation,
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
    VerificationPlan,
    WAFObservation,
    WAFObservationKind,
    XSSVerificationAudit,
    XSSVerificationResult,
    attempt_id_from_canonical,
    build_verification_attempt,
    correlation_token_from_attempt,
    logical_pair_id_from_canonical,
)

from ai.verification.composite_executor import (  # noqa: E402,F401
    CompositeVerificationExecutor,
)

from ai.verification.xss_pipeline import (  # noqa: E402,F401
    XSSVerificationPipeline,
    build_default_verifier,
)

from ai.verification.xss_case_builder import (  # noqa: E402,F401
    XSSCaseBuilder,
    get_domain_name as get_watch_domain_name,
)

__all__ = [
    "AttemptStatus",
    "BrowserExecutionObservation",
    "CompositeVerificationExecutor",
    "ReflectionLocation",
    "ReflectionObservation",
    "SourceToSinkStep",
    "StoredXSSPhase",
    "StoredXSSPhaseObservation",
    "VerificationAttempt",
    "VerificationEvidence",
    "VerificationExecutor",
    "VerificationMode",
    "VerificationPlan",
    "XSSCaseBuilder",
    "XSSVerificationPipeline",
    "WAFObservation",
    "WAFObservationKind",
    "XSSVerificationAudit",
    "XSSVerificationResult",
    "attempt_id_from_canonical",
    "build_default_verifier",
    "build_verification_attempt",
    "correlation_token_from_attempt",
    "logical_pair_id_from_canonical",
]
