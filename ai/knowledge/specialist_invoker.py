"""Stage R52.4 deterministic specialist invocation (pure engine).

Invokes the existing specialist research exports through their structured
Python APIs:

    "Run the selected specialist over the normalized structured context."

Hard boundaries encoded here:

- Orchestration only: this module calls the specialists' existing pure
  research pipelines. It copies no specialist logic, adds no network
  capability and imports no provider module.
- Static dispatch only: the invocation table is a closed mapping of canonical
  categories to already-imported pure functions. There is no plugin
  discovery, no dynamic import, no ``importlib`` and no runtime code loading.
- Structured output only: a specialist result is returned exactly as the
  specialist produced it (bounded by its own R39-R50 contract); failures
  raise instead of fabricating a result.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  shell, no browser, no scanner, no database, no wall-clock time, no
  randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.api_security_agent_result_export import (
    export_api_security_agent_result,
)
from ai.knowledge.cve_research_agent_result_export import (
    export_cve_research_agent_result,
)
from ai.knowledge.idor_bola_agent_result_export import (
    export_idor_bola_agent_result,
)
from ai.knowledge.jwt_authentication_agent_result_export import (
    export_jwt_authentication_agent_result,
)
from ai.knowledge.oauth_agent_result_export import export_oauth_agent_result
from ai.knowledge.specialist_registry import (
    SPECIALIST_CONTEXT_KEYS,
    specialist_agent_id,
    specialist_name,
)
from ai.knowledge.sqli_agent_result_export import export_sqli_agent_result
from ai.knowledge.ssrf_agent_result_export import export_ssrf_agent_result
from ai.knowledge.xss_agent_result_export import export_xss_agent_result
from ai.schemas.agent_orchestrator_context import (
    sanitize_orchestration_context,
)
from ai.schemas.agent_orchestrator_registry import (
    CANONICAL_SPECIALIST_ORDER,
)
from ai.schemas.agent_orchestrator_result import (
    SPECIALIST_RESULT_SANITIZERS,
)
from ai.schemas.security_agent_identity import (
    CATEGORY_CVE_RESEARCH,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_RECON,
    CATEGORY_SQLI,
    CATEGORY_SSRF,
    CATEGORY_XSS,
)

SPECIALIST_INVOKER_RULE_VERSION = "r52-4"
RULE_VERSION = SPECIALIST_INVOKER_RULE_VERSION


class SpecialistInvocationError(RuntimeError):
    """Structured, deterministic specialist invocation failure."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _context_kwargs(category: str, context: dict) -> dict:
    kwargs: dict = {}
    for key in SPECIALIST_CONTEXT_KEYS.get(category, ()):
        if key in context:
            kwargs[key] = context[key]
    return kwargs


def _invoke_xss(context: dict, **common: object) -> dict:
    return export_xss_agent_result(**common, **_context_kwargs("XSS", context))


def _invoke_ssrf(context: dict, **common: object) -> dict:
    return export_ssrf_agent_result(
        **common, **_context_kwargs("SSRF", context)
    )


def _invoke_sqli(context: dict, **common: object) -> dict:
    return export_sqli_agent_result(
        **common, **_context_kwargs("SQLI", context)
    )


def _invoke_idor(context: dict, **common: object) -> dict:
    return export_idor_bola_agent_result(
        **common, **_context_kwargs("IDOR", context)
    )


def _invoke_jwt(context: dict, **common: object) -> dict:
    return export_jwt_authentication_agent_result(
        **common, **_context_kwargs("JWT", context)
    )


def _invoke_oauth(context: dict, **common: object) -> dict:
    return export_oauth_agent_result(
        **common, **_context_kwargs("OAUTH", context)
    )


def _invoke_api_security(context: dict, **common: object) -> dict:
    return export_api_security_agent_result(
        **common, **_context_kwargs("RECON", context)
    )


def _invoke_cve_research(context: dict, **common: object) -> dict:
    return export_cve_research_agent_result(
        **common, **_context_kwargs("CVE_RESEARCH", context)
    )


#: Closed static dispatch table (no dynamic import / plugin discovery).
SPECIALIST_INVOKERS: dict = {
    CATEGORY_XSS: _invoke_xss,
    CATEGORY_SSRF: _invoke_ssrf,
    CATEGORY_SQLI: _invoke_sqli,
    CATEGORY_IDOR: _invoke_idor,
    CATEGORY_JWT: _invoke_jwt,
    CATEGORY_OAUTH: _invoke_oauth,
    CATEGORY_RECON: _invoke_api_security,
    CATEGORY_CVE_RESEARCH: _invoke_cve_research,
}


def invoke_specialist(
    category: object,
    context: object = None,
    security_agent_input: object = None,
    governance_plan: object = None,
) -> dict:
    """Invoke one specialist over the normalized context (read-only).

    Only the context keys the specialist's own analyzer consumes are passed;
    the specialist validates every value against its own closed vocabulary.
    A missing/invalid invocation or non-structured output raises
    :class:`SpecialistInvocationError`; no result is fabricated.
    """

    resolved = str(category if category is not None else "").strip().upper()
    if resolved not in CANONICAL_SPECIALIST_ORDER:
        raise SpecialistInvocationError(
            resolved, f"unknown specialist category: {category!r}"
        )
    invoker = SPECIALIST_INVOKERS.get(resolved)
    if invoker is None:
        raise SpecialistInvocationError(
            resolved, f"no invoker registered for: {resolved}"
        )
    bounded_context = sanitize_orchestration_context(context)
    try:
        result = invoker(
            bounded_context,
            agent_identity=None,
            security_agent_input=security_agent_input,
            governance_plan=governance_plan,
        )
    except SpecialistInvocationError:
        raise
    except Exception as exc:  # structured error, never a fabricated result
        raise SpecialistInvocationError(
            resolved, f"specialist execution failed: {type(exc).__name__}"
        ) from exc
    if not isinstance(result, dict) or not result:
        raise SpecialistInvocationError(
            resolved, "specialist returned a non-structured result"
        )
    sanitizer = SPECIALIST_RESULT_SANITIZERS.get(resolved)
    if sanitizer is not None and not sanitizer(result):
        raise SpecialistInvocationError(
            resolved, "specialist result failed its own contract"
        )
    return result


def specialist_identity_metadata(category: object) -> dict:
    """Return bounded identity metadata for provenance (no invention)."""

    resolved = str(category if category is not None else "").strip().upper()
    if resolved not in CANONICAL_SPECIALIST_ORDER:
        return {"category": resolved, "specialist_name": "", "agent_id": ""}
    return {
        "category": resolved,
        "specialist_name": specialist_name(resolved),
        "agent_id": specialist_agent_id(resolved),
    }


__all__ = [
    "SPECIALIST_INVOKER_RULE_VERSION",
    "RULE_VERSION",
    "SpecialistInvocationError",
    "SPECIALIST_INVOKERS",
    "invoke_specialist",
    "specialist_identity_metadata",
]
