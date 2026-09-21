"""Typed refusal/reason vocabulary for the AEC-1 pilot selector.

The exclusion vocabulary is a **closed set**: every excluded case carries
exactly one reason code from :data:`EXCLUSION_REASONS`, and nothing else is
representable. Codes are grouped into:

- :data:`PLAN_REASONS` — the ten codes fixed by ``AEC-1_IMPLEMENTATION_PLAN.md``.
- :data:`EXTENDED_REASONS` — four codes added by T1 because the plan's ten
  cannot express every real outcome in the corpus. Each is documented in
  :data:`REASON_DESCRIPTIONS` and called out in the T1 report.

Evaluation order is fixed (:data:`PRECLASSIFY_ORDER` then
:data:`SELECTION_ORDER`) so that a case's reason is deterministic and the
safety-shaped refusals always win over convenience-shaped ones.
"""

from __future__ import annotations

SELECTED = "SELECTED"

#: The ten exclusion codes fixed by the AEC-1 implementation plan (§6, T1).
PLAN_REASONS = (
    "CHALLENGE_TOKEN",
    "AUTH_REQUIRED",
    "LOGIN_ENDPOINT",
    "NON_GET_METHOD",
    "BODY_REQUIRED",
    "UPLOAD_CATEGORY",
    "OUT_OF_SCOPE_HOST",
    "HOST_BUDGET_FULL",
    "DUPLICATE_ENDPOINT",
    "NOT_COMPARABLE",
)

#: Deliberate, documented extensions required by the real corpus.
EXTENDED_REASONS = (
    "CATEGORY_OUT_OF_PILOT",
    "FAMILY_CAP_FULL",
    "HOST_SET_FULL",
    "PILOT_CAP_FULL",
)

EXCLUSION_REASONS = PLAN_REASONS + EXTENDED_REASONS

REASON_DESCRIPTIONS = {
    "CHALLENGE_TOKEN": (
        "Parameter is a bot-management / challenge token. Contacting it would "
        "probe a protection mechanism and cannot produce research evidence."
    ),
    "AUTH_REQUIRED": (
        "Parameter or endpoint is consistent with a session, credential or "
        "identity context. The pilot holds no identity and must not acquire "
        "one (Phase 2 owns identity custody)."
    ),
    "LOGIN_ENDPOINT": (
        "Endpoint is a login / account / SSO / authorization surface. The "
        "pilot never touches authentication surfaces."
    ),
    "NON_GET_METHOD": (
        "Case is not a GET (GET and HEAD are the only methods the pilot may "
        "use). State-changing methods are out of scope."
    ),
    "BODY_REQUIRED": (
        "The parameter is delivered in the request body. The pilot sends no "
        "bodies."
    ),
    "UPLOAD_CATEGORY": (
        "File-upload candidate. The pilot never uploads anything."
    ),
    "OUT_OF_SCOPE_HOST": (
        "Host is outside the program scope, matches an out-of-scope entry, or "
        "its program is unknown (deny by default)."
    ),
    "HOST_BUDGET_FULL": (
        "Per-host request budget for this host is already fully allocated by "
        "higher-priority cases."
    ),
    "DUPLICATE_ENDPOINT": (
        "Another selector-identical case (same host, endpoint and parameter) "
        "was already selected; one comparison per endpoint is enough."
    ),
    "NOT_COMPARABLE": (
        "The case carries no comparable input dimension (no parameter, or the "
        "parameter cannot take two distinct safe values)."
    ),
    "CATEGORY_OUT_OF_PILOT": (
        "The case does not belong to any of the three pilot families "
        "(IDOR wp-json resource, SSRF oEmbed proxy, reflected XSS query)."
    ),
    "FAMILY_CAP_FULL": (
        "The case's pilot family has already reached its cap."
    ),
    "HOST_SET_FULL": (
        "The pilot's distinct-host set is already full; a new host cannot be "
        "added."
    ),
    "PILOT_CAP_FULL": (
        "The global case budget is already fully allocated."
    ),
}

#: Pre-classification (per case, independent of selection state) — first match wins.
PRECLASSIFY_ORDER = (
    "CHALLENGE_TOKEN",
    "LOGIN_ENDPOINT",
    "AUTH_REQUIRED",
    "BODY_REQUIRED",
    "NON_GET_METHOD",
    "UPLOAD_CATEGORY",
    "OUT_OF_SCOPE_HOST",
    "NOT_COMPARABLE",
    "CATEGORY_OUT_OF_PILOT",
)

#: Selection-phase (depends on what has already been chosen) — first match wins.
SELECTION_ORDER = (
    "DUPLICATE_ENDPOINT",
    "FAMILY_CAP_FULL",
    "HOST_BUDGET_FULL",
    "HOST_SET_FULL",
    "PILOT_CAP_FULL",
)


class SelectionError(ValueError):
    """AEC-1 selector misuse or unsafe output target (sanitized message)."""


__all__ = [
    "EXCLUSION_REASONS",
    "EXTENDED_REASONS",
    "PLAN_REASONS",
    "PRECLASSIFY_ORDER",
    "REASON_DESCRIPTIONS",
    "SELECTED",
    "SELECTION_ORDER",
    "SelectionError",
]
