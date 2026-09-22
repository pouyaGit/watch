"""Observation type registry + plan validation (Phases 5, 7, 16).

Only observation types the existing codebase actually supports appear
here — the registry is the single authority the planner and the LLM
advisor are validated against. Every type maps to an existing read-only
boundary:

  url/parameter/endpoint/http/header rows -> ReadStoreObservations
  kb-rows                                 -> KnowledgeLoader (bounded KB)

Registry duties:
  * describe authorization, scope, inputs/outputs, evidence, risk/cost;
  * validate a full observation request (unknown type, wrong capability,
    missing inputs => rejection with reasons);
  * scan advisory text for forbidden actions (exploit/shell/code/network
    execution instructions) so planner advice can never smuggle one in.

This module performs no I/O and never executes anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

REGISTRY_RULE_VERSION = "hunt-observation-registry-v1"


@dataclass(frozen=True)
class ObservationType:
    observation_type: str
    description: str
    required_authorization: str
    allowed_scope: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    evidence_produces: tuple[str, ...]
    risk_class: str            # READ_ONLY for every type, by construction
    cost_class: str            # LOW | MEDIUM
    prerequisites: tuple[str, ...]
    executes_http: bool = False   # False for every type (store reads only)
    requires_query: bool = False  # kb-rows: bounded KB query terms

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_type": self.observation_type,
            "description": self.description,
            "required_authorization": self.required_authorization,
            "allowed_scope": self.allowed_scope,
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "evidence_produces": list(self.evidence_produces),
            "risk_class": self.risk_class,
            "cost_class": self.cost_class,
            "prerequisites": list(self.prerequisites),
        }


_SCOPE_PREREQ = ("watch_scope_authorized",)
_STORE_PREREQ = _SCOPE_PREREQ + ("observation_store_available",)

REGISTRY: dict[str, ObservationType] = {
    t.observation_type: t for t in (
        ObservationType(
            observation_type="url-rows",
            description=("bounded read of stored URL rows (path, status, "
                         "declared parameters) for the authorized scope"),
            required_authorization="watch:scope",
            allowed_scope="job.authorization_ref",
            inputs=("subdomain", "limit"),
            outputs=("urls_rows",),
            evidence_produces=("observation",),
            risk_class="READ_ONLY",
            cost_class="LOW",
            prerequisites=_STORE_PREREQ,
        ),
        ObservationType(
            observation_type="parameter-rows",
            description=("bounded read of stored parameter inventories from "
                         "URL and endpoint rows for the authorized scope"),
            required_authorization="watch:scope",
            allowed_scope="job.authorization_ref",
            inputs=("subdomain", "limit"),
            outputs=("parameter_rows",),
            evidence_produces=("observation",),
            risk_class="READ_ONLY",
            cost_class="LOW",
            prerequisites=_STORE_PREREQ,
        ),
        ObservationType(
            observation_type="endpoint-rows",
            description=("bounded read of stored endpoint rows (path, "
                         "example URL, parameters) for the authorized scope"),
            required_authorization="watch:scope",
            allowed_scope="job.authorization_ref",
            inputs=("subdomain", "limit"),
            outputs=("endpoint_rows",),
            evidence_produces=("observation",),
            risk_class="READ_ONLY",
            cost_class="LOW",
            prerequisites=_STORE_PREREQ,
        ),
        ObservationType(
            observation_type="http-rows",
            description=("bounded read of stored HTTP observation rows "
                         "(status, title, technology signal, sanitized "
                         "header excerpt) for the authorized scope"),
            required_authorization="watch:scope",
            allowed_scope="job.authorization_ref",
            inputs=("subdomain", "limit"),
            outputs=("http_rows", "technology_signals"),
            evidence_produces=("observation",),
            risk_class="READ_ONLY",
            cost_class="LOW",
            prerequisites=_STORE_PREREQ,
        ),
        ObservationType(
            observation_type="header-rows",
            description=("bounded read of stored response-header excerpts "
                         "(sensitive headers already scrubbed at the "
                         "boundary) for the authorized scope"),
            required_authorization="watch:scope",
            allowed_scope="job.authorization_ref",
            inputs=("subdomain", "limit"),
            outputs=("header_rows",),
            evidence_produces=("observation",),
            risk_class="READ_ONLY",
            cost_class="LOW",
            prerequisites=_STORE_PREREQ,
        ),
        ObservationType(
            observation_type="kb-rows",
            description=("bounded, query-scoped read of the existing "
                         "knowledge base (CVE/concept documents) — no "
                         "network, no target contact"),
            required_authorization="watch:scope",
            allowed_scope="job.authorization_ref",
            inputs=("query_hints", "limit"),
            outputs=("knowledge_docs",),
            evidence_produces=("knowledge",),
            risk_class="READ_ONLY",
            cost_class="MEDIUM",
            prerequisites=_SCOPE_PREREQ + ("knowledge_store_available",),
            requires_query=True,
        ),
    )
}

ALLOWED_TYPES: tuple[str, ...] = tuple(sorted(REGISTRY))

# Category -> observation types most likely to carry that category's
# structural signal (used by the missing-evidence engine and scoring).
CATEGORY_SIGNAL_TYPES: dict[str, tuple[str, ...]] = {
    "XSS": ("parameter-rows", "http-rows", "url-rows"),
    "CVE_RESEARCH": ("http-rows", "kb-rows"),
    "SSRF": ("parameter-rows", "endpoint-rows"),
    "SQLI": ("http-rows", "url-rows"),
    "IDOR": ("url-rows", "endpoint-rows"),
    "JWT": ("http-rows", "header-rows"),
    "OAUTH": ("url-rows", "http-rows"),
    "RECON": ("http-rows", "endpoint-rows", "url-rows"),
}

# ---------------------------------------------------- forbidden advisory
# Patterns that make advisory planner text unusable: it proposes (or
# contains) execution the planner must never express. Matched advisory
# is REJECTED wholesale and recorded — never executed, never planned.
FORBIDDEN_ADVISORY: tuple[tuple[str, re.Pattern], ...] = (
    ("EXPLOIT_INSTRUCTION",
     re.compile(r"(?i)\b(send|execute|run|craft|generate|inject|insert|"
                r"deliver|deploy|upload|fire|launch)\b[^.]{0,40}"
                r"\b(payloads?|exploits?|poc)\b"
                r"|\b(payloads?|exploits?)\b\s*"
                r"(code|string|generator|tool|testing harness)\b")),
    ("SHELL_INSTRUCTION",
     re.compile(r"(?i)\b(bash|sh\s+-c|shell|subprocess|os\.system|"
                r"popen|nc\s+-|netcat|ssh\s+)\b")),
    ("CODE_EXECUTION_INSTRUCTION",
     re.compile(r"(?i)\b(eval\s*\(|exec\s*\(|pickle\.loads|"
                r"__import__|compile\s*\()")),
    ("NETWORK_EXECUTION_INSTRUCTION",
     re.compile(r"(?i)\b(curl\s+|wget\s+|http\s*get\s+to\s+|"
                r"send\s+a\s+request\s+to\s+|make\s+a\s+request\s+to\s+|"
                r"fetch\s+https?://|probing|probe\s+the\s+target|"
                r"scan\s+the\s+target|nuclei|sqlmap|fuzz(er|ing)?\b|"
                r"brute[- ]?force)")),
    ("CREDENTIAL_INSTRUCTION",
     re.compile(r"(?i)\b(login\s+with|use\s+(the\s+)?password|"
                r"credentials?\s*[:=]|auth\s+token\s*[:=])")),
    ("FINDING_CLAIM",
     re.compile(r"(?i)\b(confirmed\s+vulnerable|is\s+vulnerable|"
                r"true\s+positive|severity\s*:|cvss\s*:)")),
)

# Explicit execution-boundary statement: no type may ever flip these.
EXECUTION_GUARANTEES: tuple[str, ...] = (
    "no_target_contact",
    "no_http_requests",
    "no_shell",
    "no_code_execution",
    "no_payloads",
    "scope_fixed_to_authorization_ref",
)


def scan_forbidden(texts: Iterable[str]) -> list[str]:
    """Return the codes of forbidden advisory content found in ``texts``."""
    hits: list[str] = []
    for text in texts:
        blob = str(text or "")
        for code, pattern in FORBIDDEN_ADVISORY:
            if pattern.search(blob) and code not in hits:
                hits.append(code)
    return hits


def validate_observation_requests(
    requests: Iterable[dict[str, Any]],
    *,
    allowed_for_capability: Iterable[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Deterministic plan-request validation.

    Returns ``(valid_requests, rejection_reasons)``. A request is valid
    only when its type is in the registry AND in the capability's
    allowlist, inputs are structurally supported, and the request never
    carries execution/scope fields. Unknown types are rejected — the
    planner cannot invent capabilities.
    """
    allowed = {str(t) for t in allowed_for_capability}
    valid: list[dict[str, Any]] = []
    reasons: list[str] = []
    for raw in list(requests)[:8]:
        if not isinstance(raw, dict):
            reasons.append("malformed_observation_request")
            continue
        otype = str(raw.get("observation_type") or "")
        spec = REGISTRY.get(otype)
        if spec is None:
            reasons.append(f"unknown_observation_type:{otype or 'empty'}")
            continue
        if otype not in allowed:
            reasons.append(
                f"observation_type_not_in_capability:{otype}")
            continue
        if spec.executes_http:
            reasons.append(f"type_requires_http_execution:{otype}")
            continue
        forbidden_fields = {"url", "host", "payload", "code", "shell",
                            "headers", "body", "method", "command"} & \
            {str(k).lower() for k in raw}
        if forbidden_fields:
            reasons.append(
                f"unsupported_input:{otype}:{sorted(forbidden_fields)[0]}")
            continue
        # normalize: only registry-supported keys survive
        cleaned = {
            "observation_type": otype,
            "inputs": {str(k): v for k, v in
                       dict(raw.get("inputs") or {}).items()
                       if str(k) in {"subdomain", "limit", "query_hints"}},
            "expected_evidence": str(raw.get("expected_evidence") or "")[:200],
            "missing_item_ids": [str(m)[:80] for m in
                                 (raw.get("missing_item_ids") or [])][:8],
            "risk_class": spec.risk_class,
        }
        if spec.requires_query:
            hints = [str(h)[:60] for h in
                     (cleaned["inputs"].get("query_hints") or [])][:6]
            if not hints:
                reasons.append(f"missing_inputs:{otype}:query_hints")
                continue
            cleaned["inputs"]["query_hints"] = hints
        valid.append(cleaned)
    return valid, reasons


def registry_catalog(types: Iterable[str] | None = None) -> list[dict]:
    wanted = [t for t in (types or ALLOWED_TYPES) if t in REGISTRY]
    return [REGISTRY[t].to_dict() for t in wanted]


__all__ = [
    "ALLOWED_TYPES",
    "CATEGORY_SIGNAL_TYPES",
    "EXECUTION_GUARANTEES",
    "FORBIDDEN_ADVISORY",
    "REGISTRY",
    "REGISTRY_RULE_VERSION",
    "ObservationType",
    "registry_catalog",
    "scan_forbidden",
    "validate_observation_requests",
]
