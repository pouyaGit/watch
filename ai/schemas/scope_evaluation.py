"""ScopeEvaluation data contract (Phase 5D).

Position in the pipeline::

    IssuedExecutionAuthorization (5B, LIVE only)
        + TargetResolution (5C, immutable facts)
        + CompiledScopePolicy (fresh, hashed)
            |
            v
    ScopeEvaluator (ai/scope, this phase)
            |
            v
    ScopeEvaluation (immutable decision, this module)
            |
            v  (ALLOWED + id-triple only)
    future 5E/5F/5G transport

Trust semantics (normative per
``agent-reports/scope-evaluator-architecture.md``):

- A ``ScopeEvaluation`` with ``decision == ALLOWED`` means exactly:
  the 5C-resolved canonical target satisfies the freshly read,
  hash-bound program scope policy for the authorized program, with
  all pinned addresses dual-gated and every redirect hop
  independently evaluated. It is NOT a vulnerability verdict, NOT a
  finding, and NOT execution permission by itself (transport owns
  dial enforcement).
- ``DENIED`` is terminal for the evaluated target/hop. ``INCONCLUSIVE``
  means "cannot decide with the supplied observations" (e.g. a hop
  without address observations) and MUST be treated as
  non-authorizing by every consumer — it never permits transport.
- No verdict-shaped field may exist on any model in this module
  (``extra="forbid"`` enforces it structurally; tests enumerate the
  forbidden names, including boolean ``scope_allowed`` /
  ``execution_allowed`` aliases).

This module is PURE and DETERMINISTIC:

- NO network, NO DNS, NO subprocess, NO database, NO LLM, NO scope
  data fetching, NO execution, NO verification, NO findings.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.evidence.hashing import hash_payload
from ai.evidence.scrubber import contains_secret_shape

SCHEMA_VERSION = "scope_evaluation/v1"

EVALUATOR_VERSION = "scope-evaluator/v1"

ScopeDecision = Literal["ALLOWED", "DENIED", "INCONCLUSIVE"]

AddressVerdict = Literal["ALLOW", "DENY", "UNKNOWN"]

#: Closed failure vocabulary. Bounded, secret-free, single-line;
#: raw parser/network exceptions never escape through these codes.
ScopeFailureCode = Literal[
    "TARGET_NOT_CANONICAL",
    "PROGRAM_NOT_FOUND",
    "SCOPE_POLICY_MISSING",
    "SCOPE_POLICY_INVALID",
    "SCOPE_DRIFT",
    "TARGET_NOT_IN_SCOPE",
    "TARGET_EXCLUDED",
    "ADDRESS_NOT_IN_SCOPE",
    "UNSAFE_ADDRESS",
    "REDIRECT_NOT_IN_SCOPE",
    "REDIRECT_INVALID",
    "REDIRECT_LIMIT",
    "TARGET_BINDING_MISMATCH",
    "AUTHZ_BINDING_MISMATCH",
    "RESOLUTION_BINDING_MISMATCH",
    "DIAL_BINDING_MISMATCH",
    "AUTHZ_NOT_LIVE",
]

_EVALUATION_ID_RE = re.compile(r"^se-[0-9a-f]{16}$")
_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_RESOLUTION_ID_RE = re.compile(r"^res-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: Field names that must never appear on scope models. Defense in
#: depth behind ``extra="forbid"``: any future field addition with one
#: of these names fails closed at review time via tests. Note that
#: ``include_rule`` / ``exclude_rule`` are deliberately named to avoid
#: the ``matched`` alias; ``decision`` is the only outcome shape (no
#: ``scope_allowed`` / ``execution_allowed`` booleans).
FORBIDDEN_SCOPE_FIELDS = frozenset(
    {
        "verdict",
        "finding",
        "vulnerable",
        "confirmed",
        "severity",
        "matched",
        "not_vulnerable",
        "exploited",
        "scope_allowed",
        "execution_allowed",
        "allow",
        "deny",
    }
)


class ScopeError(ValueError):
    """Bounded, non-secret 5D failure with an explicit code.

    Details are closed-code style: short, caller-value-free, screened
    against secret markers. Raw exceptions, connection strings, and
    credentials must never flow through here.
    """

    _CODES = frozenset(
        {
            "TARGET_NOT_CANONICAL",
            "PROGRAM_NOT_FOUND",
            "SCOPE_POLICY_MISSING",
            "SCOPE_POLICY_INVALID",
            "SCOPE_DRIFT",
            "TARGET_NOT_IN_SCOPE",
            "TARGET_EXCLUDED",
            "ADDRESS_NOT_IN_SCOPE",
            "UNSAFE_ADDRESS",
            "REDIRECT_NOT_IN_SCOPE",
            "REDIRECT_INVALID",
            "REDIRECT_LIMIT",
            "TARGET_BINDING_MISMATCH",
            "AUTHZ_BINDING_MISMATCH",
            "RESOLUTION_BINDING_MISMATCH",
            "DIAL_BINDING_MISMATCH",
            "AUTHZ_NOT_LIVE",
            "INVALID_REQUEST",
        }
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self._CODES:
            raise ValueError(f"unknown scope error code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("scope error detail must be single-line")
        if contains_secret_shape(safe_detail):
            raise ValueError(
                "scope error detail carries suspected secret material"
            )
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


def evaluation_id_for(
    *,
    authorization_id: str,
    execution_id: str,
    resolution_id: str,
    canonical_target_hash: str,
    scope_lists_hash_current: str | None,
    chain_digest: str = "",
) -> str:
    """Deterministic evaluation identity (dedupe alias, never proof).

    Same binding tuple always yields the same id; any binding change
    (new execution, new resolution, new policy hash, new hop chain)
    yields a new evaluation. Evaluations are never mutated: a changed
    input requires a new evaluation.
    """

    basis = hash_payload(
        {
            "authorization_id": authorization_id,
            "canonical_target_hash": canonical_target_hash,
            "chain_digest": chain_digest,
            "evaluator_version": EVALUATOR_VERSION,
            "execution_id": execution_id,
            "resolution_id": resolution_id,
            "scope_lists_hash_current": scope_lists_hash_current,
        }
    )
    return "se-" + basis[:16]


class AddressDecision(BaseModel):
    """Per-address gate outcome (dual safety/scope gate, §12 arch).

    The outcome field is deliberately named ``outcome``, not
    ``verdict``: verdict-shaped names are forbidden on scope models.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    address: str
    outcome: AddressVerdict = "UNKNOWN"
    reason: str = ""


class HopDecision(BaseModel):
    """One independently evaluated redirect hop (§14–§15 arch)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hop_index: int
    location_raw_scrubbed: str = ""
    canonical_url: str = ""
    canonical_host: str = ""
    scheme: str = ""
    effective_port: int = 0
    decision: ScopeDecision = "DENIED"
    failure_code: ScopeFailureCode | None = None
    include_rule: str | None = None
    exclude_rule: str | None = None
    upgraded: bool = False

    @field_validator("hop_index")
    @classmethod
    def _hop_index(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("hop_index must be a positive integer")
        return value

    @field_validator("effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("effective_port must be an integer")
        if not 0 <= value <= 65535:
            raise ValueError("effective_port out of range")
        return value


class ScopeEvaluation(BaseModel):
    """Immutable outcome of one scope evaluation.

    ``decision == ALLOWED`` is the only authorizing outcome, and only
    together with a matching ``(authorization_id, execution_id,
    resolution_id)`` triple presented back at transport entry.
    ``INCONCLUSIVE`` never authorizes.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    evaluation_id: str
    authorization_id: str
    execution_id: str
    resolution_id: str
    program_name: str
    canonical_target_hash: str
    scope_lists_hash_current: str | None = None
    decision: ScopeDecision = "DENIED"
    include_rule: str | None = None
    exclude_rule: str | None = None
    address_decisions: tuple[AddressDecision, ...] = ()
    hop_decisions: tuple[HopDecision, ...] = ()
    failure_code: ScopeFailureCode | None = None
    evaluated_at: str = ""
    evaluator_version: Literal["scope-evaluator/v1"] = "scope-evaluator/v1"
    schema_version: Literal["scope_evaluation/v1"] = "scope_evaluation/v1"

    @field_validator("evaluation_id")
    @classmethod
    def _evaluation_id(cls, value: str) -> str:
        if not _EVALUATION_ID_RE.match(value or ""):
            raise ValueError(f"invalid evaluation_id: {value!r}")
        return value

    @field_validator("authorization_id")
    @classmethod
    def _authorization_id(cls, value: str) -> str:
        if not _AUTHZ_ID_RE.match(value or ""):
            raise ValueError(f"invalid authorization_id: {value!r}")
        return value

    @field_validator("execution_id")
    @classmethod
    def _execution_id(cls, value: str) -> str:
        if not _EXECUTION_ID_RE.match(value or ""):
            raise ValueError(f"invalid execution_id: {value!r}")
        return value

    @field_validator("resolution_id")
    @classmethod
    def _resolution_id(cls, value: str) -> str:
        if not _RESOLUTION_ID_RE.match(value or ""):
            raise ValueError(f"invalid resolution_id: {value!r}")
        return value

    @field_validator("canonical_target_hash")
    @classmethod
    def _target_hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError("invalid canonical_target_hash")
        return value

    @field_validator("scope_lists_hash_current")
    @classmethod
    def _policy_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError("invalid scope_lists_hash_current")
        return value

    def is_authorizing(self) -> bool:
        """True only for ALLOWED. INCONCLUSIVE never authorizes."""
        return self.decision == "ALLOWED"


__all__ = [
    "SCHEMA_VERSION",
    "EVALUATOR_VERSION",
    "ScopeDecision",
    "AddressVerdict",
    "ScopeFailureCode",
    "FORBIDDEN_SCOPE_FIELDS",
    "ScopeError",
    "AddressDecision",
    "HopDecision",
    "ScopeEvaluation",
    "evaluation_id_for",
]
