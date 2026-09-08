"""TestPlan data contract (Phase 1).

A TestPlan is UNTRUSTED pre-execution intent derived from a single
Hypothesis:

- It NEVER owns scope, execution, evidence, or verdicts.
- It NEVER contains CONFIRMED / NOT_VULNERABLE / VERIFIED semantics.
- It describes *intent* (what should be tested and what evidence would
  suffice) but never asserts that evidence exists.
- It contains no executable code, shell commands, or tool invocations.
- The target reference is descriptive/non-authoritative; the eventual
  executor MUST re-resolve the canonical target deterministically before
  any network action. A TestPlan with ``scope_allowed: true``-like
  authority MUST NOT exist — and this schema has no such field.
- Artifact references are content-hashed pointers, not executable content.

Like Hypothesis, identity follows the KnowledgeStore convention: the
deterministic idempotency key is the full SHA-256 over the canonical
TestPlan basis, and ``test_plan_id`` is its short alias
(``tp-`` + first 16 hex chars). LLM metadata is audit-only and excluded
from identity.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai.schemas.hypothesis import (
    LLMMetadata,
    ResearchProvenance,
    TargetRef,
    _HYP_ID_RE as _HYPOTHESIS_ID_RE,
)


SCHEMA_VERSION = "testplan/v1"

TestPlanStatus = Literal[
    "PROPOSED",
    "APPROVED",
    "REJECTED",
    "SUPERSEDED",
    "CANCELLED",
]

TestCategory = Literal[
    "xss_reflected",
    "xss_stored",
    "xss_dom",
    "xss_generic",
    "nuclei_cve",
    "nuclei_generic",
    "http_signature",
    "http_probe",
]

ExecutionType = Literal[
    "http_verification",
    "browser_verification",
    "nuclei_scan",
    "http_probe",
]

VerifierType = Literal[
    "xss_verifier",
    "nuclei_verifier",
    "http_matcher",
    "manual_review",
]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")
_ART_ID_RE = re.compile(r"^art-[0-9a-f]{16}$")
_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")

# Re-export for external validators that import from this module.
_HYP_ID_RE = _HYPOTHESIS_ID_RE


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_text(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(folded.split())


def test_plan_idempotency_key(
    *,
    hypothesis_id: str,
    program_name: str,
    subdomain: str,
    endpoint: str,
    test_category: str,
    execution_type: str,
    objective: str,
    request_spec: dict,
    verifier_type: str,
    match_id: str = "",
    snapshot_hash: str = "",
) -> str:
    """Full SHA-256 idempotency key over the canonical TestPlan basis.

    Binds hypothesis + target + category + execution + normalized
    objective + canonical request spec + verifier. LLM metadata,
    preconditions, expected behavior prose, provenance ordering,
    timestamps, and status are EXCLUDED so retries and
    cross-provider duplicates resolve to one key.

    Phase 4B addition: ``match_id`` (a ``tm-…`` deterministic match
    alias) and ``snapshot_hash`` (the bound target-observation
    state) join the basis WHEN PROVIDED, so plans built from
    different snapshots cannot collide. Both default to ``""``
    and are OMITTED from the canonical basis when empty, so every
    key computed by pre-existing callers reproduces byte-for-byte.
    """

    canonical = {
        "endpoint": endpoint,
        "execution_type": execution_type,
        "hypothesis_id": hypothesis_id,
        "objective": _normalize_text(objective),
        "program_name": program_name,
        "request_spec": request_spec,
        "subdomain": subdomain,
        "test_category": test_category,
        "verifier_type": verifier_type,
    }
    if match_id:
        canonical["match_id"] = match_id
    if snapshot_hash:
        canonical["snapshot_hash"] = snapshot_hash
    return _sha256_hex(_canonical_json(canonical))


def test_plan_id_from_key(key: str) -> str:
    return "tp-" + key[:16]


def artifact_id_from_hash(content_hash: str) -> str:
    return "art-" + content_hash[:16]


class HttpRequestSpec(BaseModel):
    """Constrained HTTP request description. No execution authority.

    Only the fields a deterministic executor needs to build a safe
    request. No command, script, plugin, or tool-call field exists.
    """

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    path: str = "/"
    query_params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("path must be a non-empty string")
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        if "\n" in value or "\r" in value:
            raise ValueError("path must not contain newlines")
        return value

    @field_validator("query_params", "headers")
    @classmethod
    def _no_newlines_in_map(
        cls, value: dict[str, str]
    ) -> dict[str, str]:
        for k, v in value.items():
            if "\n" in k or "\r" in k or "\n" in v or "\r" in v:
                raise ValueError("header/param keys and values must not contain newlines")
        return value


class ArtifactRef(BaseModel):
    """Immutable, content-hashed pointer to a generated artifact.

    The artifact bytes themselves are NOT embedded. The hash binds the
    reference to exact content for auditability; the path is
    informational only.
    """

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    artifact_type: Literal["nuclei_template", "xss_payload", "http_request", "generic"] = "generic"
    content_hash: str
    path: str | None = None

    @field_validator("artifact_id")
    @classmethod
    def _art_id(cls, value: str) -> str:
        if not _ART_ID_RE.match(value or ""):
            raise ValueError(f"invalid artifact_id: {value!r}")
        return value

    @field_validator("content_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid content_hash: {value!r}")
        return value

    @model_validator(mode="after")
    def _id_matches_hash(self) -> "ArtifactRef":
        if self.artifact_id != artifact_id_from_hash(self.content_hash):
            raise ValueError("artifact_id must be the alias of content_hash")
        return self


class TestPlan(BaseModel):
    """A proposed security test derived from one Hypothesis.

    Pre-execution lifecycle only:
    PROPOSED → APPROVED / REJECTED / SUPERSEDED / CANCELLED.

    There is deliberately NO verdict-valued state. APPROVED means
    "the plan's syntax and references passed deterministic
    validation", NOT "the vulnerability is confirmed". CONFIRMED,
    NOT_VULNERABLE, and VERIFIED are rejected at the type level.

    The target reference is descriptive: executors MUST re-resolve
    the canonical target and re-apply scope policy at execution time.
    This schema has no ``scope_allowed`` or equivalent authority flag.
    """

    model_config = ConfigDict(extra="forbid")

    test_plan_id: str
    idempotency_key: str
    hypothesis_id: str
    # Phase 4B match binding (optional, additive). When set, these
    # identify the exact deterministic TargetPatternMatch
    # (``tm-…``) and target-observation snapshot (full SHA-256)
    # this plan was derived from. They are descriptive audit
    # pointers, NOT authority: scope and execution still require
    # independent re-resolution. ``None`` preserves the pre-4B
    # shape for plans built without a bound match.
    match_id: str | None = None
    snapshot_hash: str | None = None
    target: TargetRef
    test_category: TestCategory
    objective: str
    preconditions: list[str] = Field(default_factory=list)
    execution_type: ExecutionType
    request_spec: HttpRequestSpec = Field(default_factory=HttpRequestSpec)
    expected_behavior: str = ""
    required_evidence: list[str] = Field(default_factory=list)
    verifier_type: VerifierType
    provenance: ResearchProvenance
    artifact_ref: ArtifactRef | None = None
    status: TestPlanStatus = "PROPOSED"
    supersedes: str | None = None
    cancel_reason: str | None = None
    llm: LLMMetadata = Field(default_factory=LLMMetadata)
    schema_version: Literal["testplan/v1"] = "testplan/v1"
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @field_validator("test_plan_id")
    @classmethod
    def _tp_id(cls, value: str) -> str:
        if not _TP_ID_RE.match(value or ""):
            raise ValueError(f"invalid test_plan_id: {value!r}")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid idempotency_key: {value!r}")
        return value

    @field_validator("hypothesis_id")
    @classmethod
    def _hyp_id(cls, value: str) -> str:
        if not _HYP_ID_RE.match(value or ""):
            raise ValueError(f"invalid hypothesis_id: {value!r}")
        return value

    @field_validator("match_id")
    @classmethod
    def _match_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _TM_ID_RE.match(value):
            raise ValueError(f"invalid match_id: {value!r}")
        return value

    @field_validator("snapshot_hash")
    @classmethod
    def _snapshot_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid snapshot_hash: {value!r}")
        return value

    @field_validator("objective")
    @classmethod
    def _objective(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("objective must be a non-empty string")
        return value

    @field_validator("supersedes")
    @classmethod
    def _supersedes_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _TP_ID_RE.match(value):
            raise ValueError(f"invalid supersedes: {value!r}")
        return value

    @model_validator(mode="after")
    def _lifecycle_consistency(self) -> "TestPlan":
        if self.status == "SUPERSEDED" and not self.supersedes:
            raise ValueError("SUPERSEDED requires supersedes test_plan_id")
        if self.status == "CANCELLED" and not (
            self.cancel_reason and self.cancel_reason.strip()
        ):
            raise ValueError("CANCELLED requires cancel_reason")
        if self.test_plan_id != test_plan_id_from_key(self.idempotency_key):
            raise ValueError("test_plan_id must be the alias of idempotency_key")
        # Cross-contract binding sanity: hypothesis and plan must target
        # the same canonical identity (program+subdomain+endpoint). This
        # is structural, not scope authority — executors still re-resolve.
        # We enforce it here so a plan cannot silently drift targets.
        # (The plan's TargetRef is still descriptive; this is consistency.)
        return self


def build_test_plan(
    *,
    hypothesis_id: str,
    target: TargetRef,
    test_category: str,
    objective: str,
    execution_type: str,
    verifier_type: str,
    provenance: ResearchProvenance,
    request_spec: HttpRequestSpec | dict | None = None,
    preconditions: list[str] | None = None,
    expected_behavior: str = "",
    required_evidence: list[str] | None = None,
    artifact_ref: ArtifactRef | None = None,
    llm: LLMMetadata | None = None,
    created_at: str | None = None,
    match_id: str | None = None,
    snapshot_hash: str | None = None,
) -> TestPlan:
    """Deterministic factory: same logical basis → same identity.

    When ``match_id`` / ``snapshot_hash`` are provided they join
    the key basis, so plans built from different target snapshots
    cannot collide; when omitted the key reproduces the pre-4B
    basis exactly.
    """

    if isinstance(request_spec, dict):
        spec_obj = HttpRequestSpec.model_validate(request_spec)
    elif isinstance(request_spec, HttpRequestSpec):
        spec_obj = request_spec
    elif request_spec is None:
        spec_obj = HttpRequestSpec()
    else:
        raise TypeError("request_spec must be HttpRequestSpec, dict, or None")

    # Canonical request_spec for hashing: sorted keys via _canonical_json
    # of its model_dump. Use mode="json" for determinism.
    spec_canonical = json.loads(
        _canonical_json(spec_obj.model_dump(mode="json"))
    )

    key = test_plan_idempotency_key(
        hypothesis_id=hypothesis_id,
        program_name=target.program_name,
        subdomain=target.subdomain,
        endpoint=target.endpoint,
        test_category=test_category,
        execution_type=execution_type,
        objective=objective,
        request_spec=spec_canonical,
        verifier_type=verifier_type,
        match_id=match_id or "",
        snapshot_hash=snapshot_hash or "",
    )
    return TestPlan(
        test_plan_id=test_plan_id_from_key(key),
        idempotency_key=key,
        hypothesis_id=hypothesis_id,
        match_id=match_id,
        snapshot_hash=snapshot_hash,
        target=target,
        test_category=test_category,  # type: ignore[arg-type]
        objective=objective,
        preconditions=list(preconditions or []),
        execution_type=execution_type,  # type: ignore[arg-type]
        request_spec=spec_obj,
        expected_behavior=expected_behavior,
        required_evidence=list(required_evidence or []),
        verifier_type=verifier_type,  # type: ignore[arg-type]
        provenance=provenance,
        artifact_ref=artifact_ref,
        llm=llm or LLMMetadata(),
        **({"created_at": created_at} if created_at is not None else {}),
    )


__all__ = [
    "SCHEMA_VERSION",
    "ArtifactRef",
    "HttpRequestSpec",
    "TestPlan",
    "TestPlanStatus",
    "TestCategory",
    "ExecutionType",
    "VerifierType",
    "artifact_id_from_hash",
    "build_test_plan",
    "test_plan_id_from_key",
    "test_plan_idempotency_key",
]
