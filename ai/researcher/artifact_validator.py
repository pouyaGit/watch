"""Deterministic Artifact Reference + Safety Contract validator (Phase 4C).

Pure entry point::

    TestPlan + artifact bytes -> validated ArtifactReference

This module is PURE and DETERMINISTIC:

- NO LLM calls, NO model/prompt/embedding imports.
- NO network access (no requests/httpx/urllib/socket/DNS; URL
  handling is stdlib string parsing inside the Nuclei H2 gate).
- NO subprocess, NO os/sys process manipulation.
- NO database (no MongoEngine, no database.db).
- NO scope policy import, NO scope calculation, NO authorization.
- NO verifier/oracle/executor imports or calls (no XSS verifier,
  no XSS oracle, no Nuclei runtime, no browser/HTTP executor).
- NO finding creation, NO verdict fields, NO execution.

Validation proves ONLY artifact contract/safety. ``VALID`` means
"the artifact passed deterministic contract/safety validation" —
never "the target is vulnerable", never "execution is
authorized".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ai.researcher.nuclei_artifact_validator import (
    NucleiFixture,
    parse_template_content,
    validate_nuclei_body,
    validate_nuclei_headers,
    validate_nuclei_path,
    validate_nuclei_query_params,
    validate_nuclei_safety,
    validate_nuclei_specificity,
)
from ai.schemas.artifact import (
    MAX_XSS_PAYLOAD_BYTES,
    ArtifactReference,
    build_artifact_reference,
    content_hash_for_bytes,
    max_bytes_for,
)
from ai.schemas.test_plan import TestPlan

_ALLOWED_TYPES = frozenset(
    {"nuclei_template", "xss_payload", "http_request_spec"}
)


class HttpArtifactContent(BaseModel):
    """Canonical HTTP request-spec artifact content.

    Strict schema (``extra="forbid"``). DELETE is deliberately
    absent: no existing Watch contract requires destructive
    artifact methods, so the gate rejects DELETE fail-closed.
    """

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"] = "GET"
    path: str = "/"
    query_params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


@dataclass(frozen=True)
class ArtifactValidation:
    """Outcome of deterministic artifact validation.

    ``state`` is the closed validation verdict for the bytes
    (``VALID`` or ``REJECTED``); ``reference`` is the hash-bound,
    plan-bound :class:`ArtifactReference` carrying that state;
    ``reasons`` is deterministic explanatory text. The reference
    is independently re-validatable via
    :func:`validate_reference_binding`.
    """

    state: str
    reference: ArtifactReference
    reasons: tuple[str, ...] = field(default_factory=tuple)


def _parse_http_content(content: bytes) -> HttpArtifactContent:
    try:
        text = bytes(content).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"artifact bytes are not UTF-8: {exc}") from exc
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"artifact bytes are not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("artifact content must be a JSON object")
    return HttpArtifactContent.model_validate(payload)


def validate_xss_payload(content: bytes) -> list[str]:
    """XSS payload gate: bounded inert data, never executed.

    The payload is content DATA. It is hashed, plan-bound, and
    size-bounded, but never launched in a browser, never sent,
    never resolved against callbacks, and never classified as
    "working". UTF-8 text without NUL bytes; control characters
    (CR/LF/C0) are rejected so one payload cannot smuggle extra
    transports. Returns violations (empty means acceptable).
    """

    errors: list[str] = []
    if not content:
        errors.append("xss payload must be non-empty")
        return errors
    if len(content) > MAX_XSS_PAYLOAD_BYTES:
        errors.append(
            f"xss payload exceeds {MAX_XSS_PAYLOAD_BYTES} bytes "
            f"({len(content)} bytes)"
        )
    if b"\x00" in bytes(content):
        errors.append("xss payload must not contain NUL bytes")
    try:
        text = bytes(content).decode("utf-8")
    except UnicodeDecodeError:
        errors.append("xss payload must be UTF-8")
        return errors
    for char in text:
        code = ord(char)
        if char in ("\n", "\r") or code < 32 and char != "\t" or code == 127:
            errors.append(
                "xss payload must not contain CR/LF/control characters"
            )
            break
    return errors


def validate_http_safety(content: HttpArtifactContent) -> list[str]:
    """H2-equivalent gate for ``http_request_spec`` artifacts."""

    errors: list[str] = []
    validate_nuclei_path(content.path, errors)
    validate_nuclei_headers(content.headers, errors)
    validate_nuclei_query_params(content.query_params, errors)
    validate_nuclei_body(content.body, errors)
    return errors


def _check_inputs(test_plan: object, content: object) -> None:
    if not isinstance(test_plan, TestPlan):
        raise TypeError(
            "artifact validation accepts only TestPlan, not "
            f"{type(test_plan).__name__}; raw dicts are never coerced"
        )
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError(
            "artifact content must be bytes, not "
            f"{type(content).__name__}"
        )


def build_validated_reference(
    test_plan: object,
    content: object,
    artifact_type: object,
    *,
    fixtures: object = None,
) -> ArtifactValidation:
    """Validate artifact bytes against a TestPlan and bind a reference.

    Deterministic: same (plan, bytes, type, fixtures) → same
    reference, same state, same reasons. Fail closed: any
    contract, binding, size, safety, or specificity violation
    yields a ``REJECTED`` reference (never ``VALID``), and unknown
    artifact types raise ``ValueError``. The returned reference is
    always hash-bound and plan-bound even when rejected, so
    re-validation converges.
    """

    _check_inputs(test_plan, content)
    assert isinstance(test_plan, TestPlan)
    assert isinstance(content, (bytes, bytearray))
    raw = bytes(content)

    if not isinstance(artifact_type, str) or artifact_type not in _ALLOWED_TYPES:
        raise ValueError(f"unknown artifact_type: {artifact_type!r}")

    reasons: list[str] = []

    # Size gate (fail closed, before parsing).
    try:
        limit = max_bytes_for(artifact_type)
    except ValueError as exc:
        raise ValueError(f"unknown artifact_type: {artifact_type!r}") from exc
    if len(raw) > limit:
        reasons.append(
            f"artifact content exceeds {limit} bytes for "
            f"{artifact_type!r} ({len(raw)} bytes)"
        )

    safety_errors: list[str] = []
    specificity_ok: bool | None = None

    if artifact_type == "nuclei_template":
        try:
            template = parse_template_content(raw)
        except (ValueError, TypeError) as exc:
            safety_errors.append(f"malformed nuclei content: {exc}")
            template = None
        if template is not None:
            safety_errors.extend(validate_nuclei_safety(template))
            if fixtures is None:
                reasons.append(
                    "missing fixtures: nuclei specificity cannot be "
                    "established without a benign fixture"
                )
            elif not isinstance(fixtures, (list, tuple)):
                raise TypeError(
                    "fixtures must be a list or tuple of "
                    f"NucleiFixture, not {type(fixtures).__name__}"
                )
            else:
                for item in fixtures:
                    if not isinstance(item, NucleiFixture):
                        raise TypeError(
                            "fixtures must be NucleiFixture, not "
                            f"{type(item).__name__}"
                        )
                result = validate_nuclei_specificity(template, fixtures)
                specificity_ok = result.passed
                if not result.passed:
                    reasons.extend(result.reasons)
    elif artifact_type == "xss_payload":
        safety_errors.extend(validate_xss_payload(raw))
    elif artifact_type == "http_request_spec":
        try:
            http_content = _parse_http_content(raw)
        except (ValueError, TypeError) as exc:
            safety_errors.append(f"malformed http content: {exc}")
            http_content = None
        if http_content is not None:
            safety_errors.extend(validate_http_safety(http_content))

    if safety_errors:
        reasons.extend(safety_errors)

    state = "REJECTED" if reasons else "VALID"
    if artifact_type == "nuclei_template" and specificity_ok is False and not reasons:
        state = "REJECTED"

    if len(raw) > limit:
        # Oversized bytes cannot go through the size-enforcing
        # factory, but the rejection must still be hash-bound and
        # plan-bound so re-validation converges.
        from ai.schemas.artifact import artifact_id_for as _id_for

        digest = content_hash_for_bytes(raw)
        reference = ArtifactReference(
            artifact_id=_id_for(
                artifact_type=artifact_type,
                test_plan_id=test_plan.test_plan_id,
                content_hash=digest,
            ),
            artifact_type=artifact_type,  # type: ignore[arg-type]
            content_hash=digest,
            test_plan_id=test_plan.test_plan_id,
            hypothesis_id=test_plan.hypothesis_id,
            match_id=test_plan.match_id,
            snapshot_hash=test_plan.snapshot_hash,
            validation_state=state,  # type: ignore[arg-type]
        )
    else:
        reference = build_artifact_reference(
            artifact_type=artifact_type,
            content=raw,
            test_plan_id=test_plan.test_plan_id,
            hypothesis_id=test_plan.hypothesis_id,
            match_id=test_plan.match_id,
            snapshot_hash=test_plan.snapshot_hash,
            validation_state=state,  # type: ignore[arg-type]
        )
    if state == "VALID":
        reasons = (
            "artifact passed deterministic contract/safety validation; "
            "this asserts nothing about target vulnerability, scope, "
            "or execution authorization",
        )
    return ArtifactValidation(
        state=state, reference=reference, reasons=tuple(reasons)
    )


def validate_reference_binding(
    reference: object,
    test_plan: object,
    content: object,
    *,
    fixtures: object = None,
) -> list[str]:
    """Independently re-validate a reference against a plan + bytes.

    Checks (all fail closed, returned as error strings):

    - typed inputs (``ArtifactReference`` / ``TestPlan`` / bytes).
    - ``reference.test_plan_id == test_plan.test_plan_id``.
    - provenance equality: ``hypothesis_id`` / ``match_id`` /
      ``snapshot_hash`` must equal the plan's bindings exactly
      (an artifact for one plan can never attach to another).
    - ``reference.content_hash == SHA256(content)``.
    - ``reference.artifact_id`` recomputes from
      (type, plan, hash, version).
    - content re-passes type validation (safety + specificity);
      a ``VALID`` reference whose bytes no longer validate is
      reported (duplicate validation converges on the same
      verdict).
    """

    errors: list[str] = []
    if not isinstance(reference, ArtifactReference):
        raise TypeError(
            "reference must be ArtifactReference, not "
            f"{type(reference).__name__}"
        )
    _check_inputs(test_plan, content)
    assert isinstance(test_plan, TestPlan)
    assert isinstance(content, (bytes, bytearray))
    raw = bytes(content)

    if reference.test_plan_id != test_plan.test_plan_id:
        errors.append(
            "test_plan binding mismatch: reference binds "
            f"{reference.test_plan_id!r} but plan is "
            f"{test_plan.test_plan_id!r}"
        )
    if reference.hypothesis_id != test_plan.hypothesis_id:
        errors.append("hypothesis binding mismatch")
    if reference.match_id != test_plan.match_id:
        errors.append("match binding mismatch")
    if reference.snapshot_hash != test_plan.snapshot_hash:
        errors.append("snapshot binding mismatch")

    if reference.content_hash != content_hash_for_bytes(raw):
        errors.append("content hash does not match artifact bytes")

    # Recompute identity directly: hostile metadata never enters.
    from ai.schemas.artifact import artifact_id_for as _id_for

    recomputed = _id_for(
        artifact_type=reference.artifact_type,
        test_plan_id=reference.test_plan_id,
        content_hash=reference.content_hash,
        schema_version=reference.artifact_schema_version,
    )
    if reference.artifact_id != recomputed:
        errors.append("artifact_id does not match the deterministic basis")

    # Independent re-validation of the bytes.
    recheck = build_validated_reference(
        test_plan, raw, reference.artifact_type, fixtures=fixtures
    )
    if reference.validation_state == "VALID" and recheck.state != "VALID":
        errors.append(
            "reference claims VALID but bytes fail re-validation: "
            + "; ".join(recheck.reasons)
        )
    return errors


__all__ = [
    "ArtifactValidation",
    "HttpArtifactContent",
    "build_validated_reference",
    "validate_http_safety",
    "validate_reference_binding",
    "validate_xss_payload",
]
