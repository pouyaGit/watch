"""Immutable EvidenceBuilder/sealer (Phase 5H-core).

One-way construction: ``BUILDING → SEALED | INCOMPLETE``. The builder
is single-use and worker-local: after :meth:`seal` or
:meth:`seal_partial` the builder is spent and any further call raises
``EVIDENCE_IMMUTABLE``.

Deliberately absent (and test-asserted absent): ``reassign``,
``rebind``, ``repair``, ``reattach``, ``supersede``, ``patch``,
``append``. There is no API that mutates a sealed record under any
name.

Hash separation (frozen field lists):

- ``bindings_hash``: identity/binding fields. ``evidence_id``
  excluded (handle, not content).
- ``observations_hash``: transport facts + hashes of content.
  Raw bodies/samples excluded (only their hashes participate).
- ``content_hash``: exactly the bounded persisted samples.
- Timestamps never participate (the hashing module additionally
  refuses them — double protection).
"""

from __future__ import annotations

from typing import Any

from ai.evidence import hashing
from ai.schemas import evidence as ev

__all__ = [
    "EvidenceBuilder",
    "bindings_payload",
    "observations_payload",
    "content_payload",
    "compute_hashes",
    "verify_record",
    "REQUIRED_OBSERVATIONS",
]

#: Which observation channel completes each execution class.
REQUIRED_OBSERVATIONS: dict[str, tuple[str, ...]] = {
    "http_probe": ("http",),
    "http_verification": ("http",),
    "nuclei_scan": ("nuclei",),
    "browser_verification": ("browser",),
}


def _target_payload(target: ev.TargetIdentity) -> dict[str, Any]:
    return {
        "effective_port": target.effective_port,
        "host": target.host,
        "path_scope": target.path_scope,
        "program_name": target.program_name,
        "scheme": target.scheme,
    }


def _snapshot_payload(
    snapshot: ev.SnapshotBinding | None,
) -> dict[str, Any]:
    if snapshot is None:
        return {
            "cdn_mapping_hash": None,
            "cdn_mapping_version": None,
            "fixture_set_id": None,
            "fixture_version": None,
            "scope_lists_hash": None,
            "scope_policy_version": None,
            "snapshot_ref": None,
        }
    return {
        "cdn_mapping_hash": snapshot.cdn_mapping_hash,
        "cdn_mapping_version": snapshot.cdn_mapping_version,
        "fixture_set_id": snapshot.fixture_set_id,
        "fixture_version": snapshot.fixture_version,
        "scope_lists_hash": snapshot.scope_lists_hash,
        "scope_policy_version": snapshot.scope_policy_version,
        "snapshot_ref": snapshot.snapshot_ref,
    }


def bindings_payload(record: ev.EvidenceRecord) -> dict[str, Any]:
    """Frozen bindings-hash payload (absent optional == null)."""
    derivation = record.derivation_binding
    template = record.template_binding
    return {
        "artifact_content_hash": record.artifact_content_hash,
        "artifact_id": record.artifact_id,
        "authorization_id": record.authorization_id,
        "derivation_contract_hash": (
            derivation.contract_hash if derivation is not None else None
        ),
        "evidence_schema_version": record.evidence_schema_version,
        "execution_id": record.execution_id,
        "execution_stage": record.execution_stage,
        "hypothesis_id": record.hypothesis_id,
        "match_id": record.match_id,
        "snapshot_binding": _snapshot_payload(record.snapshot_binding),
        "target_identity": _target_payload(record.target),
        "template_binding": {
            "template_hash": template.template_hash
            if template is not None
            else None,
            "template_id": template.template_id
            if template is not None
            else None,
        },
        "test_plan_id": record.test_plan_id,
    }


def _http_payload(http: ev.HttpObservation | None) -> dict[str, Any]:
    if http is None:
        return {
            "chain_truncated": None,
            "dial_ips": None,
            "method": None,
            "redirect_chain": None,
            "request_body_hash": None,
            "request_headers": None,
            "request_url": None,
            "response_body_hash": None,
            "response_headers": None,
            "response_status": None,
            "transport_outcome": None,
        }
    return {
        "chain_truncated": http.chain_truncated,
        "dial_ips": list(http.dial_ips),
        "method": http.method,
        "redirect_chain": [
            {
                "canonical_hash": hop.canonical_hash,
                "redacted_query_hash": hop.redacted_query_hash,
                "redacted_url": hop.redacted_url,
            }
            for hop in http.redirect_chain
        ],
        "request_body_hash": http.request_body_hash,
        "request_headers": {
            "headers": dict(http.request_headers.headers),
            "truncated": http.request_headers.truncated,
        },
        "request_url": {
            "canonical_hash": http.request_url.canonical_hash,
            "redacted_query_hash": http.request_url.redacted_query_hash,
            "redacted_url": http.request_url.redacted_url,
        },
        "response_body_hash": http.response_body_hash,
        "response_headers": {
            "headers": dict(http.response_headers.headers),
            "truncated": http.response_headers.truncated,
        },
        "response_status": http.response_status,
        "transport_outcome": http.transport_outcome,
    }


def _nuclei_payload(nuclei: ev.NucleiObservation | None) -> dict[str, Any]:
    if nuclei is None:
        return {
            "argv_digest": None,
            "exit_code": None,
            "finding_like_text_present": None,
            "killed": None,
            "stderr_hash": None,
            "stdout_hash": None,
            "template_hash": None,
            "template_id": None,
            "timed_out": None,
        }
    return {
        "argv_digest": nuclei.argv_digest,
        "exit_code": nuclei.exit_code,
        "finding_like_text_present": nuclei.finding_like_text_present,
        "killed": nuclei.killed,
        "stderr_hash": nuclei.stderr_hash,
        "stdout_hash": nuclei.stdout_hash,
        "template_hash": nuclei.template_hash,
        "template_id": nuclei.template_id,
        "timed_out": nuclei.timed_out,
    }


def _browser_payload(
    browser: ev.BrowserObservation | None,
    derivation: ev.DerivationBinding | None,
) -> dict[str, Any]:
    executed = (
        derivation.executed_payload_hash
        if derivation is not None
        else None
    )
    if browser is not None and browser.executed_payload_hash is not None:
        executed = browser.executed_payload_hash
    if browser is None:
        return {
            "channels_truncated": None,
            "dialog_marker_hashes": None,
            "e_flags": None,
            "eval_marker_hashes": None,
            "executed_payload_hash": executed,
            "oracle_event_hashes": None,
            "page_url": None,
            "round_id": None,
            "storage_keys_hash": None,
            "submit_evidence_ref": None,
        }
    return {
        "channels_truncated": browser.channels_truncated,
        "dialog_marker_hashes": list(browser.dialog_marker_hashes),
        "e_flags": {
            "e1": browser.e1_observed,
            "e2": browser.e2_observed,
            "e3": browser.e3_observed,
        },
        "eval_marker_hashes": list(browser.eval_marker_hashes),
        "executed_payload_hash": executed,
        "oracle_event_hashes": list(browser.oracle_event_hashes),
        "page_url": (
            {
                "canonical_hash": browser.page_url.canonical_hash,
                "redacted_query_hash": browser.page_url.redacted_query_hash,
                "redacted_url": browser.page_url.redacted_url,
            }
            if browser.page_url is not None
            else None
        ),
        "round_id": browser.round_id,
        "storage_keys_hash": browser.storage_keys_hash,
        "submit_evidence_ref": browser.submit_evidence_ref,
    }


def observations_payload(record: ev.EvidenceRecord) -> dict[str, Any]:
    """Frozen observations-hash payload (hashes of content, not content)."""
    return {
        "browser": _browser_payload(record.browser, record.derivation_binding),
        "execution_class": record.execution_class,
        "http": _http_payload(record.http),
        "nuclei": _nuclei_payload(record.nuclei),
    }


def content_payload(record: ev.EvidenceRecord) -> dict[str, Any]:
    """Frozen content-hash payload (exactly the persisted samples)."""
    http = record.http
    nuclei = record.nuclei
    return {
        "browser_markers": {
            "dialog_count": len(record.browser.dialog_marker_hashes)
            if record.browser is not None
            else None,
            "eval_count": len(record.browser.eval_marker_hashes)
            if record.browser is not None
            else None,
            "oracle_count": len(record.browser.oracle_event_hashes)
            if record.browser is not None
            else None,
        },
        "http_samples": {
            "redirect_chain": [
                hop.redacted_url for hop in http.redirect_chain
            ]
            if http is not None
            else None,
            "request_body_sample": http.request_body_sample
            if http is not None
            else None,
            "request_headers": dict(http.request_headers.headers)
            if http is not None
            else None,
            "response_body_sample": http.response_body_sample
            if http is not None
            else None,
            "response_headers": dict(http.response_headers.headers)
            if http is not None
            else None,
            "sample_omitted": http.sample_omitted
            if http is not None
            else None,
        },
        "nuclei_samples": {
            "stderr_sample": nuclei.stderr_sample
            if nuclei is not None
            else None,
            "stdout_sample": nuclei.stdout_sample
            if nuclei is not None
            else None,
        },
    }


def compute_hashes(record: ev.EvidenceRecord) -> tuple[str, str, str]:
    """Compute (bindings_hash, observations_hash, content_hash)."""
    return (
        hashing.hash_payload(bindings_payload(record)),
        hashing.hash_payload(observations_payload(record)),
        hashing.hash_payload(content_payload(record)),
    )


def _completeness_errors(record: ev.EvidenceRecord) -> list[str]:
    errors: list[str] = []
    if not record.snapshot_binding or not record.snapshot_binding.scope_lists_hash:
        errors.append("snapshot-binding-missing")
    required = REQUIRED_OBSERVATIONS.get(record.execution_class, ())
    if "http" in required:
        http = record.http
        if http is None:
            errors.append("http-observation-missing")
        else:
            if http.response_status is None:
                errors.append("http-response-status-missing")
            if http.response_body_hash is None:
                errors.append("http-response-body-hash-missing")
    if "nuclei" in required:
        nuclei = record.nuclei
        if nuclei is None:
            errors.append("nuclei-observation-missing")
        else:
            if nuclei.exit_code is None and not (
                nuclei.timed_out or nuclei.killed
            ):
                errors.append("nuclei-exit-facts-missing")
    if "browser" in required:
        browser = record.browser
        if browser is None:
            errors.append("browser-observation-missing")
        else:
            executed = (
                browser.executed_payload_hash
                or (
                    record.derivation_binding.executed_payload_hash
                    if record.derivation_binding is not None
                    else None
                )
            )
            if executed is None:
                errors.append("browser-executed-payload-hash-missing")
            if browser.page_url is None:
                errors.append("browser-page-url-missing")
    if record.execution_stage == "oracle" and (
        record.derivation_binding is None
        or record.derivation_binding.contract_hash is None
    ):
        errors.append("derivation-binding-missing")
    if record.execution_class == "nuclei_scan" and (
        record.template_binding is None
        or record.template_binding.template_hash is None
    ):
        errors.append("template-binding-missing")
    return errors


def verify_record(record: ev.EvidenceRecord) -> None:
    """Recompute all three hashes; raise on any mismatch.

    Raises ``EVIDENCE_HASH_MISMATCH`` naming the divergent hash.
    Raises ``EVIDENCE_MALFORMED`` when seal hashes are absent.
    """
    if not isinstance(record, ev.EvidenceRecord):
        raise TypeError(
            "verify_record accepts only EvidenceRecord, "
            f"not {type(record).__name__}"
        )
    if (
        record.bindings_hash is None
        or record.observations_hash is None
        or record.content_hash is None
    ):
        raise ev.EvidenceError("EVIDENCE_MALFORMED", "seal hashes absent")
    expected = compute_hashes(record)
    actual = (
        record.bindings_hash,
        record.observations_hash,
        record.content_hash,
    )
    names = ("bindings_hash", "observations_hash", "content_hash")
    for name, want, got in zip(names, expected, actual):
        if want != got:
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH", f"divergent {name}"
            )


class EvidenceBuilder:
    """Single-use worker-local evidence constructor (BUILDING only)."""

    def __init__(self, record: ev.EvidenceRecord) -> None:
        if not isinstance(record, ev.EvidenceRecord):
            raise TypeError(
                "EvidenceBuilder accepts only EvidenceRecord, "
                f"not {type(record).__name__}"
            )
        if record.lifecycle != "BUILDING":
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "builder requires BUILDING record"
            )
        self._record = record
        self._spent = False

    @classmethod
    def begin(
        cls,
        *,
        authorization: object,
        execution_id: str,
        execution_stage: str = "single",
        execution_class: str = "http_probe",
        started_at: str = "",
    ) -> "EvidenceBuilder":
        """Open a BUILDING record bound to a typed issuance record.

        Binding values are COPIED from the issuance record (authority);
        content hashes are computed later from observed bytes (never
        copied). Accepts only genuine ``IssuedExecutionAuthorization``
        instances — raw dicts raise ``TypeError`` (5B discipline).
        """
        from ai.schemas.execution_authorization import (
            IssuedExecutionAuthorization,
        )

        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "evidence binds only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}; "
                "raw dicts are never coerced"
            )
        record = ev.EvidenceRecord(
            evidence_id=ev.generate_evidence_id(),
            execution_id=execution_id,
            authorization_id=authorization.authorization_id,
            execution_stage=execution_stage,  # type: ignore[arg-type]
            execution_class=execution_class,  # type: ignore[arg-type]
            artifact_id=authorization.artifact.artifact_id,
            artifact_content_hash=authorization.artifact.content_hash,
            target=ev.TargetIdentity(
                program_name=authorization.target.program_name,
                host=authorization.target.host,
                scheme=authorization.target.scheme,
                effective_port=authorization.target.effective_port,
                path_scope=authorization.target.path_scope,
            ),
            program_name=authorization.target.program_name,
            hypothesis_id=authorization.hypothesis_id,
            test_plan_id=authorization.test_plan_id,
            match_id=authorization.match_id,
            snapshot_binding=ev.SnapshotBinding(
                snapshot_ref=authorization.target.snapshot_ref,
                scope_policy_version=(
                    authorization.target.scope_policy_version
                ),
                scope_lists_hash=authorization.target.scope_lists_hash,
                fixture_set_id=(
                    authorization.fixture_binding.fixture_set_id
                    if authorization.fixture_binding is not None
                    else None
                ),
                fixture_version=(
                    authorization.fixture_binding.fixture_version
                    if authorization.fixture_binding is not None
                    else None
                ),
                cdn_mapping_version=(
                    authorization.cdn_binding.mapping_version
                    if authorization.cdn_binding is not None
                    else None
                ),
                cdn_mapping_hash=(
                    authorization.cdn_binding.mapping_hash
                    if authorization.cdn_binding is not None
                    else None
                ),
            ),
            derivation_binding=(
                ev.DerivationBinding(
                    contract_hash=hashing.hash_payload(
                        authorization.xss_derivation.model_dump(mode="json")
                    ),
                    executed_payload_hash=None,
                    execution_phase=(
                        authorization.xss_derivation.execution_phase
                    ),
                )
                if authorization.xss_derivation is not None
                else None
            ),
            started_at=started_at,
        )
        return cls(record)

    def _require_open(self) -> None:
        if self._spent:
            raise ev.EvidenceError(
                "EVIDENCE_IMMUTABLE", "builder is spent; sealed bytes frozen"
            )

    @property
    def record(self) -> ev.EvidenceRecord:
        """Current worker-local record (deep copy; BUILDING only)."""
        self._require_open()
        return self._record.model_copy(deep=True)

    def attach_http(self, observation: ev.HttpObservation) -> None:
        """Attach the HTTP observation (once; no replacement)."""
        self._require_open()
        if not isinstance(observation, ev.HttpObservation):
            raise TypeError(
                "attach_http accepts only HttpObservation, "
                f"not {type(observation).__name__}"
            )
        if self._record.http is not None:
            raise ev.EvidenceError(
                "EVIDENCE_IMMUTABLE", "http observation already attached"
            )
        self._record.http = observation.model_copy(deep=True)

    def attach_nuclei(self, observation: ev.NucleiObservation) -> None:
        """Attach the Nuclei observation (once; no replacement)."""
        self._require_open()
        if not isinstance(observation, ev.NucleiObservation):
            raise TypeError(
                "attach_nuclei accepts only NucleiObservation, "
                f"not {type(observation).__name__}"
            )
        if self._record.nuclei is not None:
            raise ev.EvidenceError(
                "EVIDENCE_IMMUTABLE", "nuclei observation already attached"
            )
        self._record.nuclei = observation.model_copy(deep=True)
        self._record.template_binding = ev.TemplateBinding(
            template_id=observation.template_id,
            template_hash=observation.template_hash,
        )

    def attach_browser(
        self,
        observation: ev.BrowserObservation,
        *,
        executed_payload_hash: str | None = None,
    ) -> None:
        """Attach the browser observation (once; no replacement).

        The executed oracle payload hash O is recorded independently
        of the artifact payload hash P (dual-hash rule): it is either
        carried on the observation or passed explicitly, never copied
        from the artifact binding.
        """
        self._require_open()
        if not isinstance(observation, ev.BrowserObservation):
            raise TypeError(
                "attach_browser accepts only BrowserObservation, "
                f"not {type(observation).__name__}"
            )
        if self._record.browser is not None:
            raise ev.EvidenceError(
                "EVIDENCE_IMMUTABLE", "browser observation already attached"
            )
        merged = observation.model_copy(deep=True)
        if executed_payload_hash is not None:
            merged.executed_payload_hash = executed_payload_hash
        self._record.browser = merged
        if self._record.derivation_binding is not None:
            self._record.derivation_binding = (
                self._record.derivation_binding.model_copy(
                    update={
                        "executed_payload_hash": merged.executed_payload_hash
                    }
                )
            )
        elif merged.executed_payload_hash is not None:
            self._record.derivation_binding = ev.DerivationBinding(
                contract_hash=None,
                executed_payload_hash=merged.executed_payload_hash,
                execution_phase=None,
            )

    def seal(
        self, *, finished_at: str = "", sealed_at: str = ""
    ) -> ev.EvidenceRecord:
        """Seal a complete record (BUILDING → SEALED, complete=true).

        Raises ``EVIDENCE_INCOMPLETE`` (never seals) when required
        observations or bindings are missing — call
        :meth:`seal_partial` to seal the partial record explicitly.
        """
        self._require_open()
        errors = _completeness_errors(self._record)
        if errors:
            raise ev.EvidenceError(
                "EVIDENCE_INCOMPLETE",
                f"missing: {','.join(errors)[:120]}",
            )
        bindings_hash, observations_hash, content_hash = compute_hashes(
            self._record
        )
        sealed = self._record.model_copy(
            update={
                "complete": True,
                "lifecycle": "SEALED",
                "bindings_hash": bindings_hash,
                "observations_hash": observations_hash,
                "content_hash": content_hash,
                "finished_at": finished_at,
                "sealed_at": sealed_at,
            }
        )
        verify_record(sealed)
        self._spent = True
        return sealed

    def seal_partial(
        self,
        *,
        reasons: tuple[str, ...],
        finished_at: str = "",
        sealed_at: str = "",
    ) -> ev.EvidenceRecord:
        """Seal a partial record (BUILDING → INCOMPLETE, complete=false).

        Terminal: the returned record can never become SEALED and can
        never enter verifier handoff. ``reasons`` uses the closed
        ``IncompleteReason``-style vocabulary (validated non-empty).
        """
        self._require_open()
        if not reasons:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "partial seal requires reasons"
            )
        for reason in reasons:
            if not isinstance(reason, str) or not reason.strip():
                raise ev.EvidenceError(
                    "EVIDENCE_MALFORMED", "partial seal reason invalid"
                )
        bindings_hash, observations_hash, content_hash = compute_hashes(
            self._record
        )
        partial = self._record.model_copy(
            update={
                "complete": False,
                "lifecycle": "INCOMPLETE",
                "bindings_hash": bindings_hash,
                "observations_hash": observations_hash,
                "content_hash": content_hash,
                "incomplete_reasons": tuple(reasons),
                "finished_at": finished_at,
                "sealed_at": sealed_at,
            }
        )
        verify_record(partial)
        self._spent = True
        return partial
