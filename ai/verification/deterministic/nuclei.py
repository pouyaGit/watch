"""Nuclei advisory gate (Phase 5I) — observation ONLY, never a verdict.

``NucleiObservation`` is ADVISORY OBSERVATION ONLY. The following can
NEVER directly create CONFIRMED and are never trusted as proof:

- ``finding_like_text_present`` (text-shape signal)
- ``stdout`` / ``stderr`` samples or hashes
- exit status / timed_out / killed
- generic matcher text, caller severity, template severity

The deterministic gate re-validates the frozen 5F binding posture
(template identity + template hash equal the sealed binding;
``argv_digest`` equals the locally recomputed closed-spec argv
digest; execution class is ``nuclei_scan``; target/plan bindings
already passed the gate). Binding mismatch or ambiguous/truncated/
unattributed evidence => UNKNOWN. Clean binding with an advisory
text signal => POTENTIAL at most.

``Nuclei => CONFIRMED`` MUST remain UNREACHABLE in this build: the
architecture defers it until a separately versioned specificity
policy exists. The transition is deliberately absent; attempting it
raises ``VerifierInvariantError``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.execution.nuclei_executor import (
    SERVER_CONTROLLED_NUCLEI_BINARY,
    argv_digest_for,
    build_nuclei_argv,
    build_target_string,
    scratch_dir_for,
)
from ai.schemas import evidence as ev

__all__ = ["NucleiAdvisory", "verify_nuclei_observation"]


@dataclass(frozen=True)
class NucleiAdvisory:
    """Deterministic advisory-gate outcome (POTENTIAL ceiling)."""

    advisory_match: bool
    reason: str


def _recompute_argv_digest(record: ev.EvidenceRecord) -> str:
    """Locally recompute the closed-spec argv digest (5F builders).

    Pure string derivation only: no process creation, no transport.
    """
    target = record.target
    target_string = build_target_string(
        scheme=target.scheme,
        canonical_host=target.host,
        effective_port=target.effective_port,
    )
    template_hash = record.template_binding.template_hash  # type: ignore[union-attr]
    scratch_dir = scratch_dir_for(record.execution_id)
    template_path = f"{scratch_dir}/{template_hash[:16]}.json"
    argv = build_nuclei_argv(
        template_path=template_path, target_string=target_string
    )
    if argv[0] != SERVER_CONTROLLED_NUCLEI_BINARY:
        raise ValueError("argv shape drift")
    return argv_digest_for(argv)


def verify_nuclei_observation(
    record: ev.EvidenceRecord,
) -> NucleiAdvisory:
    """Run the deterministic advisory gate (binding-first)."""
    observation = record.nuclei
    if observation is None:
        return NucleiAdvisory(False, "nuclei_observation_missing")
    binding = record.template_binding
    if binding is None:
        return NucleiAdvisory(False, "template_binding_missing")
    if (
        observation.template_id != binding.template_id
        or observation.template_hash != binding.template_hash
    ):
        return NucleiAdvisory(False, "template_binding_mismatch")
    if record.execution_class != "nuclei_scan":
        return NucleiAdvisory(False, "execution_class_mismatch")
    if record.derivation_binding is not None:
        return NucleiAdvisory(False, "derivation_binding_unexpected")
    try:
        expected_digest = _recompute_argv_digest(record)
    except (ValueError, TypeError):
        return NucleiAdvisory(False, "argv_digest_unrecomputable")
    if observation.argv_digest != expected_digest:
        return NucleiAdvisory(False, "argv_digest_mismatch")
    if observation.timed_out or observation.killed:
        return NucleiAdvisory(False, "nuclei_output_truncated")
    if observation.exit_code is None:
        return NucleiAdvisory(False, "nuclei_exit_unknown")
    # Text-shape signal only: POTENTIAL ceiling. stdout/stderr content
    # is untrusted data and is never parsed for verdicts.
    if observation.finding_like_text_present:
        return NucleiAdvisory(True, "nuclei_advisory_weak")
    return NucleiAdvisory(False, "nuclei_no_advisory_signal")
