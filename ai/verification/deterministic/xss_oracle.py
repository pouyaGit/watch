"""Sealed XSS oracle proof (Phase 5I, pure functions over sealed bytes).

Ports the World A oracle semantics as PURE functions over sealed
``BrowserObservation`` + sealed derivation/binding information. The
legacy execute-and-judge entry point (``ai/verification/verifier.py``)
is NEVER called; no attempt is ever executed. ``ai.verification.oracle`` primitives are reused for
deterministic derivation ONLY (trusted Watch code); every binding
rule around them is re-implemented against sealed evidence.

Executor-owned proof channels (the ONLY route to execution proof):

- E1: exact dialog marker ``D`` with a supported dialog kind. The
  sealed ``dialog_marker_hashes`` cover ``f"{kind}:{message}"``; the
  verifier recomputes ``D`` from the sealed derivation (never trusts
  a caller-supplied D) and requires hash membership for a supported
  kind. Arbitrary strings ("xss confirmed", console text, DOM text)
  can never satisfy E1 — only the exact-D hash counts.
- E2: same-origin ``/.watch-oracle/<D>`` network event. Sealed
  ``oracle_event_hashes`` cover ``f"{channel}:{marker}"``; E2
  requires the exact ``network:D`` hash plus sealed page/endpoint
  origin equality. Wrong-origin events cannot enter the sealed
  channel (5G drops them pre-hash) and the verifier additionally
  re-proves the page origin from the sealed URL.
- E3: exact executed-payload eval marker. ``eval_marker_hashes``
  cover ``f"{operator}:{value}"``; the verifier reconstructs the
  expected executed payload deterministically from the sealed seed +
  the authorized derivation context, enforces the <=240 exact-
  equality precondition (over 240 the channel is disabled, never
  approximated), and only accepts the closed operator set
  {eval, setTimeout:string}.

Never trusted: e1/e2/e3 booleans, executed_script,
correlation_token_in_runtime, console text, DOM text, generic
"script executed" strings, caller claims.

Every channel additionally requires the ordered gate list: marker
identity (hash equality against locally derived expectations),
payload-hash binding, execution identity, program/target binding,
artifact/test-plan binding, phase binding, freshness (seed
re-derivation under the sealed execution binding), anti-harvest (D
absent from all sealed pre-execution material), and same-origin
rules. Any failure => UNKNOWN, never a downgrade-as-proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from ai.evidence import scrubber
from ai.evidence.hashing import hash_payload, sha256_hex
from ai.verification.oracle import (
    ORACLE_PATH_PREFIX,
    OraclePlanner,
    is_valid_oracle_value,
    oracle_seed,
    oracle_value_from_seed,
)
from ai.schemas import evidence as ev
from ai.schemas.execution_authorization import RUN_SALT_AUTHORITY

__all__ = [
    "SUPPORTED_DIALOG_KINDS",
    "SUPPORTED_EVAL_OPERATORS",
    "E3_MAX_PAYLOAD_LENGTH",
    "OracleIdentity",
    "derive_oracle_identity",
    "expected_dialog_hashes",
    "expected_eval_hashes",
    "expected_network_hash",
    "evaluate_sealed_e1",
    "evaluate_sealed_e2",
    "evaluate_sealed_e3",
    "sealed_anti_harvest_violations",
    "page_origin",
    "sealed_texts",
]


SUPPORTED_DIALOG_KINDS = ("alert", "confirm", "prompt")
SUPPORTED_EVAL_OPERATORS = ("eval", "setTimeout:string")
E3_MAX_PAYLOAD_LENGTH = 240


@dataclass(frozen=True)
class OracleIdentity:
    """Locally recomputed oracle identity for one sealed execution."""

    seed: str
    value: str
    phase: str


def derive_oracle_identity(record: ev.EvidenceRecord) -> OracleIdentity:
    """Recompute S/D from the sealed execution binding (never caller claims).

    The 5I analogue of the World A ``run_salt`` freshness gate: the
    seed is re-derived under the sealed execution binding
    (``RUN_SALT_AUTHORITY`` + unique execution_id + sealed phase), so
    a marker replayed from any other execution cannot recompute the
    expected hashes. Raises ``ValueError`` on a missing/incoherent
    derivation binding (fail closed).
    """
    derivation = record.derivation_binding
    if derivation is None:
        raise ValueError("derivation_binding_missing")
    phase = derivation.execution_phase or "oracle"
    if phase not in ("oracle", "stored_submit", "stored_read"):
        raise ValueError("derivation_phase_unknown")
    seed = oracle_seed(RUN_SALT_AUTHORITY, record.execution_id, phase)
    value = oracle_value_from_seed(seed)
    if not is_valid_oracle_value(value) or value == seed:
        raise ValueError("oracle_pair_invalid")
    executed = derivation.executed_payload_hash
    if executed is not None and executed != sha256_hex(value.encode("utf-8")):
        raise ValueError("executed_payload_hash_mismatch")
    return OracleIdentity(seed=seed, value=value, phase=phase)


def expected_dialog_hashes(value: str) -> tuple[str, ...]:
    """Exact-D dialog marker hashes for supported kinds (E1)."""
    out = []
    for kind in SUPPORTED_DIALOG_KINDS:
        text = f"{kind}:{value}"
        out.append(sha256_hex(scrubber.scrub_text(text).encode("utf-8")))
    return tuple(out)


def expected_network_hash(value: str) -> str:
    """Exact-D same-origin network marker hash (E2)."""
    text = f"network:{value}"
    return sha256_hex(scrubber.scrub_text(text).encode("utf-8"))


def expected_eval_hashes(payload: str) -> tuple[str, ...]:
    """Exact-payload eval marker hashes for the closed operator set."""
    out = []
    for operator in SUPPORTED_EVAL_OPERATORS:
        text = f"{operator}:{payload}"
        out.append(sha256_hex(scrubber.scrub_text(text).encode("utf-8")))
    return tuple(out)


def evaluate_sealed_e1(
    observation: ev.BrowserObservation, value: str
) -> bool:
    """E1: an exact-D dialog with a supported kind, hash-proved.

    Substring/prefix/suffix/whitespace/case variants produce a
    different hash and can never match. The advisory ``e1_observed``
    boolean is never consulted.
    """
    if not is_valid_oracle_value(value):
        return False
    if observation.channels_truncated:
        return False
    expected = set(expected_dialog_hashes(value))
    return any(h in expected for h in observation.dialog_marker_hashes)


def page_origin(url: str) -> tuple[str, str, str] | None:
    """Origin extraction over sealed (redacted) URLs."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not host:
        return None
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), host, str(port)


def evaluate_sealed_e2(
    observation: ev.BrowserObservation,
    value: str,
    *,
    endpoint_origin: tuple[str, str, str] | None,
) -> bool:
    """E2: exact ``network:<D>`` hash + sealed same-origin proof.

    The oracle path must be the endpoint origin; the sealed final
    page URL must also be on that origin (an oracle confirmed from an
    unrelated redirect target is rejected). Cross-origin events can
    never enter the sealed channel (frozen 5G drops them pre-hash).
    """
    if not is_valid_oracle_value(value):
        return False
    if observation.channels_truncated:
        return False
    if endpoint_origin is None:
        return False
    expected = expected_network_hash(value)
    if expected not in observation.oracle_event_hashes:
        return False
    page = observation.page_url
    if page is None:
        return False
    final_origin = page_origin(page.redacted_url)
    if final_origin is None or final_origin != endpoint_origin:
        return False
    # The final page must not itself BE the oracle path (a navigation
    # to /.watch-oracle/<D> is not a page-initiated oracle request).
    path = unquote(urlsplit(page.redacted_url).path or "")
    return path != ORACLE_PATH_PREFIX + value


def _planner_context(authorization: object | None) -> str | None:
    derivation = getattr(authorization, "xss_derivation", None)
    if derivation is None:
        return None
    return getattr(derivation, "allowed_context", None)


def expected_executed_payload(
    identity: OracleIdentity,
    authorization: object | None,
    *,
    execution_id: str,
) -> str | None:
    """Reconstruct the expected executed oracle payload (deterministic).

    The payload is planner-owned and deterministic under the sealed
    seed: the planner is invoked with the SAME inputs the executor
    side used (``RUN_SALT_AUTHORITY`` + execution_id + sealed phase),
    and the skeleton family comes from the AUTHORIZED derivation
    contract carried on the provenance record (never from evidence
    text). Returns ``None`` when the context is not plannable.
    """
    context = _planner_context(authorization)
    if not context:
        return None
    planner = OraclePlanner()
    try:
        plan = planner.plan(
            context_type=context,
            case_id="sealed",
            attempt_id=execution_id,
            logical_pair_id="sealed",
            run_salt=RUN_SALT_AUTHORITY,
            phase=identity.phase,
        )
    except ValueError:
        return None
    if not plan.supported:
        return None
    if plan.seed != identity.seed:
        return None
    return plan.payload


def evaluate_sealed_e3(
    observation: ev.BrowserObservation,
    identity: OracleIdentity,
    authorization: object | None,
    *,
    execution_id: str = "",
) -> bool:
    """E3: exact executed-payload eval marker, <=240, closed operators.

    The sealed ``executed_payload_hash`` must equal ``sha256(D)`` (the
    executed identity binding; submitted-vs-executed identities stay
    separate). The expected eval-value preimages are ONLY locally
    derived ones: the reconstructed planner payload (when it fits the
    240-char exact-equality bound) and the executed oracle identity
    ``D`` itself (16 chars; producible in-page only by executing the
    payload's own transform, since D never travels on the wire).
    Over-240 preimages are excluded — never approximated by prefix
    comparison — and only the closed operator set counts
    (``new Function`` unsupported). Advisory booleans are ignored.
    """
    if not is_valid_oracle_value(identity.value):
        return False
    if observation.channels_truncated:
        return False
    executed = observation.executed_payload_hash
    if executed is None or executed != sha256_hex(
        identity.value.encode("utf-8")
    ):
        return False
    preimages: set[str] = set()
    if len(identity.value) <= E3_MAX_PAYLOAD_LENGTH:
        preimages.add(identity.value)
    payload = expected_executed_payload(
        identity, authorization, execution_id=execution_id
    )
    if payload is not None and len(payload) <= E3_MAX_PAYLOAD_LENGTH:
        preimages.add(payload)
    if not preimages:
        return False
    expected: set[str] = set()
    for preimage in preimages:
        expected.update(expected_eval_hashes(preimage))
    return any(h in expected for h in observation.eval_marker_hashes)


def sealed_texts(record: ev.EvidenceRecord) -> tuple[str, ...]:
    """Every sealed pre-execution observable text (anti-harvest surface).

    Post-execution executor-owned oracle evidence (marker hashes) has
    NO representation here — mirrors the World A ``PreExecutionInput``
    structural boundary.
    """
    texts: list[str] = []
    http = record.http
    if http is not None:
        texts.append(http.request_url.redacted_url)
        if http.request_body_sample:
            texts.append(http.request_body_sample)
        if http.response_body_sample:
            texts.append(http.response_body_sample)
        for hop in http.redirect_chain:
            texts.append(hop.redacted_url)
        for snapshot in (http.request_headers, http.response_headers):
            for value in snapshot.headers.values():
                texts.append(value)
    browser = record.browser
    if browser is not None and browser.page_url is not None:
        texts.append(browser.page_url.redacted_url)
    return tuple(text for text in texts if text)


def sealed_anti_harvest_violations(
    identity: OracleIdentity, record: ev.EvidenceRecord
) -> tuple[str, ...]:
    """D must not occur in ANY sealed pre-execution observable.

    S MAY occur (it travels inside the payload by design). D occurring
    on the wire would mean the oracle value was harvested, defeating
    the anti-harvest property — fail closed.
    """
    violations: list[str] = []
    value = identity.value
    if not is_valid_oracle_value(value):
        return ("invalid_oracle_value",)
    for index, text in enumerate(sealed_texts(record)):
        if value and value in text:
            violations.append(f"oracle_value_on_wire:sealed_text:{index}")
    return tuple(violations)


def contract_hash_matches(
    record: ev.EvidenceRecord, authorization: object | None
) -> bool:
    """Sealed derivation contract matches the authorized contract."""
    derivation = record.derivation_binding
    if derivation is None or not derivation.contract_hash:
        return False
    authorized = getattr(authorization, "xss_derivation", None)
    if authorized is None:
        return True  # no authorized contract to compare; phase check governs
    recomputed = hash_payload(authorized.model_dump(mode="json"))
    return recomputed == derivation.contract_hash


__all__ += [
    "OracleIdentity",
    "contract_hash_matches",
    "derive_oracle_identity",
    "expected_executed_payload",
    "sealed_anti_harvest_violations",
    "sealed_texts",
]
