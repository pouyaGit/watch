"""Canonical SHA-256 hashing over normalized JSON (Phase 5H-core).

Single shared implementation used by evidence sealing and by every
revalidation path (builder, orphan recovery, handoff). No per-caller
variants exist by design.

Rules (frozen):

- ``SHA-256`` only.
- Canonical JSON: ``sort_keys=True``, ``separators=(",", ":")``,
  ``ensure_ascii=False``, UTF-8 bytes.
- Normalization before hashing: absent optional == explicit null
  (missing keys are injected as null inside known model shapes);
  newline normalization (``\\r\\n``/``\\r`` -> ``\\n``) for text
  sample leaves; booleans stay booleans; integers stay integers.
- Timestamps and all other audit-only leaves are stripped by the
  payload builders in ``ai.schemas.evidence`` callers — this module
  additionally refuses any mapping containing a forbidden
  timestamp/audit key, so a caller that forgets to strip fails
  closed instead of forking identity.
- No ``repr()``, no ``str(dict)``, no sets, no floats, no bytes
  leaves (bytes enter only as hashes or tagged text).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = [
    "sha256_hex",
    "canonical_json",
    "normalize_for_hash",
    "hash_payload",
    "hash_text",
    "AUDIT_ONLY_KEYS",
]

#: Leaves that must never participate in content identity. Presence
#: in a hash payload raises ``TypeError`` (fail closed).
AUDIT_ONLY_KEYS = frozenset(
    {
        "started_at",
        "finished_at",
        "sealed_at",
        "duration_ms",
        "duration_seconds",
        "worker_pid",
        "worker_hostname",
        "scheduler_metadata",
        "caller_labels",
        "attempt_count",
        "attempt_counters",
        "notes",
        "expected_behavior",
        "llm_prose",
        "audit_seq",
    }
)


def sha256_hex(data: bytes) -> str:
    """SHA-256 over exact bytes (hex, lowercase)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(
            "sha256_hex accepts only bytes, "
            f"not {type(data).__name__}"
        )
    return hashlib.sha256(bytes(data)).hexdigest()


def hash_text(text: str) -> str:
    """SHA-256 over the UTF-8 bytes of ``text`` (newline-normalized)."""
    if not isinstance(text, str):
        raise TypeError(
            "hash_text accepts only str, " f"not {type(text).__name__}"
        )
    return sha256_hex(text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8"))


def canonical_json(payload: dict) -> str:
    """Canonical JSON string for a normalized mapping."""
    if not isinstance(payload, dict):
        raise TypeError(
            "canonical_json accepts only dict, "
            f"not {type(payload).__name__}"
        )
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def normalize_for_hash(value: Any) -> Any:
    """Normalize a JSON value for deterministic hashing.

    - mappings: keys must be strings; values normalized recursively.
    - ``None`` is preserved; callers inject null for absent
      optionals before calling (absent == null by construction).
    - strings: newline-normalized (``\\r\\n``/``\\r`` -> ``\\n``).
    - booleans/ints: preserved exactly (``True`` is not ``1``;
      callers must not mix them).
    - lists/tuples: order-preserving, items normalized.
    - Anything else (float, bytes, set, custom object) raises
      ``TypeError`` — floats would fork identity across platforms.
    """
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return value.replace("\r\n", "\n").replace("\r", "\n")
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    "hash payload mapping keys must be strings, "
                    f"not {type(key).__name__}"
                )
            if key in AUDIT_ONLY_KEYS:
                raise TypeError(
                    f"audit-only key must not enter content identity: {key!r}"
                )
            normalized[key] = normalize_for_hash(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [normalize_for_hash(item) for item in value]
    raise TypeError(
        "hash payload leaves must be str/int/bool/null/list/mapping, "
        f"not {type(value).__name__}"
    )


def hash_payload(payload: dict) -> str:
    """SHA-256 over the canonical JSON of a normalized mapping."""
    normalized = normalize_for_hash(payload)
    if not isinstance(normalized, dict):  # pragma: no cover - defensive
        raise TypeError("hash payload must normalize to a mapping")
    return sha256_hex(canonical_json(normalized).encode("utf-8"))
