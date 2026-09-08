"""TargetResolver boundary (Phase 5C).

Fresh canonical target representation for authorized executions.
Read-only, deterministic, offline: no verdicts, no scope decisions,
no network, no LLM, no database driver, no execution.
"""

from ai.resolver.canonicalization import (
    CanonicalAuthority,
    CanonicalizationError,
    canonicalize_host,
    canonicalize_port,
    canonicalize_scheme,
    canonicalize_target,
)
from ai.resolver.dns import (
    DNS_ERROR_CODES,
    MAX_DNS_ANSWERS,
    DnsError,
    DnsResolver,
    FakeDnsFailure,
    FakeDnsResolver,
    classify_address,
    validate_answers,
)
from ai.resolver.inventory import (
    AssetRecord,
    InMemoryInventoryRepository,
    InventoryError,
    InventoryRepository,
    ProgramRecord,
    scope_lists_hash_for,
)
from ai.resolver.resolver import TargetResolver

__all__ = [
    "CanonicalAuthority",
    "CanonicalizationError",
    "canonicalize_host",
    "canonicalize_port",
    "canonicalize_scheme",
    "canonicalize_target",
    "DNS_ERROR_CODES",
    "MAX_DNS_ANSWERS",
    "DnsError",
    "DnsResolver",
    "FakeDnsFailure",
    "FakeDnsResolver",
    "classify_address",
    "validate_answers",
    "AssetRecord",
    "InMemoryInventoryRepository",
    "InventoryError",
    "InventoryRepository",
    "ProgramRecord",
    "scope_lists_hash_for",
    "TargetResolver",
]
