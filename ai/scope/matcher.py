"""Deterministic label-aware host matching (Phase 5D).

Two rule kinds, zero substring logic:

- ``exact``: rule host equals the candidate host (string equality on
  canonical forms — both sides are canonical by construction).
- ``wildcard`` (base ``example.com`` for text ``*.example.com``):
  the candidate has EXACTLY one more label than the base and all
  trailing labels equal the base labels.

There is deliberately no ``endswith``/``contains``/regex path:
``evil-example.com`` cannot match ``example.com`` because label
comparison fails on the first differing label, and depth/apex rules
fall out of label counting. IP candidates never match host rules —
the evaluator routes them to the address gate instead (and the
policy compiler refuses IP-shaped rules, so a match call with an IP
candidate simply matches nothing).

This module is PURE and DETERMINISTIC: no network, no DNS, no
database, no LLM. No ``re`` (regex is banned from the matcher to
exclude ReDoS); splitting on ``.`` over already-validated canonical
names is total and linear.
"""

from __future__ import annotations

from ai.scope.policy import ScopeRule

__all__ = [
    "split_labels",
    "match_rule",
    "match_inclusions",
    "match_exclusions",
]


def split_labels(canonical_host: str) -> tuple[str, ...]:
    """Label-split a canonical hostname (caller guarantees canonical)."""

    if not isinstance(canonical_host, str) or not canonical_host:
        raise TypeError("split_labels accepts only a non-empty string")
    return tuple(canonical_host.split("."))


def match_rule(rule: ScopeRule, candidate_host: str) -> bool:
    """True when one compiled rule matches a canonical candidate."""

    if not isinstance(rule, ScopeRule):
        raise TypeError(
            "match_rule accepts only ScopeRule, "
            f"not {type(rule).__name__}"
        )
    if not isinstance(candidate_host, str) or not candidate_host:
        raise TypeError("candidate must be a non-empty string")
    if rule.kind == "exact":
        return candidate_host == rule.host
    if rule.kind == "wildcard":
        candidate = split_labels(candidate_host)
        base = split_labels(rule.host)
        # Exactly one additional leftmost label: apex excluded (equal
        # length), deeper descendants excluded (longer).
        if len(candidate) != len(base) + 1:
            return False
        return candidate[1:] == base
    raise TypeError(f"unknown rule kind: {rule.kind!r}")


def match_inclusions(
    inclusions: tuple[ScopeRule, ...], candidate_host: str
) -> ScopeRule | None:
    """First matching inclusion rule, or None (deterministic order)."""

    for rule in inclusions:
        if match_rule(rule, candidate_host):
            return rule
    return None


def match_exclusions(
    exclusions: tuple[ScopeRule, ...], candidate_host: str
) -> ScopeRule | None:
    """First matching exclusion rule, or None (deterministic order)."""

    for rule in exclusions:
        if match_rule(rule, candidate_host):
            return rule
    return None
