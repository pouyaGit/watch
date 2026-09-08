"""ScopeEvaluator boundary (Phase 5D).

Centralized deterministic scope authority over 5C canonical facts
and freshly read hashed policy. No verdicts, no network, no DNS, no
LLM, no database driver, no execution.
"""

from ai.scope.evaluator import (
    MAX_LOCATION_LENGTH,
    MAX_REDIRECT_EDGES,
    HopObservation,
    ScopeEvaluator,
    require_allowed,
)
from ai.scope.matcher import (
    match_exclusions,
    match_inclusions,
    match_rule,
    split_labels,
)
from ai.scope.policy import (
    MAX_POLICY_ENTRIES,
    MAX_POLICY_ENTRY_LENGTH,
    CompiledScopePolicy,
    InMemoryPolicyStore,
    PolicyError,
    PolicyStore,
    ScopeRule,
    compile_entry,
    compile_policy,
)

__all__ = [
    "MAX_LOCATION_LENGTH",
    "MAX_REDIRECT_EDGES",
    "HopObservation",
    "ScopeEvaluator",
    "require_allowed",
    "match_exclusions",
    "match_inclusions",
    "match_rule",
    "split_labels",
    "MAX_POLICY_ENTRIES",
    "MAX_POLICY_ENTRY_LENGTH",
    "CompiledScopePolicy",
    "InMemoryPolicyStore",
    "PolicyError",
    "PolicyStore",
    "ScopeRule",
    "compile_entry",
    "compile_policy",
]
