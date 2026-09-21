#!/usr/bin/env python3
"""policy.py — deterministic delivery policy for the Watch agent workspace.

Autonomous Delivery Pipeline v1 (Epic 0).

This module is *policy only*: it decides what may be promoted and what must
block promotion. It never executes anything, never touches the filesystem and
never talks to Git or the network. Every function is pure and deterministic, so
the same input always yields the same verdict — which is what makes the
delivery layer auditable.

Policy surface
--------------
- ALLOWED_PATHS        paths the agent may change
- FORBIDDEN_PATHS      paths the agent must never change (authority chain,
                       production entry points, protected directories)
- SECRET_PATTERNS      files that must never be committed
- ENV_PATTERNS         environment / credential configuration
- SYSTEM_PATTERNS      systemd and OS-level units
- GUARD_PATHS          delivery files whose deletion blocks promotion
- REQUIRED_CHECKS      the six checks that gate promotion
- promotion_verdict()  the promotion rule itself

CLI (read-only, no writes, no execution)::

    policy.py --document       # JSON policy document (stable ordering)
    policy.py --fingerprint    # sha256 of the policy document
    policy.py --verdict        # {"checks": {...}} on stdin -> verdict JSON

Exit codes: 0 = ready, 1 = blocked, 2 = invalid input.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import sys
from typing import Any, Mapping, Sequence

POLICY_VERSION = "delivery-policy/v1"

#: Documented guarantees asserted by the test suite.
POLICY_EXECUTES = False
POLICY_SIDE_EFFECT_FREE = True

AGENT_BRANCH = "agent/daily-development"
MAIN_BRANCH = "main"

VERDICT_READY = "READY FOR PROMOTION"
VERDICT_BLOCKED = "BLOCKED"
CHECK_PASS = "PASS"
CHECK_BLOCK = "BLOCK"
CHECK_SKIPPED = "SKIPPED"

#: Patterns are matched with fnmatch, where ``*`` also crosses ``/``; a pattern
#: ending in ``/*`` therefore covers a whole directory tree.
ALLOWED_PATHS: tuple[str, ...] = (
    ".gitignore",
    "README.md",
    "api.py",
    "aec/*",
    "agent-reports/*",
    "ai/research_agent/*",
    "ai/researcher/*",
    "ai/knowledge/*",
    "ai/reports/*",
    "ai/providers/*",
    "ai/llm/*",
    "ai/scope/*",
    "ai/research_cli.py",
    "ai_data/aec/*",
    "ai_data/investigations/*",
    "ai_data/research/*",
    "backend/*",
    "docs/*",
    "scripts/watch-agent/*",
    "tests/*",
    "web/*",
)

FORBIDDEN_PATHS: tuple[str, ...] = (
    "AGENTS.md",
    "ai/execution/*",
    "ai/evidence/*",
    "ai/verification/*",
    "ai/authorizer/*",
    "ai/finding/*",
    "ai/limits/*",
    "ai/live_validation/*",
    "ai/lab/*",
    "ai/schemas/*",
    "ai_data/nuclei/*",
    "backend/tasks_registry.py",
    "crawl/*",
    "database/*",
    "docker-compose*",
    "ns/*",
    "nuclei/*",
    "run-pipeline.sh",
    "venv/*",
    "watch_xss_verify.py",
    ".github/workflows/*",
)

SECRET_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.keystore",
    "*.p12",
    "*credentials*",
    "*secret*",
    "*id_rsa*",
    "*id_ed25519*",
    ".ssh/*",
    ".netrc",
)

ENV_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
)

SYSTEM_PATTERNS: tuple[str, ...] = (
    "systemd/*",
    "*.service",
    "*.timer",
    "*.socket",
    "/etc/*",
    "/lib/systemd/*",
    "/usr/lib/systemd/*",
)

#: Deleting one of these is a dangerous modification: it removes a gate.
GUARD_PATHS: tuple[str, ...] = (
    "scripts/watch-agent/delivery/policy.py",
    "scripts/watch-agent/delivery/diff_guard.py",
    "scripts/watch-agent/delivery/check.sh",
    "scripts/watch-agent/delivery/status.sh",
    "scripts/watch-agent/delivery/report.sh",
    "tests/test_delivery_policy.py",
    "tests/test_delivery_guard.py",
)

REQUIRED_CHECKS: tuple[str, ...] = (
    "BRANCH",
    "COMMIT",
    "TESTS",
    "PATH_GUARD",
    "REPORT",
    "PRODUCTION_UNTOUCHED",
)

CHECK_DESCRIPTIONS: dict[str, str] = {
    "BRANCH": "the workspace is on the agent branch and epic-owned files are committed",
    "COMMIT": "at least one commit exists between the integration branch and HEAD",
    "TESTS": "the delivery and epic tests pass",
    "PATH_GUARD": "no forbidden path, secret, environment or system file is changed",
    "REPORT": "an agent report is part of the promoted change set",
    "PRODUCTION_UNTOUCHED": "the production checkout still matches the recorded baseline",
}

KIND_SEVERITY: dict[str, str] = {
    # classifications produced by classify_path_kinds()
    "FORBIDDEN": "BLOCK",
    "SECRET": "BLOCK",
    "ENV": "BLOCK",
    "SYSTEM": "BLOCK",
    "ALLOWED": "NONE",
    "UNKNOWN": "WARN",
    # finding kinds produced by diff_guard
    "FORBIDDEN_PATH": "BLOCK",
    "SECRET_FILE": "BLOCK",
    "ENV_CHANGE": "BLOCK",
    "SYSTEM_FILE": "BLOCK",
    "GUARD_DELETED": "BLOCK",
    "PATH_TRAVERSAL": "BLOCK",
    "NO_CHANGES": "BLOCK",
    "UNPARSEABLE_INPUT": "BLOCK",
    "LIVE_GATE_FLIP": "BLOCK",
    "SECRET_CONTENT": "BLOCK",
    "MODE_CHANGE": "WARN",
    "UNKNOWN_PATH": "WARN",
    "BINARY_FILE": "WARN",
    "LARGE_DIFF": "WARN",
}

#: Precedence for the single dominant classification of a path.
KIND_PRECEDENCE: tuple[str, ...] = (
    "FORBIDDEN",
    "SECRET",
    "ENV",
    "SYSTEM",
    "ALLOWED",
    "UNKNOWN",
)

_CLASSIFICATION_KINDS: tuple[str, ...] = ("FORBIDDEN", "SECRET", "ENV", "SYSTEM")

_REPO_PREFIXES: tuple[str, ...] = (
    "opt/watch/.worktrees/watch-agent/",
    "opt/watch/",
)


def normalise_path(path: object) -> str:
    """Canonical, comparable form of a repository-relative path."""
    text = str(path if path is not None else "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    for prefix in _REPO_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    return text


def has_traversal(path: object) -> bool:
    """True when a path tries to escape the repository root."""
    segments = normalise_path(path).split("/")
    return ".." in segments


def matches_any(path: object, patterns: Sequence[str]) -> bool:
    """fnmatch any of the patterns (``*`` crosses ``/``)."""
    text = normalise_path(path)
    if not text:
        return False
    return any(fnmatch.fnmatchcase(text, pattern) for pattern in patterns)


def classify_path_kinds(path: object) -> tuple[str, ...]:
    """All applicable kinds for a path, most severe first. Never raises."""
    if has_traversal(path):
        return ("FORBIDDEN", "PATH_TRAVERSAL")
    kinds: list[str] = []
    if matches_any(path, FORBIDDEN_PATHS):
        kinds.append("FORBIDDEN")
    if matches_any(path, SECRET_PATTERNS):
        kinds.append("SECRET")
    if matches_any(path, ENV_PATTERNS):
        kinds.append("ENV")
    if matches_any(path, SYSTEM_PATTERNS):
        kinds.append("SYSTEM")
    if matches_any(path, ALLOWED_PATHS):
        kinds.append("ALLOWED")
    if not kinds:
        kinds.append("UNKNOWN")
    return tuple(kinds)


def classify_path(path: object) -> str:
    """The single dominant classification of a path."""
    kinds = classify_path_kinds(path)
    for candidate in KIND_PRECEDENCE:
        if candidate in kinds:
            return candidate
    return "UNKNOWN"


def is_allowed_path(path: object) -> bool:
    """True only when the path is explicitly allowed and nothing else."""
    return classify_path_kinds(path) == ("ALLOWED",)


def is_forbidden_path(path: object) -> bool:
    """True for the authority chain, protected directories and CI."""
    kinds = classify_path_kinds(path)
    return "FORBIDDEN" in kinds


def is_secret_path(path: object) -> bool:
    return "SECRET" in classify_path_kinds(path)


def is_env_path(path: object) -> bool:
    return "ENV" in classify_path_kinds(path)


def is_system_path(path: object) -> bool:
    return "SYSTEM" in classify_path_kinds(path)


def is_guard_path(path: object) -> bool:
    """True for the delivery guard files that must never be deleted."""
    return matches_any(path, GUARD_PATHS)


def severity_for(kind: object) -> str:
    """BLOCK for anything that stops promotion, WARN otherwise."""
    return KIND_SEVERITY.get(str(kind), "WARN")


def kind_precedence(kind: object) -> int:
    """Sort position of a kind within the classification precedence."""
    try:
        return KIND_PRECEDENCE.index(str(kind))
    except ValueError:
        return len(KIND_PRECEDENCE)


def policy_document() -> dict[str, Any]:
    """The whole policy as a JSON-serialisable document (stable ordering)."""
    return {
        "policy_version": POLICY_VERSION,
        "agent_branch": AGENT_BRANCH,
        "main_branch": MAIN_BRANCH,
        "executes": POLICY_EXECUTES,
        "side_effect_free": POLICY_SIDE_EFFECT_FREE,
        "allowed_paths": list(ALLOWED_PATHS),
        "forbidden_paths": list(FORBIDDEN_PATHS),
        "secret_patterns": list(SECRET_PATTERNS),
        "env_patterns": list(ENV_PATTERNS),
        "system_patterns": list(SYSTEM_PATTERNS),
        "guard_paths": list(GUARD_PATHS),
        "required_checks": list(REQUIRED_CHECKS),
        "check_descriptions": dict(CHECK_DESCRIPTIONS),
        "kind_severity": dict(KIND_SEVERITY),
        "kind_precedence": list(KIND_PRECEDENCE),
        "verdict_ready": VERDICT_READY,
        "verdict_blocked": VERDICT_BLOCKED,
        "certifications": {
            "auto_merge_main": False,
            "auto_push_main": False,
            "bypass_review": False,
            "stores_credentials": False,
            "modifies_credentials": False,
            "modifies_systemd": False,
        },
    }


def policy_fingerprint() -> str:
    """sha256 over the canonical policy document."""
    canonical = json.dumps(policy_document(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verdict(blocking: Sequence[str], skipped: Sequence[str]) -> dict[str, Any]:
    blocking_sorted = sorted(set(blocking))
    skipped_sorted = sorted(set(skipped))
    if blocking_sorted:
        return {
            "verdict": VERDICT_BLOCKED,
            "blocking": blocking_sorted,
            "warnings": [],
            "skipped": skipped_sorted,
            "blocked": True,
        }
    verdict = VERDICT_READY
    if skipped_sorted:
        verdict = f"{VERDICT_READY} ({', '.join(skipped_sorted)} SKIPPED)"
    return {
        "verdict": verdict,
        "blocking": [],
        "warnings": [],
        "skipped": skipped_sorted,
        "blocked": False,
    }


def promotion_verdict(checks: object) -> dict[str, Any]:
    """Apply the promotion rule to a mapping of check name -> PASS/BLOCK/SKIPPED.

    Fail-closed: a missing check, an unknown check, or a state that is not one
    of the three known states blocks promotion.
    """
    if not isinstance(checks, Mapping):
        return _verdict(["INVALID_CHECK_SET"], [])
    blocking: list[str] = []
    skipped: list[str] = []
    for name in REQUIRED_CHECKS:
        if name not in checks:
            blocking.append(f"CHECK_MISSING:{name}")
            continue
        state = checks[name]
        if not isinstance(state, str):
            blocking.append(f"CHECK_INVALID_STATE:{name}")
            continue
        normalised = state.strip().upper()
        if normalised == CHECK_PASS:
            continue
        if normalised == CHECK_BLOCK:
            blocking.append(f"CHECK_BLOCKED:{name}")
        elif normalised == CHECK_SKIPPED:
            skipped.append(name)
        else:
            blocking.append(f"CHECK_INVALID_STATE:{name}")
    for name in sorted(set(checks) - set(REQUIRED_CHECKS)):
        blocking.append(f"UNKNOWN_CHECK:{name}")
    return _verdict(blocking, skipped)


def main(argv: Sequence[str] | None = None) -> int:
    """Read-only CLI. Prints JSON to stdout; writes nothing."""
    args = [str(item) for item in (argv if argv is not None else sys.argv[1:])]
    if "--document" in args:
        print(json.dumps(policy_document(), indent=2, sort_keys=True))
        return 0
    if "--fingerprint" in args:
        print(policy_fingerprint())
        return 0
    if "--verdict" in args:
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            print(
                json.dumps(
                    {
                        "verdict": VERDICT_BLOCKED,
                        "blocking": ["INVALID_INPUT"],
                        "warnings": [],
                        "skipped": [],
                        "blocked": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 2
        checks = payload.get("checks") if isinstance(payload, Mapping) else None
        result = promotion_verdict(checks if checks is not None else {})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if result["blocked"] else 0
    print(__doc__)
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
