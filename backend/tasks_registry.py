"""
backend/tasks_registry.py — The single source of truth for runnable scripts.

Anything user-supplied that would influence which script gets executed MUST
go through this allowlist. No other code path builds a script path or shell
command from user input.

Adding a new task: drop a new entry here. Nothing else needs to change.

Phase P1 hardening: every entry is validated at import (fail closed).
Only explicit allowlisted identifiers in this static dict may ever run:
task ids, scripts, and arguments are NEVER taken from caller input —
``backend/task_runner.py`` resolves the script path exclusively from
the validated entry, spawns it with ``shell=False`` (argv list, no
shell), and re-checks path confinement at launch time.
"""
import os

PROJECT_ROOT = "/opt/watch"
VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "bin", "python3")

#: Subdirectories of PROJECT_ROOT whose scripts may be registered.
#: Security-execution-adjacent modules (legacy verification, finding,
#: and live-runner code, plus the disabled legacy job entrypoint) live
#: outside these directories and therefore cannot be registered.
ALLOWED_SCRIPT_DIRS = ("crawl", "ns")

#: Characters that must never appear in task ids, script paths, or
#: default arguments (shell metacharacters + control characters).
_FORBIDDEN_CHARS = frozenset({";", "&", "|", "$", "`", "\n", "\r", "\x00"})

# task_id -> { name, script, default_args }
#
# - name: human-readable label shown in the UI
# - script: ABSOLUTE path to the .py file, executed directly (no shell)
# - default_args: list of CLI args appended to every manual launch
#
# Phase 1 covers the heavy/optional jobs. The core 12h pipeline (watch.timer)
# stays on systemd and is intentionally NOT in this registry -- it's not
# user-editable, doesn't need to be, and exposing it here would let someone
# accidentally trigger it from the dashboard.
TASKS_REGISTRY = {
    "crawl_all": {
        "name": "Crawl All (full corpus)",
        "script": os.path.join(PROJECT_ROOT, "crawl", "watch_crawl_all.py"),
        "default_args": ["--max-minutes", "300"],
    },
    "crawl_fresh": {
        "name": "Crawl Fresh (last 24h live subs)",
        "script": os.path.join(PROJECT_ROOT, "crawl", "watch_crawl_fresh.py"),
        "default_args": [],
    },
    "param_discovery": {
        "name": "Parameter Discovery (x8)",
        "script": os.path.join(PROJECT_ROOT, "crawl", "watch_param_discovery.py"),
        "default_args": ["--max-minutes", "180"],
    },
    "dns_precheck": {
        "name": "DNS Bruteforce Precheck",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_dns_precheck.py"),
        "default_args": ["--max-minutes", "60"],
    },
    "dns_static": {
        "name": "DNS Bruteforce (static wordlist)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_dns_static.py"),
        "default_args": ["--max-minutes", "180"],
    },
    "dns_dynamic": {
        "name": "DNS Bruteforce (dynamic / AlterX)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_dns_dynamic.py"),
        "default_args": ["--max-minutes", "180"],
    },
}


def get_task(task_id: str):
    """Return the registry entry for task_id, or None if unknown.

    Callers (task_runner, routers) MUST check the result and 404 on None --
    this is the allowlist enforcement point.
    """
    return TASKS_REGISTRY.get(task_id)


def _validate_entry(task_id: str, entry: dict) -> None:
    """Fail closed on any registry entry that could escape confinement.

    Raises ValueError/TypeError at import time so a bad edit can never
    become a runnable job. This is a static-registry guard, not a
    runtime filter: caller input never reaches this function.
    """
    if not isinstance(task_id, str) or not task_id:
        raise TypeError(f"task_id must be a non-empty string, got {task_id!r}")
    if any(c in _FORBIDDEN_CHARS or c == "/" for c in task_id):
        raise ValueError(f"task_id carries unsafe characters: {task_id!r}")
    if not isinstance(entry, dict):
        raise TypeError(f"registry entry must be a dict for {task_id!r}")
    script = entry.get("script")
    if not isinstance(script, str) or not script:
        raise TypeError(f"script must be a non-empty string for {task_id!r}")
    if any(c in _FORBIDDEN_CHARS for c in script):
        raise ValueError(f"script carries unsafe characters for {task_id!r}")
    normalized = os.path.normpath(script)
    if not os.path.isabs(normalized) or normalized != script:
        raise ValueError(f"script must be a normalized absolute path for {task_id!r}")
    if os.path.commonpath([normalized, PROJECT_ROOT]) != PROJECT_ROOT:
        raise ValueError(f"script escapes PROJECT_ROOT for {task_id!r}")
    rel_dir = os.path.dirname(os.path.relpath(normalized, PROJECT_ROOT))
    if rel_dir not in ALLOWED_SCRIPT_DIRS:
        raise ValueError(
            f"script directory {rel_dir!r} is not allowlisted for {task_id!r}"
        )
    if not normalized.endswith(".py"):
        raise ValueError(f"script must be a .py file for {task_id!r}")
    args = entry.get("default_args", [])
    if not isinstance(args, (list, tuple)):
        raise TypeError(f"default_args must be a list for {task_id!r}")
    for arg in args:
        if not isinstance(arg, str):
            raise TypeError(f"default_args must be strings for {task_id!r}")
        if any(c in _FORBIDDEN_CHARS for c in arg):
            raise ValueError(
                f"default_args carry unsafe characters for {task_id!r}"
            )


def _validate_registry() -> None:
    for task_id, entry in TASKS_REGISTRY.items():
        _validate_entry(task_id, entry)


_validate_registry()


def all_tasks():
    """Yield (task_id, entry) pairs in a stable order (registry insertion order)."""
    for task_id, entry in TASKS_REGISTRY.items():
        yield task_id, entry


def task_ids():
    """Just the task_ids, in registry order."""
    return list(TASKS_REGISTRY.keys())