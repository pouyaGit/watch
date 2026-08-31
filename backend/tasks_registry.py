"""
backend/tasks_registry.py — The single source of truth for runnable scripts.

Anything user-supplied that would influence which script gets executed MUST
go through this allowlist. No other code path builds a script path or shell
command from user input.

Adding a new task: drop a new entry here. Nothing else needs to change.
"""
import os

PROJECT_ROOT = "/opt/watch"
VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "bin", "python3")

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


def all_tasks():
    """Yield (task_id, entry) pairs in a stable order (registry insertion order)."""
    for task_id, entry in TASKS_REGISTRY.items():
        yield task_id, entry


def task_ids():
    """Just the task_ids, in registry order."""
    return list(TASKS_REGISTRY.keys())