"""Allowlist of scripts the dashboard may launch.

Task ids, script paths and arguments come only from this static table; caller
input can select a tool and a scope that already exists in Programs. Entries are
validated at import and fail closed.

arg_style:
  none              whole-DB script, no scope argument (scope must be "all")
  filter_flag       accepts --filter <domain>
  positional_domain takes the domain as its last argument
heavy: the same work as a watch-heavy.service lane; never run beside that service.
max_minutes_flag: the script itself accepts --max-minutes; otherwise the runner
enforces the budget with a watchdog.
"""
import os

PROJECT_ROOT = "/opt/watch"
VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "bin", "python3")

ALLOWED_SCRIPT_DIRS = ("enum", "ns", "http", "crawl")
ARG_STYLES = ("none", "filter_flag", "positional_domain")

SYSTEM_UNITS = ("watch.service", "watch-heavy.service", "watch-ct-stream.service")
SYSTEM_ACTIONS = ("stop", "restart")
HEAVY_UNIT = "watch-heavy.service"

_FORBIDDEN_CHARS = frozenset({";", "&", "|", "$", "`", "\n", "\r", "\x00"})

TASKS_REGISTRY = {
    "enum": {
        "tool": "enum_all",
        "name": "Enum (all subdomain sources)",
        "script": os.path.join(PROJECT_ROOT, "enum", "watch_enum_all.py"),
        "default_args": [],
        "arg_style": "none",
        "supports_all": True,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "dns_resolve": {
        "tool": "ns_all",
        "name": "DNS resolve (all)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_ns_all.py"),
        "default_args": [],
        "arg_style": "none",
        "supports_all": True,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "http": {
        "tool": "http",
        "name": "HTTP probe (all)",
        "script": os.path.join(PROJECT_ROOT, "http", "watch_http_all.py"),
        "default_args": [],
        "arg_style": "none",
        "supports_all": True,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "crawl_fresh": {
        "tool": "crawl_fresh",
        "name": "Crawl fresh (24h live subs)",
        "script": os.path.join(PROJECT_ROOT, "crawl", "watch_crawl_fresh.py"),
        "default_args": [],
        "arg_style": "none",
        "supports_all": True,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "crawl_all": {
        "tool": "katana",
        "name": "Crawl (katana)",
        "script": os.path.join(PROJECT_ROOT, "crawl", "watch_crawl_all.py"),
        "default_args": ["--max-minutes", "300"],
        "arg_style": "filter_flag",
        "supports_all": True,
        "max_minutes_flag": True,
        "heavy": True,
    },
    "param_discovery": {
        "tool": "x8",
        "name": "Parameter discovery (x8)",
        "script": os.path.join(PROJECT_ROOT, "crawl", "watch_param_discovery.py"),
        "default_args": ["--max-minutes", "180"],
        "arg_style": "filter_flag",
        "supports_all": True,
        "max_minutes_flag": True,
        "heavy": True,
    },
    "dns_precheck": {
        "tool": "dns_precheck",
        "name": "DNS bruteforce precheck",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_dns_precheck.py"),
        "default_args": ["--max-minutes", "60"],
        "arg_style": "filter_flag",
        "supports_all": True,
        "max_minutes_flag": True,
        "heavy": False,
    },
    "dns_static": {
        "tool": "dns_static",
        "name": "DNS bruteforce (static)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_dns_static.py"),
        "default_args": ["--max-minutes", "180"],
        "arg_style": "filter_flag",
        "supports_all": True,
        "max_minutes_flag": True,
        "heavy": False,
    },
    "dns_dynamic": {
        "tool": "dns_dynamic",
        "name": "DNS bruteforce (dynamic)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_dns_dynamic.py"),
        "default_args": ["--max-minutes", "180"],
        "arg_style": "filter_flag",
        "supports_all": True,
        "max_minutes_flag": True,
        "heavy": False,
    },
    "subfinder": {
        "tool": "subfinder",
        "name": "Subfinder",
        "script": os.path.join(PROJECT_ROOT, "enum", "watch_subfinder.py"),
        "default_args": [],
        "arg_style": "positional_domain",
        "supports_all": False,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "crtsh": {
        "tool": "crtsh",
        "name": "crt.sh",
        "script": os.path.join(PROJECT_ROOT, "enum", "watch_crtsh.py"),
        "default_args": [],
        "arg_style": "positional_domain",
        "supports_all": False,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "certspotter": {
        "tool": "certspotter",
        "name": "Certspotter",
        "script": os.path.join(PROJECT_ROOT, "enum", "watch_certspotter.py"),
        "default_args": [],
        "arg_style": "positional_domain",
        "supports_all": False,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "ns_domain": {
        "tool": "ns",
        "name": "DNS resolve (per domain)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_ns.py"),
        "default_args": [],
        "arg_style": "positional_domain",
        "supports_all": False,
        "max_minutes_flag": False,
        "heavy": False,
    },
    "brute": {
        "tool": "brute",
        "name": "DNS brute (heavy lane)",
        "script": os.path.join(PROJECT_ROOT, "ns", "watch_brute_worker.py"),
        "default_args": ["--max-minutes", "300"],
        "arg_style": "filter_flag",
        "supports_all": True,
        "max_minutes_flag": True,
        "heavy": True,
    },
}

TOOL_TO_TASK = {entry["tool"]: task_id for task_id, entry in TASKS_REGISTRY.items()}


def get_task(task_id: str):
    if not isinstance(task_id, str):
        return None
    return TASKS_REGISTRY.get(task_id)


def _validate_entry(task_id: str, entry: dict) -> None:
    if not isinstance(task_id, str) or not task_id or "/" in task_id:
        raise ValueError(f"unsafe task_id: {task_id!r}")
    if any(c in _FORBIDDEN_CHARS for c in task_id):
        raise ValueError(f"unsafe task_id: {task_id!r}")
    tool = entry.get("tool")
    if not isinstance(tool, str) or not tool.replace("_", "").isalnum() or not tool.islower():
        raise ValueError(f"tool name must be lowercase alphanumeric for {task_id!r}")
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
        raise ValueError(f"script directory {rel_dir!r} is not allowlisted for {task_id!r}")
    if not normalized.endswith(".py"):
        raise ValueError(f"script must be a .py file for {task_id!r}")
    args = entry.get("default_args", [])
    if not isinstance(args, (list, tuple)):
        raise TypeError(f"default_args must be a list for {task_id!r}")
    for arg in args:
        if not isinstance(arg, str) or any(c in _FORBIDDEN_CHARS for c in arg):
            raise ValueError(f"default_args carry unsafe characters for {task_id!r}")
    if entry.get("arg_style") not in ARG_STYLES:
        raise ValueError(f"arg_style must be one of {ARG_STYLES} for {task_id!r}")
    for flag in ("supports_all", "max_minutes_flag", "heavy"):
        if not isinstance(entry.get(flag), bool):
            raise TypeError(f"{flag} must be a bool for {task_id!r}")
    if entry["arg_style"] == "positional_domain" and entry["supports_all"]:
        raise ValueError(f"positional_domain tools cannot support whole-DB runs: {task_id!r}")
    if entry["max_minutes_flag"] and "--max-minutes" not in args:
        raise ValueError(f"max_minutes_flag set without --max-minutes default for {task_id!r}")
    if not entry["max_minutes_flag"] and "--max-minutes" in args:
        raise ValueError(f"--max-minutes in default_args without max_minutes_flag for {task_id!r}")


for _task_id, _entry in TASKS_REGISTRY.items():
    _validate_entry(_task_id, _entry)

if len(TOOL_TO_TASK) != len(TASKS_REGISTRY):
    raise ValueError("tool names must be unique across TASKS_REGISTRY")
