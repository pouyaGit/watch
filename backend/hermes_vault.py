"""Read-only bridge to the Hermes autofill vault (metadata only — never secret values).

The Hermes vault lives at ``~/.hermes/vault/``, encrypted at rest with a local Fernet
key, and its code + crypto deps ship in a separate install under
``/usr/local/lib/hermes-agent`` with its own venv. Rather than couple watch's venv to
Hermes internals, we shell out to Hermes's own interpreter and let it emit item
*metadata* as JSON via ``VaultStore.list_items()``. Deletion goes through
``VaultStore.remove_item()`` by handle.

Secret values (passwords, card numbers, TOTP seeds) are NEVER read or transmitted here:
``list_items()`` / ``VaultItemMeta.to_dict()`` are metadata-only by design, and we never
call ``resolve_secret``. The watch dashboard is plain HTTP on a public bind, so this
stays strictly a viewer + delete surface; adding credentials is left to the
``hermes vault add`` CLI where the plaintext never crosses the network.
"""
import json
import os
import subprocess
from pathlib import Path

HERMES_PY = "/usr/local/lib/hermes-agent/venv/bin/python"
HERMES_ROOT = "/usr/local/lib/hermes-agent"
# Pin the home so resolution never depends on the service's HOME env.
HERMES_HOME = "/root/.hermes"

# argv: [py, "-c", SCRIPT, HERMES_ROOT, *extra]
_LIST_SCRIPT = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from agent.vault_store import VaultStore\n"
    "print(json.dumps([m.to_dict() for m in VaultStore().list_items()]))\n"
)

_REMOVE_SCRIPT = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from agent.vault_store import VaultStore\n"
    "sys.exit(0 if VaultStore().remove_item(sys.argv[2]) else 2)\n"
)


class VaultUnavailable(Exception):
    """The Hermes vault could not be reached (not installed, crypto error, etc.)."""


def _env():
    env = dict(os.environ)
    env["HERMES_HOME"] = HERMES_HOME
    env.setdefault("HOME", "/root")
    return env


def available():
    return Path(HERMES_PY).exists() and Path(HERMES_ROOT).is_dir()


def _run(script, *extra, timeout=15):
    try:
        return subprocess.run(
            [HERMES_PY, "-c", script, HERMES_ROOT, *extra],
            capture_output=True, text=True, timeout=timeout, env=_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VaultUnavailable(str(exc))


def list_items():
    """Return a list of metadata dicts (id, kind, label, origin, identifier, …).

    Raises VaultUnavailable on any failure so the page can show a clear note."""
    if not available():
        raise VaultUnavailable("Hermes is not installed on this host")
    proc = _run(_LIST_SCRIPT)
    if proc.returncode != 0:
        raise VaultUnavailable(proc.stderr.strip() or f"exit {proc.returncode}")
    try:
        items = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise VaultUnavailable(f"unexpected vault output: {exc}")
    items.sort(key=lambda m: (m.get("kind", ""), (m.get("label") or "").lower()))
    return items


def remove_item(item_id):
    """Delete one vault item by handle. True if removed, False if no such handle."""
    if not available():
        raise VaultUnavailable("Hermes is not installed on this host")
    proc = _run(_REMOVE_SCRIPT, item_id)
    if proc.returncode == 0:
        return True
    if proc.returncode == 2:
        return False
    raise VaultUnavailable(proc.stderr.strip() or f"exit {proc.returncode}")
