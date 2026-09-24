#!/usr/bin/env python3
"""Shared fixtures for the EPIC10 incremental-DNS test suites.

The production prior-state provider reads MongoDB (`Subdomains` /
`LiveSubdomains`). Tests must never touch a live database, so they install a
deterministic provider through the documented injection hook
(`utils.dns_incremental.set_prior_lookup_provider`) and point the attempt store
at a temp file.

`passthrough_provider` reproduces the pre-EPIC10 world exactly: nothing has ever
been resolved and nothing has ever been attempted, so every candidate is NEW and
selected. Chunking/fail-fast tests that predate EPIC10 use it so their expected
command lists stay valid while still exercising the real selection code path.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from utils import dns_incremental  # noqa: E402
from utils.dns_incremental import (  # noqa: E402
    AttemptState,
    DnsAttemptStore,
    DnsResolutionPolicy,
    PriorResolution,
)

NOW = datetime(2026, 9, 24, 20, 30, 0)


def passthrough_provider(names):
    """No prior resolution, no attempt history: everything is NEW."""
    return {name: PriorResolution() for name in names}


def static_provider(prior_map):
    """Return a provider serving a fixed prior-resolution map."""
    def provider(names):
        return {name: prior_map.get(name, PriorResolution()) for name in names}
    return provider


def static_provider_with_scope(scope, prior_map=None):
    """Prior map where every name carries a scope (for report assertions)."""
    prior_map = prior_map or {}
    def provider(names):
        out = {}
        for name in names:
            base = prior_map.get(name, PriorResolution())
            out[name] = PriorResolution(
                last_resolved=base.last_resolved,
                source_changed=base.source_changed,
                scope=scope)
        return out
    return provider


def install_offline_selection(state_dir):
    """Point the real selection path at offline fakes (for pre-EPIC10 suites).

    EPIC10 wired incremental selection into `utils.common.run_command_in_zsh_ns`,
    so any suite that drives that function now passes through the selector. These
    suites test chunking/fail-fast mechanics and must stay offline: this installs
    the "nothing ever resolved, nothing ever attempted" provider (every candidate
    is NEW, so the command lists are unchanged) and redirects the attempt store
    into a temp directory.

    Returns the previous environment mapping so callers can restore it.
    """
    previous_env = {key: os.environ.get(key) for key in
                    ("DNS_RESOLUTION_ENABLED", "DNS_RESOLUTION_STATE_FILE")}
    os.environ["DNS_RESOLUTION_ENABLED"] = "true"
    os.environ["DNS_RESOLUTION_STATE_FILE"] = os.path.join(state_dir, "state.json")
    dns_incremental.set_prior_lookup_provider(passthrough_provider)
    return previous_env


def restore_offline_selection(previous_env):
    """Undo `install_offline_selection`."""
    dns_incremental.reset_prior_lookup_provider()
    for key, value in (previous_env or {}).items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


class IncrementalTestCase:
    """Mixin: temp state file + injected providers, cleaned up afterwards.

    Not a unittest.TestCase itself -- mixed into the real test classes so each
    suite keeps its own `unittest` base.
    """

    def setUpIncremental(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="epic10-")
        self.state_file = os.path.join(self._tmpdir.name, "state.json")
        self.store = DnsAttemptStore(self.state_file)
        dns_incremental.reset_prior_lookup_provider()
        dns_incremental.set_prior_lookup_provider(passthrough_provider)

    def tearDownIncremental(self):
        dns_incremental.reset_prior_lookup_provider()
        try:
            self._tmpdir.cleanup()
        except Exception:
            pass

    # -- helpers ----------------------------------------------------------
    def policy(self, **kwargs):
        kwargs.setdefault("state_file", self.state_file)
        return DnsResolutionPolicy(**kwargs)

    def resolve(self, name, *, hours_ago=0.0, changed=False, now=NOW, scope=None):
        """PriorResolution for a name resolved `hours_ago` before `now`."""
        return PriorResolution(
            last_resolved=now - timedelta(hours=hours_ago),
            source_changed=changed,
            scope=scope,
        )

    def attempts(self, *, attempts=1, streak=1, last_hours_ago=0.0, now=NOW,
                 last_answer=None):
        return AttemptState(
            attempts=attempts,
            streak=streak,
            last_attempt=now - timedelta(hours=last_hours_ago),
            last_answer=last_answer,
        )

    def select(self, names, *, policy=None, provider=None, store=None, now=NOW,
               reporter=None, **policy_kwargs):
        policy = policy or self.policy(**policy_kwargs)
        return dns_incremental.select_dns_candidates(
            names,
            policy=policy,
            prior_lookup=provider if provider is not None else passthrough_provider,
            store=store if store is not None else self.store,
            now=now,
            reporter=reporter,
        )
