"""backend/research_agents/llm_guard.py — free-only cost guard (Phase 1/9).

The ONLY allowed LLM path in this deployment:

    OpenRouter  ->  model ``openrouter/free``  (OpenRouter's free router)

This module is the single gate every LLM-enabled job passes through.  In
free-only mode (default; ``WATCH_AGENT_LLM_MODE=free``) it fails closed on:

* any provider other than OPENROUTER
* any model other than ``openrouter/free`` (paid, unknown, or another free
  model — no silent substitution, no fallback, no downgrade path exists)
* an env ``OPENROUTER_MODEL`` that is set to anything but the free router
* an env ``OPENROUTER_BASE_URL`` that is not the OpenRouter API host
* a missing/blank ``OPENROUTER_API_KEY``

``WATCH_AGENT_LLM_MODE=off`` rejects any LLM request entirely; any other
mode value is invalid and rejected.  The key is never read into a value
this module returns — only presence is reported, and the indicator projection
can never contain it.
"""

from __future__ import annotations

import os

FREE_ONLY_RULE_VERSION = "agent-intelligence-v1-free-only"
FREE_MODEL = "openrouter/free"
PROVIDER_LABEL = "OpenRouter Free"
ALLOWED_PROVIDER_KINDS = frozenset({"OPENROUTER"})
OPENROUTER_BASE_PREFIX = "https://openrouter.ai"
KEY_ENV = "OPENROUTER_API_KEY"
MODEL_ENV = "OPENROUTER_MODEL"
BASE_URL_ENV = "OPENROUTER_BASE_URL"
MODE_ENV = "WATCH_AGENT_LLM_MODE"


class FreeOnlyViolation(Exception):
    """Fail-closed rejection of any non-free LLM configuration."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = str(reason)[:120]


def _b(value: object, limit: int = 60) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def llm_mode() -> str:
    """Current cost-guard mode: ``free`` (default) or ``off``; else raise."""

    raw = os.environ.get(MODE_ENV, "")
    mode = str(raw or "").strip().lower()
    if mode in ("", "free"):
        return "free"
    if mode == "off":
        return "off"
    raise FreeOnlyViolation(f"invalid_llm_mode:{_b(mode)}")


def resolve_free_config(provider_kind: object = None,
                        requested_model: object = None,
                        timeout_seconds: int = 30) -> dict:
    """Validate and resolve the free-only LLM configuration.

    Returns a key-free projection: provider kind, requested model, label,
    timeout.  Raises :class:`FreeOnlyViolation` on every non-free or
    incomplete configuration — there is no fallback branch.
    """

    mode = llm_mode()          # raises on invalid mode
    if mode == "off":
        raise FreeOnlyViolation("llm_mode_off")

    kind = str(provider_kind or "").strip().upper()
    if kind not in ALLOWED_PROVIDER_KINDS:
        raise FreeOnlyViolation(f"provider_not_allowed:{_b(kind)}")

    model = str(requested_model or "").strip() or FREE_MODEL
    if model != FREE_MODEL:
        # covers paid models, unknown models and other free-model ids
        raise FreeOnlyViolation(f"model_not_free:{_b(model)}")

    env_model = str(os.environ.get(MODEL_ENV, "") or "").strip()
    if env_model and env_model != FREE_MODEL:
        raise FreeOnlyViolation(f"env_model_not_free:{_b(env_model)}")

    env_base = str(os.environ.get(BASE_URL_ENV, "") or "").strip()
    if env_base and not env_base.startswith(OPENROUTER_BASE_PREFIX):
        raise FreeOnlyViolation(f"base_url_not_openrouter:{_b(env_base)}")

    if not str(os.environ.get(KEY_ENV, "") or "").strip():
        raise FreeOnlyViolation("missing_openrouter_api_key")

    return {
        "rule_version": FREE_ONLY_RULE_VERSION,
        "provider_kind": "OPENROUTER",
        "provider_label": PROVIDER_LABEL,
        "requested_model": FREE_MODEL,
        "base_url_env_ok": True,
        "timeout_seconds": int(timeout_seconds),
        "key_configured": True,      # presence only, never the value
    }


def llm_indicator() -> dict:
    """Safe runtime configuration indicator (Phase 9) — never a secret."""

    try:
        mode = llm_mode()
    except FreeOnlyViolation as exc:
        return {"rule_version": FREE_ONLY_RULE_VERSION, "enabled": False,
                "provider_label": "", "requested_model": "",
                "key_configured": False, "reason": exc.reason}
    if mode == "off":
        return {"rule_version": FREE_ONLY_RULE_VERSION, "enabled": False,
                "provider_label": PROVIDER_LABEL,
                "requested_model": FREE_MODEL,
                "key_configured": False, "reason": "llm_mode_off"}
    key_ok = bool(str(os.environ.get(KEY_ENV, "") or "").strip())
    try:
        resolve_free_config("OPENROUTER", FREE_MODEL)
        enabled = True
        reason = ""
    except FreeOnlyViolation as exc:
        enabled = False
        reason = exc.reason
    return {
        "rule_version": FREE_ONLY_RULE_VERSION,
        "enabled": enabled,
        "provider_label": PROVIDER_LABEL,
        "requested_model": FREE_MODEL,
        "key_configured": key_ok,
        "reason": reason,
    }


__all__ = [
    "ALLOWED_PROVIDER_KINDS",
    "FREE_MODEL",
    "FREE_ONLY_RULE_VERSION",
    "FreeOnlyViolation",
    "PROVIDER_LABEL",
    "llm_indicator",
    "llm_mode",
    "resolve_free_config",
]
