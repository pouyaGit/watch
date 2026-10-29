#!/usr/bin/env python3
"""Parent-vs-child credential probe for a systemd --user service.

Prints presence and length ONLY. Never a secret value, never a prefix of one.
Safe to run inside production.

    <project>/scripts/cred_probe.py <label>

Emit four blocks per process so two runs diff cleanly:
  1. credential-ish env var NAMES and value lengths
  2. flags the parent injects into the child
  3. the provider resolver's own verdict (model / base_url / key presence /
     credential_pool / get_provider() class / available())
  4. the filesystem view, including whether /tmp is private

Run it twice: once as the service's own PID, once as a child re-spawned from
inside that PID's namespaces with the daemon's env construction. The point is
the DIFF between the two blocks, not either block alone.
"""
import os
import sys

label = sys.argv[1] if len(sys.argv) > 1 else "?"
print("=== [%s] pid=%d ppid=%d ===" % (label, os.getpid(), os.getppid()))

# --- 1. env, names and lengths only
NEEDLES = ("API_KEY", "TOKEN", "CUSTOM_", "LLM", "ANTHROPIC", "OPENAI",
           "CRED", "SLUG")
keys = sorted(k for k in os.environ if any(t in k.upper() for t in NEEDLES))
print("env credential-ish vars: %d" % len(keys))
for k in keys:
    print("   %-46s len=%d" % (k, len(os.environ[k])))
if not keys:
    print("   *** NONE — this process has no credential in its environment ***")

# --- 2. the flags a spawner injects (pass the names you care about)
for flag in ("HERMES_RESEARCH_SCHEDULED", "HERMES_WEB_HOST", "HERMES_DB"):
    print("%-24s = %s" % (flag, os.environ.get(flag, "<absent>")))

# --- 3. the resolver's verdict
try:
    import research_llm as rl          # adjust to the project's adapter
except Exception as exc:                # noqa: BLE001
    print("resolver import failed: %s: %s" % (type(exc).__name__, exc))
    raise SystemExit(0)

try:
    resolved = rl._hermes_default_runtime()
    if not resolved:
        print("resolver: _hermes_default_runtime() -> None")
        print("          => get_provider() returns the Unavailable adapter and")
        print("             every LLM call is a no-op, never a 401")
    else:
        rt = resolved.get("runtime") or {}
        key = rt.get("api_key")
        keyf = key() if callable(key) else key       # a pool resolves lazily
        print("resolver: model=%r provider=%r base_url=%r"
              % (resolved.get("model"), resolved.get("provider"),
                 rt.get("base_url")))
        print("resolver: api_key present=%s len=%s"
              % (bool(keyf), len(keyf) if isinstance(keyf, str) else 0))
        pool = rt.get("credential_pool")
        print("resolver: credential_pool=%s" % (type(pool).__name__
                                               if pool is not None else None))
        if pool is not None:
            for meth in ("current", "resolve", "get", "acquire"):
                if hasattr(pool, meth):
                    try:
                        v = getattr(pool, meth)()
                        v = v() if callable(v) else v
                        print("resolver: pool.%s() -> present=%s"
                              % (meth, bool(v)))
                    except Exception as exc:        # noqa: BLE001
                        print("resolver: pool.%s() raised %s: %s"
                              % (meth, type(exc).__name__, exc))
                    break
        prov = rl.get_provider()
        print("resolver: get_provider() -> %s name=%r"
              % (type(prov).__name__, getattr(prov, "name", None)))
        print("resolver: provider.available() = %s" % prov.available())
except Exception as exc:                            # noqa: BLE001
    print("resolver raised: %s: %s" % (type(exc).__name__, exc))

# --- 4. filesystem view: is a private /tmp in play?
try:
    print("tmpdir        =", os.environ.get("TMPDIR", "<unset -> /tmp>"))
    print("HOME          =", os.environ.get("HOME", "<unset>"))
    print("/tmp listing  =", sorted(os.listdir("/tmp"))[:12])
except OSError as exc:
    print("/tmp listing  raised", exc)
for p in ("/root/.hermes/config.yaml", "/root/.hermes/.env"):
    print("cfg %-26s readable=%s" % (p, os.path.exists(p)))
print()
