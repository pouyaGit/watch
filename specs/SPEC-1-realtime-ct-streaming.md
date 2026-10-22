# SPEC 1 — Real-time Certificate Transparency (CT) Streaming

**Target project:** `/opt/watch` (the `watch` bug-bounty recon platform)
**Executor:** implement exactly as written. Do not invent features outside this spec.
**Language/stack:** Python 3.12, mongoengine models in `database/db.py`, venv at `/opt/watch/venv`.

---

## 1. Goal

Subscribe to a **live Certificate Transparency stream** and ingest brand-new
subdomains **within seconds** of a certificate being signed. Every hostname seen
on a freshly-issued certificate that falls inside a program's scope is written to
the `Subdomains` collection with provider tag `ctstream`, so it shows up in the
dashboard exactly like subfinder/crtsh results — but in near-real-time instead of
on the 12-hour batch cycle.

This is **passive**: we only read public CT logs. We never contact the target.

---

## 2. Deliverables

1. `enum/watch_ct_stream.py` — the streaming daemon (new file).
2. `systemd/watch-ct-stream.service` — a systemd **--user** unit (new file). Do
   NOT enable it yourself; just create the file and document the enable command.
3. Add `websocket-client>=1.7` to `requirements.txt`.
4. A `--once-test` self-check mode (see §7) for CI/manual verification.

No other files may be modified **except** `requirements.txt`.

---

## 3. How scope + ingestion already work (reuse, do not reinvent)

From `database/db.py`:

- `Programs` doc has `scopes: list[str]` (apex domains, e.g. `["dell.com","delltechnologies.com"]`)
  and `ooscopes: list[str]` (out-of-scope hostnames/domains).
- `upsert_subdomain(program_name: str, subdomain_name: str, provider: str)` is the
  **only** ingestion call you may use. It is idempotent (unique index on
  `program_name+subdomain`) and appends the provider to the `providers` list.

The existing `enum/watch_crtsh.py` shows the canonical scope match:

```python
name = name.lstrip("*.").strip().lower()      # strip wildcard prefix
if name == apex:            continue           # skip the apex itself
if name.endswith("." + apex):                  # in-scope subdomain
    upsert_subdomain(program.program_name, name, "ctstream")
```

You MUST reproduce this matching exactly, and additionally **reject** any name
that matches an `ooscopes` entry (exact match OR `name == oo` OR `name.endswith("."+oo)`).

---

## 4. Daemon design (`enum/watch_ct_stream.py`)

### 4.1 Imports / bootstrap
Mirror the header of `enum/watch_crtsh.py`:
```python
import sys, os, time, json, threading, signal
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import Programs, upsert_subdomain
from utils.common import current_time, colors
```

### 4.2 Scope index (hot-reloaded)
- Build an in-memory structure:
  - `apex_to_program: dict[str, str]`  (apex domain → program_name)
  - `ooscope_set: set[str]`            (all ooscopes across all programs, lowercased, non-empty)
- Load it from Mongo at startup and **refresh every `SCOPE_REFRESH_SECONDS`
  (default 60)** in a background thread, so targets added via the dashboard
  (SPEC 3) start matching within ≤60s without a restart.
- Refresh must be atomic: build the new dicts, then swap the references under a
  `threading.Lock`. A failed refresh keeps the previous index (log a warning).

### 4.3 Matcher
```python
def match(hostname: str) -> tuple[str, str] | None:
    """Return (program_name, normalized_sub) if in scope & not out-of-scope, else None."""
```
- Lowercase, strip trailing dot, strip leading `*.`.
- Reject empties / names without a dot.
- Reject if it hits `ooscope_set` (exact, or endswith "."+oo).
- For each apex in `apex_to_program`: if `name == apex` → skip (not a subdomain);
  if `name.endswith("." + apex)` → return `(program, name)`.
- Longest-apex-wins if multiple apexes match (match the most specific).

### 4.4 Stream source
- Primary: a **certstream-compatible websocket** at env `CT_STREAM_URL`
  (default `wss://certstream.calidog.io/`). Messages are JSON; for
  `message_type == "certificate_update"`, the hostnames are at
  `data.leaf_cert.all_domains` (a list). Iterate that list through `match()`.
- Use `websocket-client` (`websocket.WebSocketApp`) with:
  - automatic **reconnect** with exponential backoff (1s → 2s → 4s … cap 60s),
    reset to 1s after a message is successfully processed.
  - a ping/keepalive (`ping_interval=20, ping_timeout=10`).
  - per-message `try/except` that logs and continues (one bad cert never kills
    the stream).
- Be resilient to schema drift: if `all_domains` is missing, fall back to
  `leaf_cert.subject.CN` plus `leaf_cert.extensions.subjectAltName` parsing;
  if nothing parseable, skip.

### 4.5 De-duplication
- Keep an in-memory LRU/TTL set of recently-seen `program|subdomain` keys
  (e.g. last 100k keys or last 6h) to avoid hammering `upsert_subdomain` for the
  same host repeatedly within a burst. Mongo's unique index is the source of
  truth; this is only a write-reduction cache.

### 4.6 Ingestion + telemetry
- On a match, call `upsert_subdomain(program, sub, "ctstream")`.
- Maintain counters: `certs_seen`, `domains_seen`, `in_scope_hits`, `ingested`,
  `reconnects`. Log a one-line stats summary every `STATS_EVERY_SECONDS`
  (default 60) using the project's `current_time()` + `colors` style.
- Optional Telegram notify on each **new** in-scope subdomain, gated by env
  `CT_STREAM_NOTIFY=1` (default off). Reuse `database.notifications` if a
  suitable helper exists; otherwise skip (do not add new notify code).

### 4.7 Lifecycle
- Handle `SIGINT`/`SIGTERM`: stop the websocket, stop the refresh thread, print a
  final stats line, exit 0.
- Structured, greppable logs to stdout (systemd captures them).

---

## 5. Config (environment variables, read via `os.getenv`)

| Var | Default | Meaning |
|---|---|---|
| `CT_STREAM_URL` | `wss://certstream.calidog.io/` | websocket source |
| `SCOPE_REFRESH_SECONDS` | `60` | scope hot-reload interval |
| `STATS_EVERY_SECONDS` | `60` | stats log cadence |
| `CT_STREAM_NOTIFY` | `0` | `1` = Telegram per new sub |
| `CT_DEDUP_TTL_SECONDS` | `21600` | in-memory dedup window |

Document these in a short block at the top of the file.

---

## 6. systemd unit (`systemd/watch-ct-stream.service`)

```ini
[Unit]
Description=Watch — real-time Certificate Transparency subdomain ingestion (passive)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/enum/watch_ct_stream.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```
Enable command to document (do NOT run it): 
`XDG_RUNTIME_DIR=/run/user/0 systemctl --user enable --now watch-ct-stream.service`

---

## 7. Acceptance criteria & tests

1. `python enum/watch_ct_stream.py --once-test` must:
   - build the scope index from Mongo, print how many apexes/programs/ooscopes
     were loaded, run the matcher against a built-in fixture list
     (`["x.dell.com","dell.com","evil.com","a.b.delltechnologies.com","console.dell.com"]`
     — the last is an ooscope in prod), print the decision for each, and exit 0
     **without opening a websocket**.
   - Expected: `x.dell.com`→dell, `dell.com`→skip(apex), `evil.com`→skip(no scope),
     `a.b.delltechnologies.com`→dell, `console.dell.com`→skip(ooscope).
2. `py_compile` clean: `python -m py_compile enum/watch_ct_stream.py`.
3. Live run prints a stats line within 60s and ingests ≥1 `ctstream`-tagged row
   when an in-scope cert appears (manually verifiable against a busy scope).
4. Killing with SIGTERM exits cleanly (0) and prints final stats.
5. Adding a new program to Mongo (or via SPEC 3 UI) causes matches within
   `SCOPE_REFRESH_SECONDS` with **no restart**.

## 8. Hard constraints
- **In-scope only.** Never write a hostname that fails `match()`. Out-of-scope
  ingestion is a critical bug.
- Never contact the target; CT logs only.
- Never raise out of the per-message handler. The daemon must run for weeks.
- Do not touch any file other than the two new files + `requirements.txt`.
