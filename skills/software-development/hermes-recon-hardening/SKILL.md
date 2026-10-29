---
name: hermes-recon-hardening
description: Use when changing HERMES recon budget/routing/XSS gates.
---

# HERMES recon — budget / routing / finding-quality work

Project root `/root/hermes-recon` (`lib/` modules, `scripts/` CLIs + selftests).
Cron shims live in `/root/.hermes/scripts/` (cron only accepts relative script names).

## Where enforcement actually happens

- Cron jobs pinned `model: complex, provider: 9router` are **monitor-gated**: the
  `monitor_script` runs BEFORE the agent and the provider is only invoked when that
  script's stdout changes. That is the real pre-provider boundary — a prompt line
  saying "STOP" is not enforcement.
- Enforce budget in the monitor path (`scripts/cron_context.py --stable`): on
  refusal emit the PREVIOUS digest verbatim (byte-identical => Hermes suppresses
  the agent run) and persist DEFERRED; never advance the stored digest on refusal.
- `scripts/budget_guard.py` (no_agent cron, every 15m) pauses/resumes the pinned
  jobs and must use the SAME admission rule as the reservation, or the two
  disagree and DEFERRED state flaps.

## Budget reservations

- `lib/model_budget.py`: `reserve()` / `release()` / `finalize()` / `reap()` under an
  flock on `state/complex_budget.lock`. Invariant: `reserved + recorded <= CAP_USD`.
  Refuse when `committed >= CAP*REFUSE_AT` OR `committed + est > CAP*REFUSE_AT`
  (checking only the hard cap lets a reservation slip past the safety margin).
- `finalize()` must NOT write a ledger row by default: `usage_today()` sums the
  local ledger ON TOP of Hermes' own `~/.hermes/state.db` accounting, so a second
  row double-counts.
- `lib/routing.py` returns COMPLEX_PAID / DEFERRED / FREE_MODEL / DETERMINISTIC and
  is the single decision point (`complex_gate.py --reserve|--routing` for CLIs).

## XSS quality

- `lib/xss.py`: source classes (ATTACKER_CONTROLLED … STATIC_LITERAL), `library_tier()`
  (library = vendor bundle -> LOW, suspect = `*.min.js`/`*-util*` -> MEDIUM, else app),
  `severity_gate()` (HIGH needs an externally controllable source IN the chain +
  execution sink + no sanitizer + no library evidence). The gate only ever LOWERS the
  base model verdict.
- `URLSearchParams.append()` is not a sink; `is_url_params_sink()` filters it.
- Storage: classify from the actual `setItem` writes; literal/self-written -> LOW.
- `scripts/reclassify_xss.py` persists verdicts via `store.apply_classification()`
  (+ `finding_reviews` audit). Markdown reports are never the source of truth.
- `analysis.correlate_root_cause()` -> DUPLICATE / ROOT_CAUSE_GROUP / RELATED_FINDING,
  persisted in `correlation_groups`; `scripts/correlate.py` is the CLI.

## Template forge / Nuclei generation (M7)

- `lib/template_forge.py` generates Nuclei templates from stored intelligence. The
  M6 gate (`lib/nuclei.verify_template`) stays authoritative; never re-implement a
  trust check in the forge.
- **Candidates must live OUTSIDE every M6-approved root.** `/root/nuclei-templates`
  is itself an approved root, so a `hermes-generated/` subdir under it gets swept
  up by the inventory walk and becomes executable by existing. Default candidate
  dir is `/root/hermes-forge-candidates`.
- **Candidate identity is the DETECTION LOGIC, not the host.** Deriving the id or
  the description from the host produced one near-duplicate template per host
  (38 hosts -> 38 files). Provenance (source_host/source_finding_id) belongs on
  the candidate row, and `notes` accumulates extra observing hosts.
- **Never auto-trust generated content.** `classify_template` returning TRUSTED is
  a *content* verdict; the forge trust state must be REVIEW_REQUIRED (or BLOCKED)
  until an explicit promotion copies the file into the reviewed dir.
- **Unsafe-capability regexes need `\b` on both sides of short tokens.** A bare
  `rce` matched inside "Vercel" and rejected a valid fingerprint; `command
execution` (two words) also slipped past un-anchored alternatives.
- **Do not put banned words in your own generated boilerplate.** "not proof of
exploitability" tripped the exploit detector and rejected 70/284 signals. Reword
  disclaimers (`no attack`, `does not prove ... is a vulnerability`) and validate
  the FULL content string with no substring exemptions.
- Storing `source_signal,source_host` lookups are too coarse for dedup: one host
  can yield several findings of the same signal. Dedup on the content hash
  (`forge_upsert_candidate` returns 'duplicate') and never overwrite the first
  producer's provenance.

## Selftest traps

- Isolate BOTH stores or tests mutate production: `HERMES_STATE_DIR` (budget files)
  and `HERMES_USAGE_DB` (Hermes accounting) must be set **before** importing
  `model_budget` for the current process, not only in the child env, or the test
  writes into `state/complex_ledger.jsonl` and reads live spend.
- Copy `state/hermes.db` to a temp dir for anything touching findings.
- `phase34_selftest.py` item 3 needs a COLD analysis coverage ledger
  (`UPDATE coverage SET updated_at=0` for security/tech/version_cve/endpoints) and a
  bounded drain loop; production coverage is already warm, so nothing rotates.
- After touching budget code, re-run: `verify_routing.py`, `budget_selftest.py`,
  `xss_selftest.py`, `phase34_selftest.py`, `fix_selftest.py`, `telegram_selftest.py`.

## Runtime

- `systemctl --user restart hermes-recon.service` picks up lib changes (the daemon
  holds old code); verify `state/heartbeat.json` mode RUNNING + recent
  `logs/cycle_*.log` job lines.
