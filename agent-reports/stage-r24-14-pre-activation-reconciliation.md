# Stage R24.14 — Pre-Activation Reconciliation

## Status
**CONDITIONAL GO** — report restoration succeeded and the safety state is
intact (R24 discovery and LLM both disabled, no operational run). One deferred
action remains: the single-line `.env` model change, which this stage
deliberately does NOT perform.

## 1. Report Restoration
- Restored: **yes.** Executed exactly
  `git restore -- agent-reports/stage-r24-12-production-opt-in.md` (the sole
  write operation in this stage, as instructed).
- `test -f agent-reports/stage-r24-12-production-opt-in.md` → passes; the file
  is back in the worktree at its HEAD (`71fef7c`) version.
- `git status --short` after restore: the `D` deletion entry is gone. Remaining
  state is untouched by this stage:
  - ` M wordlists/dell_params.txt`, ` M wordlists/indeed_params.txt` —
    pre-existing/unrelated modifications (not made here; left alone).
  - Untracked (pre-existing): `agent-reports/stage-r23-2-final-google-vm.md`,
    `agent-reports/stage-r24-13-environment-model-sync.md`,
    `ai_data/knowledge/`, `ai_data/reports/`, `crawl/output/`,
    `dns-bruteforce/`.

## 2. Research LLM Configuration
- Current source of the `minimax` value: **two layers agree, `.env` governs.**
  1. `/opt/watch/.env` line 19: `OPENROUTER_MODEL=minimax/minimax-m3:free`
     (effective for the service via
     `EnvironmentFile=/opt/watch/.env` in `watch-research.service`).
  2. Code fallback `ai/llm/openrouter.py:15`:
     `DEFAULT_MODEL = "minimax/minimax-m3:free"`, used by
     `_resolve_default_model()` only when the env value is empty.
  - No other layer sets the model: systemd has **no**
    `Environment=...MODEL/LLM/DISCOVERY` lines; neither `.env` nor systemd
    defines `WATCH_LLM_MODEL` (the CLI's first-preference override), so
    `OPENROUTER_MODEL` is authoritative.
- Current effective model: `minimax/minimax-m3:free`
- Expected model: `nvidia/nemotron-3-ultra-550b-a55b:free`
- Exact proposed change (NOT performed): edit **one line** in `/opt/watch/.env`:
  - from: `OPENROUTER_MODEL=minimax/minimax-m3:free`
  - to: `OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free`
  - Changing it requires modifying **.env only** — no systemd change, no code
    change. (Code default stays `minimax`, which is correct as a fallback; the
    env value takes precedence whenever set.)
- Restart requirement: **none.** The unit file is unchanged so no
  `daemon-reload` is needed, and the service is `Type=oneshot` — each hourly
  timer firing reads `EnvironmentFile` fresh, so the next scheduled run after
  the edit automatically picks up the new model. No restart, no manual start
  required for the change itself (verification of the new value is an
  operational-stage concern).
- Secret presence (boolean only, values never printed):
  `OPENROUTER_API_KEY=SET`, `WATCH_MONGO_URI=SET`.

## 3. Safety State
- R24 discovery enabled? **No.** `WATCH_RESEARCH_DISCOVERY` is absent from
  `.env` (0 matches), absent from systemd, unset in the shell — code default
  `discovery=False` governs.
- R24 LLM enabled? **No.** `WATCH_RESEARCH_LLM` is absent from `.env`
  (0 matches), absent from systemd — code default `llm=False` governs. No
  fallback-model variable is configured anywhere.
- Timer state (observed, not changed): `watch-research.timer` is `enabled` and
  `active` (R23 hourly steady state); `watch-research.service` fires and exits
  cleanly per its window guard.
- No operational run performed: `pgrep` for
  `research_cli|research_agent|discovery_runner` found no research processes;
  no OpenRouter call was made; no scheduler execution was triggered.

## 4. Required Action Before Activation
The exact next action (to be performed in the operational stage, NOT here):
1. Set line 19 of `/opt/watch/.env` to
   `OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free` (single-line edit;
   no other file touched).
2. Verify with a secrets-safe read-back (model value only; API key and Mongo
   URI as SET/UNSET booleans).
3. Proceed to the controlled R24 opt-in runbook (manual service run first;
   timer enable only after a clean manual run).

## Agent / Model
- Model: Miuz Spark
- Stage: R24.14
- Role: Pre-Activation Reconciliation
