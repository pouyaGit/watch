# Phase: Permanent Pipeline Tooling + Fail-Fast Fix

## 1. Root cause of the 12:00 pipeline failure

Two independent defects combined:

1. **Git executable bit.** `run-pipeline.sh` was tracked as mode `100644`
   while systemd executes it directly. A local `chmod +x` fixed the
   worktree file but never corrected the Git index, so every fresh
   checkout/deploy reverted to non-executable.
2. **Fail-open on missing tooling.** This is the critical defect. The old
   `run_puredns()` in `ns/dns_brute_common.py` ran
   `puredns resolve ... > "<out>"` via `shell=True` and **ignored the
   process exit status**. When `puredns` was absent from the systemd `PATH`,
   the shell printed `/bin/sh: 1: puredns: not found` (exit 127) — but the
   `>` redirection had already created an **empty output file**, which the
   code then read as a legitimate empty result. The caller logged
   `puredns resolved 0 names`, counted the domain as processed (`6/6`),
   marked its brute-force run in the DB, and exited 0, so systemd recorded
   success. A broken-tools run was indistinguishable from a clean run with
   no findings.

## 2. Why puredns produced the false "0 names" result

Exact mechanism in the old code (`ns/dns_brute_common.py::run_puredns`):

- `subprocess.run(cmd, shell=True, timeout=21600)` — return code discarded;
  only `TimeoutExpired` was caught.
- With `puredns` missing, the shell exits 127 **after** creating the empty
  redirect target, so `os.path.exists(out_file)` was True and the function
  returned `[]`.
- A missing `resolvers.txt` also returned `[]` with only a log line.
- A timeout also fell through to reading a partial/empty file as `[]`.
- Callers (`process_domain` in static/dynamic) unconditionally incremented
  `processed` and called `mark_static_run`/`mark_dynamic_run`, and the job
  exited 0 (`mark_finished("success", 0)`), so systemd saw success and no
  failure Telegram was ever sent.

## 3. Files changed

| File | Change |
|---|---|
| `run-pipeline.sh` | Sources `pipeline_lib.sh`; steps/final telegrams preserved; final exit is 1 when any step failed (was: always 0). Git index mode corrected to `100755` (not committed). |
| `pipeline_lib.sh` | **New.** Side-effect-free-on-source step runner: `send_telegram` (unchanged text), `step()` (same behavior + sets `PIPELINE_FAILED=1` on child failure, returns child code unchanged), `pipeline_exit_code()`. No `\|\| true`, no masked codes. |
| `utils/common.py` | `WATCH_TOOL_PATH` rebuilt without the hardcoded `/home/pouya_behnia/go/bin` (now `$HOME/go/bin` + `/root/go/bin` + existing dirs, order-preserved); added shared `ToolError`, `tool_env()`, `find_tool()`, `require_tool()`, `require_tools()`. Existing zsh runners untouched. |
| `ns/dns_brute_common.py` | `run_puredns()` rewritten fail-fast (argv form, stdout-to-file, `tool_env()`, return-code checked): missing resolvers / missing binary / `OSError` / timeout / non-zero exit (incl. 127) all raise `ToolError` naming the exact command; only a zero-exit run may return `[]`. `run_httpx_quick()` now runs with the canonical tool env (still best-effort enrichment, documented). |
| `ns/watch_dns_static.py` | Job preflight `require_tools(["puredns", "dnsx"])` before the domain loop; `dnsx` confirmation failure raises `ToolError` (domain fails, not marked, not counted); empty wordlist build now raises instead of only logging; failure Telegram on uncaught exception. |
| `ns/watch_dns_dynamic.py` | Job preflight `require_tools(["alterx", "puredns", "dnsx"])`; `run_alterx()` rewritten fail-fast (missing binary / timeout / non-zero exit raise); same `dnsx` and failure-Telegram treatment as static. |
| `ns/watch_dns_precheck.py` | Job preflight `require_tools(["dnsx"])` (without dnsx every domain looks feasible); failure Telegram on uncaught exception. |
| `tests/test_pipeline_tooling_failfast.py` | **New.** 19 offline/mocked `unittest` regression tests (A–J, see §6). |

No AI/live-validation code was changed (`ai/`, `ai_data/` untouched).
No database, crawl, enum, http, or nuclei code was changed.

## 4. Tool discovery strategy

Per the required preference order:

1. **Existing convention first.** Binary resolution reuses `WATCH_TOOL_PATH`
   from `utils/common.py` (already prepended to `PATH` by every zsh runner)
   and the existing `HTTPX_BIN` env override in `config.py`. No new config
   system was introduced.
2. **No hardcoded home directory.** The old list contained the literal
   `/home/pouya_behnia/go/bin`, which is absent from the systemd `PATH`
   (`/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin`).
   It is replaced by `$HOME/go/bin` (dynamic, keeps developer shells
   working) plus the explicit systemd-available `/root/go/bin`.
3. **Deterministic PATH.** `tool_env()` builds the subprocess environment
   from `WATCH_TOOL_PATH` + inherited `PATH`; `require_tool()` resolves via
   `shutil.which` against that same search path and raises `ToolError`
   naming the exact missing command when absent — a clear failure instead of
   reliance on an interactive shell `PATH`.
4. **No absolute-path fallback and no symlink knowledge.** Nothing references
   `/home/pouya_behnia/go/bin` or the `/usr/local/bin/puredns` workaround
   symlink; if `puredns` is on the systemd `PATH` (via the symlink or a real
   install) it resolves, otherwise the job fails loudly.

Required binaries per job (audited from actual call sites, not assumed):

- `watch_dns_static`: `puredns` + `dnsx` required; `httpx` best-effort
  enrichment; `curl`/`crunch`/`sort`/`awk` for wordlist build (covered by the
  fail-fast empty-wordlist raise).
- `watch_dns_dynamic`: `alterx` + `puredns` + `dnsx` required; `httpx`
  best-effort.
- `watch_dns_precheck`: `dnsx` required (whole check is dnsx-based).
- Core pipeline (`run-pipeline.sh`): `python3` + per-script tools
  (`subfinder`/`assetfinder`/`findomain`/`crt.sh`/`wayback`/`abuseipdb` in
  enum, `dnsx` in ns, `httpx` in http, `katana` in crawl-fresh) — child
  failures now propagate to the final exit status instead of being
  telegram-only.

## 5. Failure propagation behavior

- **Tool level.** `ToolError` carries the exact command (`puredns`,
  `alterx`, `dnsx`, resolvers path) plus exit code / stderr tail. Raised
  before expensive work (preflight) or at the failing call; never converted
  to an empty result.
- **Domain level.** `process_domain` has no exception swallow: a `ToolError`
  skips `mark_*_run`, skips the `processed += 1` count, and aborts the job
  with a traceback (exit 1). Domains are never marked successfully processed
  when their required tool failed, and iteration never continues silently to
  the next domain after a required-tool failure (missing-binary preflight
  fails the whole run up front).
- **Job level.** Uncaught exceptions still call `mark_finished("failed", 1)`
  and re-raise (exit non-zero → systemd `Type=oneshot` unit fails), and now
  additionally send a `... run FAILED: <error>` Telegram (existing
  send_telegram path, previously success-only).
- **Pipeline level.** `step()` returns the child exit code unchanged and
  records failures in `PIPELINE_FAILED`; independent jobs still run in order
  (existing scheduling preserved, no lock behavior changed —
  `run-heavy-guarded.sh` untouched), and the script exits 1 with a
  `WITH FAILURES` Telegram when any step failed (was: always exit 0 with a
  success Telegram). Shell safety: no `set -e` added (would abort the
  continue-on-independent-failure design); no `|| true` / ignored codes
  anywhere; `bash -n` clean on both scripts.

## 6. Tests and exact results

`tests/test_pipeline_tooling_failfast.py` — 19 tests, all offline/mocked
(`venv/bin/python -m unittest tests.test_pipeline_tooling_failfast`):

```
Ran 19 tests in ~0.35s
OK
```

| ID | Test | Result |
|---|---|---|
| A | `git ls-files --stage run-pipeline.sh` starts with `100755` | pass |
| B | `require_tools(["puredns"])` with undiscoverable binary raises `ToolError` naming it; resolving binary returns path | pass (2 tests) |
| C | `run_puredns` with `which→None` raises (never `[]`) | pass |
| D | `run_puredns` exit 1 raises with `exit 1`; exit 127 + `puredns: not found` raises; timeout raises; `OSError` raises; missing resolvers raises | pass (5 tests) |
| E | `run_puredns` zero-exit + empty output returns `[]` (legitimate) | pass |
| F | `run_puredns` zero-exit + 2 names returns both parsed | pass |
| G | `pipeline_lib.sh`: failing child returns its code, later steps still run, final status non-zero | pass |
| H | `pipeline_lib.sh`: all-success final status zero | pass |
| I | `process_domain` propagates puredns `ToolError`, `mark_static_run` not called | pass |
| J | `WATCH_TOOL_PATH` has no `/home/pouya_behnia`, covers systemd dirs + a `go/bin`, `require_tool("sh")` resolves | pass (4 tests) |
| + | `run_alterx` missing binary raises naming `alterx` | pass |

No test uses network/DNS/MongoDB (subprocess + `shutil.which` mocked;
`database.db` import creates only a lazy client — released in `tearDownClass`).
`bash -n` passes for `pipeline_lib.sh` and `run-pipeline.sh`; all edited
Python files pass `py_compile`.

## 7. Git mode verification

```
$ git ls-files --stage run-pipeline.sh
100755 2ff20cb9588b7a071216ec7175337cf367d50a92 0  run-pipeline.sh
```

Corrected via `git update-index --chmod=+x run-pipeline.sh` (index-level
fix, not just worktree `chmod`). Worktree file is `-rwxr-xr-x`. Not
committed (per instructions).

`git diff --check` note: the repo has no `.gitattributes` / `core.whitespace`
config and the edited `ns/*.py` files are CRLF in HEAD, so plain
`git diff --check` lists `trailing whitespace` (CR-at-EOL) on added lines.
With `git -c core.whitespace=cr-at-eol diff --check` the diff is **clean** —
no genuine trailing spaces; added lines keep each file's existing CRLF
convention (converting to LF would have produced whole-file noise).

## 8. Confirmation: no live-validation code changed

`git status --short` shows modifications only in `run-pipeline.sh`,
`utils/common.py`, `ns/dns_brute_common.py`, `ns/watch_dns_static.py`,
`ns/watch_dns_dynamic.py`, `ns/watch_dns_precheck.py`, plus the two new
files (`pipeline_lib.sh`, `tests/test_pipeline_tooling_failfast.py`) and the
report itself. `ai/`, `ai_data/`, `crawl/`, `enum/`, `http/`, `database/`,
`nuclei/` untouched. No live security validation enabled, no external
bruteforce run, VPS/VM not touched.

## 9. Remaining deployment requirement for Google VM/VPS

Code-side, nothing further is required. Operationally (on the VM, outside
this task's scope):

1. **Pull and use the fixed files** — the `100755` index mode only takes
   effect on the VM after a fresh checkout/pull that applies the mode change;
   local `chmod +x` alone does not survive redeploys.
2. **Ensure `puredns` (and `alterx`, `dnsx`) resolve on the systemd `PATH`**
   (`/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin`).
   The existing `/usr/local/bin/puredns` symlink workaround satisfies this;
   a permanent install into `/usr/local/bin` or `/root/go/bin` would remove
   the need for the symlink. If the binaries are absent, jobs will now
   **fail loudly** (by design) instead of reporting false zeros.
3. **Expect the next scheduled runs to report FAILED** until (2) is done —
   that is the intended fail-closed behavior, visible via systemd unit
   status and the new failure Telegrams.
4. `systemctl daemon-reload` is not needed (no unit files changed), but the
   heavy-job timers will pick up the new scripts on their next fire.
