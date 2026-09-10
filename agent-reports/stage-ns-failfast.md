# Stage: NS/DNS Resolution Fail-Fast

- Date: 2026-09-10
- Scope: NS command wrapper only (`utils/common.py::run_command_in_zsh_ns`)
- Environment: WSL2 development box
- Confirmed root cause (from `agent-reports/dns-failure-diagnosis.md`):
  `run_command_in_zsh_ns()` ran `subprocess.run()` but never inspected
  `proc.returncode`, so missing `dnsx`, invalid flags, resolver failures, and
  other non-zero exits were converted into `[]` and treated as a successful
  DNS run.

---

## 1. Root cause

`utils/common.py::run_command_in_zsh_ns` (before this change):

```python
proc = subprocess.run(command, shell=True, executable="/bin/zsh",
                      capture_output=True, text=True, env=env)
if proc.stderr:
    print(f"... stderr: {proc.stderr.strip()}")
return [line for line in proc.stdout.splitlines() if line.strip()]
```

The return value of `subprocess.run` was ignored. Any non-zero exit — including
the 127 produced when `dnsx` is not on the effective PATH, and the 2 produced by
an invalid flag — still returned an empty (or garbage) list. The core
pipeline's `step "DNS Resolution" python3 ns/watch_ns_all.py` therefore saw
exit 0 and reported success. This was reproduced locally in the diagnosis
(`definitely_not_a_real_tool_xyz` → `[]`; `dnsx --badflag` → the error text
returned as data).

---

## 2. Exact code changes

Only `utils/common.py` changed (one source file).

1. Added `class ToolTimeout(ToolError)` — distinct hang signal, still a
   `ToolError` subclass so all existing fail-fast handling is unchanged.
2. Added `NS_COMMAND_TIMEOUT = 3600` (1 hour), documented at the definition:
   the per-domain bulk `dnsx` call is rate-limited to ~30 requests/second, so
   the largest realistic domains need many minutes; 1 hour leaves headroom
   while still bounding a hung resolver/tool. No existing project timeout
   constant was appropriate (`ALTERX_TIMEOUT` is dynamic-only; `KATANA_TIMEOUT`
   and `X8_TIMEOUT` are unrelated); this is a conservative explicit constant.
3. Added `_bounded_tail(text, limit=500)` — keeps diagnostic output bounded.
4. Rewrote the body of `run_command_in_zsh_ns` to add `timeout=`,
   `subprocess.TimeoutExpired`/`OSError` handling, and a `returncode` check that
   raises `ToolError` with a bounded diagnostic message. The successful path
   (return non-empty stdout lines, print stderr) and the command shape
   (`shell=True`, `executable="/bin/zsh"`, `capture_output=True`, `text=True`,
   PATH-prepended env) are unchanged.

---

## 3. Exit-code behavior before/after

| Situation | Before | After |
|---|---|---|
| exit 0, stdout lines | returns lines | returns lines (unchanged) |
| exit 0, empty stdout | `[]` | `[]` (still a valid empty result) |
| exit 127 (dnsx missing) | stderr printed, `[]` | **`ToolError`** naming rc 127 + stderr |
| exit != 0 (bad flag/resolver) | stderr printed, `[]` / garbage list | **`ToolError`** naming rc + bounded stdout/stderr tail |
| hang | blocked forever | **`ToolTimeout`** after `NS_COMMAND_TIMEOUT` |
| spawn failure (`OSError`) | propagated raw | **`ToolError`** with command + reason |

The error message contains the return code, a bounded command snippet, and
bounded stderr and stdout tails (≤ ~500 chars each, prefixed with `...` when
truncated). No secrets are read or logged; the only inputs are dnsx commands
and resolver IPs.

---

## 4. Timeout behavior

- `subprocess.run(..., timeout=NS_COMMAND_TIMEOUT)` with `NS_COMMAND_TIMEOUT = 3600`.
- On `subprocess.TimeoutExpired` the run is aborted and `ToolTimeout` is raised
  with the command snippet and timeout; it never returns `[]`.
- Shell mechanism unchanged (per the task): `shell=True`,
  `executable="/bin/zsh"` retained. Python kills the direct child (the shell) on
  timeout; killing the underlying `dnsx` grandchild would require switching to
  `Popen(start_new_session=True)` + process-group kill, which is a wider
  subprocess refactor and is listed as a remaining risk rather than done here.

---

## 5. Caller compatibility

Audited direct callers of `run_command_in_zsh_ns`:

- **`ns/watch_ns_all.py`** (core `DNS Resolution` step): calls it once per
  domain with no surrounding `try/except`, so a `ToolError`/`ToolTimeout` now
  propagates and the pipeline step exits non-zero. This is the desired
  behavior. No caller change was needed.
- **`ns/wildcard_detector.py`** (two call sites): wraps the call in
  `try/except Exception`, logs `wildcard error`, and returns an empty set. This
  intentional safe degradation is preserved and tested.
- **`ns/watch_ns.py`**: **not** a caller of `run_command_in_zsh_ns`; it uses the
  legacy `run_command_in_zsh_common` (a different function, still masking, but
  shared with `enum/` and therefore out of scope for this stage). `watch_ns.py`
  is not referenced by the core pipeline (`run-pipeline.sh` runs
  `watch_ns_all.py`).

No caller code was modified.

---

## 6. Core PATH finding (follow-up, not implemented)

`setup-core-pipeline.sh`'s `watch.service` runs `User=root` but has **no**
`Environment="PATH=..."` and no `RuntimeMaxSec`; `run-pipeline.sh` only does
`source ~/.zshrc` and `source venv/bin/activate`. The five heavy jobs were given
the explicit Go-tool PATH in commit `bedff46`
(`/home/pouya_behnia/go/bin`), but the core unit was not.

Consequence: if `dnsx` is only in `/home/pouya_behnia/go/bin` and root's
environment does not expose it, the core `DNS Resolution` step will now fail
**loudly** (exit 127) instead of silently returning 0 results. That is the
intended fail-fast outcome; the environment fix itself is a separate follow-up:
add the same `Environment="PATH=..."` (and ideally a `RuntimeMaxSec`) to
`setup-core-pipeline.sh`, mirroring `setup-weekly-jobs.sh`. Not implemented in
this stage per the task constraints (`Do NOT modify systemd scheduling`; only a
strictly minimal NS change was in scope).

---

## 7. Tests

New `tests/test_ns_failfast.py` (14 tests, fully offline — `subprocess.run` and
caller-level runner imports are mocked; no network/DNS/MongoDB/pipeline):

1. successful command → stdout lines returned; timeout, shell, executable, and
   capture flags asserted
2. missing tool / returncode 127 → `ToolError` naming 127 + stderr
3. dnsx bad flag / returncode != 0 → `ToolError`
4. stderr/stdout diagnostics bounded (two ~500-char tails, not 10 KB)
5. timeout → `ToolTimeout` with timeout value; `ToolTimeout` is a `ToolError`
6. empty stdout + returncode 0 → `[]` remains valid
7. caller compatibility: `watch_ns_all.dnsx` propagates a runner failure, and
   its success path still parses/stores (mocked)
8. `wildcard_detector` degrades safely (`_resolve_level_ips` and
   `get_wildcard_ips` return empty sets on runner failure)
9. `OSError` → `ToolError`; timeout constant bounded (`0 < T <= 7200`)

Commands:

```
python3 -m unittest tests.test_ns_failfast tests.test_pipeline_tooling_failfast \
    tests.test_dynamic_dns_hardening
  -> Ran 52 tests ... OK
python3 -m py_compile utils/common.py ns/watch_ns_all.py ns/wildcard_detector.py \
    ns/watch_ns.py tests/test_ns_failfast.py
  -> OK
git -c core.whitespace=cr-at-eol diff --check
  -> clean (utils/common.py is LF; ns/ CRLF files untouched)
```

---

## 8. Regression results

- 52/52 focused + existing tests pass (14 new NS + 19 pipeline tooling +
  19 dynamic hardening).
- `utils/common.py` is the only source file changed. `ns/dns_brute_common.py`,
  `ns/watch_dns_dynamic.py`, and their tests (previous stage) are untouched.
- `run_command_in_zsh_common`, `run_command_in_zsh_http`, and the enum/http
  runners are unchanged.
- `dnsx` invocation shape is byte-identical; only failure handling changed.
- No static DNS, crawl/httpx/enumeration, AI, database, or systemd change.

---

## 9. Remaining risks

- On timeout with `shell=True`, Python kills the zsh shell (the direct child);
  a `dnsx` grandchild could in principle survive. A `Popen` +
  `start_new_session=True` + process-group kill would close this, but it is a
  larger subprocess refactor deferred out of this stage. If orphan `dnsx`
  processes appear in production, that follow-up should be prioritized.
- The core `watch.service` PATH gap (Section 6) can make a correctly-failing NS
  step report exit 127 until the unit gets the same PATH as the heavy jobs.
- `NS_COMMAND_TIMEOUT = 3600` is a conservative upper bound; if the resolver
  rate limit or typical domain size changes materially, re-evaluate this
  constant.
- `ns/watch_ns.py` (legacy, unused by the core pipeline) still routes through
  the masking `run_command_in_zsh_common`; fixing that runner would also affect
  `enum/` and is intentionally out of scope.
- No production pipeline was run; validation is unit/mocked plus syntax checks.

---

## 10. Explicit statements

- No LLM used in the implementation or tests.
- No network used.
- No Go tools reinstalled (`dnsx` untouched and not installed).
- No Dynamic DNS files changed (`ns/watch_dns_dynamic.py`,
  `ns/dns_brute_common.py` untouched this stage).
- No Static DNS files changed (`ns/watch_dns_static.py` untouched).
- No systemd changes (units, slices, timers, paths untouched).
- No Git operations performed (no add/commit/push).
- No push performed.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: NS Fail-Fast
- Role: DNS Reliability
