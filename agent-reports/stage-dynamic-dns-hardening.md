# Stage: Dynamic DNS Pipeline Hardening

- Date: 2026-09-10
- Scope: Dynamic DNS only (`ns/watch_dns_dynamic.py`, `ns/dns_brute_common.py`)
- Environment: WSL2 development box
- Production symptom addressed: `alterx timed out on
  /opt/watch/dns-bruteforce/work/dell.com.known.txt (partial output discarded,
  not treated as 0 candidates)`

---

## 1. Current flow (before this change)

`ns/watch_dns_dynamic.py::process_domain`

```
Subdomains.objects(scope=domain)                     # full known list, live Mongo obj
  -> "\n".join(known) -> <domain>.known.txt          # no dedup, no validation, no cap
  -> run_alterx(): shell=True, no stdin control
       alterx -l known.txt -o <domain>.alterx.txt    # no -limit/-silent/-duc
       subprocess.run(..., timeout=1800)             # per-domain
  -> [read entire out_file into a Python list]       # memory blow-up
  -> "\n".join(candidates) -> <domain>.dynamic.candidates.txt
  -> run_puredns(candidates_file, resolved_file)     # unchanged
  -> existing = set(known); new_names = diff
  -> upsert_subdomain(...,"dynamicBF"), resolve_ip_and_store(), mark_dynamic_run()
  -> run_httpx_quick() + upsert_http()
```

`main()` looped domains with no per-domain error handling: any `ToolError`
aborted the whole run. `__main__` marked the run `failed` and re-raised.

Architecture is preserved: same alterx (`-l`/`-o`), same puredns flags, same
`WildcardDetector`, same persistence/httpx path. Only input preparation,
subprocess handling, output streaming, and per-domain error policy changed.

---

## 2. Confirmed root cause(s)

Evidence-driven, from the code and from alterx/puredns upstream behavior:

1. **Unbounded alterx generation.** The full known list was passed with no cap.
   The shipped `permutation_v0.1.0.yaml` expands each input line into
   **~696 permutations** (`6 {{word}} patterns × 111 words + 24 numbers +
   6 regions`). `alterx` `ExecuteWithWriter` only stops writing on
   `-limit` (default 0 = unlimited) / `-max-size` (default `MaxInt`); neither
   was passed. `-limit` bounds *written* output but alterx still generates and
   de-duplicates everything internally, so the real generation cost is driven
   by **input size**.
2. **Disk-backed dedupe above 100 MB.** `projectdiscovery/utils/dedupe` uses an
   in-memory map only up to `MaxInMemoryDedupeSize = 100 MB`; above it alterx
   uses a LevelDB/hybrid disk map. That threshold is crossed at roughly
   `100 MiB / (696 × ~72 B) ≈ 1,800` input lines, so essentially every large
   domain ran the slow, disk-bound path and hit the 1800 s ceiling.
3. **Whole-output buffering.** `out_file.read_text().splitlines()` loaded the
   entire (partial) output into RAM, then re-joined it — OOM risk under the
   heavy slice's `MemoryMax=3G` even on success.
4. **Timeout did not kill the real process.** `shell=True` made `/bin/sh` the
   direct child; on `TimeoutExpired` only the shell was killed, leaving the
   `alterx` child alive (still writing the output file).
5. **No per-domain fail-soft.** One timing-out domain aborted the entire run.

---

## 3. Exact code changes

### 3.1 `ns/dns_brute_common.py`

- `import re`.
- `class ToolTimeout(ToolError)` — a distinct timeout signal so the dynamic
  pipeline can report TIMEOUT separately from a hard failure.
- Constants and derived ceiling:
  - `ALTERX_MAX_PERMUTATIONS_PER_INPUT = 696` (from the shipped permutation
    config; six word-patterns × 111 + 24 + 6).
  - `ALTERX_EST_KEY_BYTES = 72`.
  - `ALTERX_IN_MEMORY_DEDUPE_BYTES = 100 * 1024 * 1024`.
  - `_derived_dynamic_max_input_lines()` =
    `100 MiB // (696 × 72)` = 2092, floored to the nearest 100 → **2000**.
  - `DYNAMIC_MAX_INPUT_LINES` = derived default, overridable with
    `WATCH_DYNAMIC_MAX_INPUT_LINES` (`_env_positive_int`).
  - `DYNAMIC_MAX_CANDIDATES = 2000 × 696 = 1,392,000`.
- `is_valid_hostname(name)` — conservative validation (rejects empty, `*`,
  URLs, empty labels, leading/trailing `-`; accepts `_`).
- `bounded_deterministic_sample(sorted_items, limit)` — all items when under
  the limit, else an evenly-spaced sorted sample.
- `stream_valid_candidates(src, dst, max_candidates)` — line-by-line
  strip/validate/dedup/cap, never buffering the whole file, preserving order.
- `run_puredns()` timeout now raises `ToolTimeout` (still a `ToolError`, so all
  existing fail-fast tests/behaviour hold).

### 3.2 `ns/watch_dns_dynamic.py`

- Imports `signal` and the new helpers/constants; `ALTERX_TIMEOUT = 1800`
  (unchanged value, now a named constant).
- `_cleanup(*paths)` — best-effort transient-file removal.
- `_terminate_process_group(proc)` — SIGTERM, wait 10 s, then SIGKILL the
  process group (works because alterx is spawned with `start_new_session=True`).
- `build_known_file(domain, known_file, max_input_lines)` — streams the Mongo
  cursor, drops malformed/empty names, dedups exactly (no case changes),
  writes a sorted `\n`-joined file, and returns stats
  (`total/unique/malformed/duplicates/selected/truncated/names`). `names`
  (the full valid unique set) is retained so a capped input never re-reports
  existing hosts as new.
- `run_alterx(known_subs_file, raw_out_file, candidates_file, max_candidates,
  timeout)` rewritten:
  - verifies input exists and is non-empty;
  - builds an **argv list** (no shell) with
    `-silent -duc -limit <max_candidates>`;
  - `subprocess.Popen(..., stdin=DEVNULL, stdout=DEVNULL, stderr=PIPE,
    start_new_session=True)` + `communicate(timeout=...)`;
  - on timeout: kill process group, delete raw + candidate files, raise
    `ToolTimeout` including input path, timeout, elapsed, bytes and line count;
  - on non-zero exit: delete output, raise `ToolError` with stderr tail;
  - on missing output file with exit 0: raise (never treat as zero success);
  - on success: stream raw → candidates, delete raw, return the count.
- `process_domain()` — uses `build_known_file`; cleans up on every failure
  path; returns `None` for a genuinely empty input (SKIPPED), `0` for a
  legitimate zero-candidate success.
- `main()` — per-domain `try/except ToolTimeout` / `except Exception`; tallies
  SUCCESS/FAILED/TIMEOUT/SKIPPED; continues to the next domain; budget-expired
  domains are recorded SKIPPED; summary lists counts and failed/timeout
  domains; returns the number of failures.
- `__main__` — `mark_finished("failed", 1)` and `sys.exit(1)` when any domain
  failed or timed out; `success` only when zero failures.

---

## 4. Timeout behavior

- Timeout value unchanged: `ALTERX_TIMEOUT = 1800` seconds, per domain.
- No timeout increase.
- On expiry the alterx **process group** is SIGTERM'd then SIGKILL'd
  (`start_new_session=True` makes alterx the group leader, so children are
  covered).
- Partial alterx output and any candidate file are deleted; a timeout is never
  converted to `0 candidates` or an empty successful resolution.
- The raised `ToolTimeout` reports: input file, timeout, elapsed seconds, input
  bytes and input line count.
- `main()` marks the domain TIMEOUT and continues with the remaining domains.

---

## 5. Output handling

- alterx writes to a private raw file (`<domain>.alterx.txt`);
  `stderr` is captured via `communicate` (bounded); `stdout` is `DEVNULL`.
- The candidate file is produced by `stream_valid_candidates`, which reads the
  raw file one line at a time (no `read_text`, no whole-file list, no
  `communicate()` accumulation) and stops at `DYNAMIC_MAX_CANDIDATES`.
- The candidate file is written completely before `run_puredns` is called; on
  any failure it is deleted and never passed downstream.

---

## 6. Candidate explosion protection

- **Input cap (the effective generation bound):**
  `DYNAMIC_MAX_INPUT_LINES = 2000` by default, *derived* from alterx's own
  in-memory dedupe threshold (`100 MiB / (696 perms × 72 B)`, floored to 100),
  not an arbitrary constant. Overridable with
  `WATCH_DYNAMIC_MAX_INPUT_LINES`.
- **Output cap (defense in depth):** `-limit 1392000` (= 2000 × 696) bounds the
  written candidate set; alterx's own dedupe de-duplicates.
- **Deterministic:** the input is sorted unique; when over the cap an
  evenly-spaced sample of that sorted set is used, so the same input always
  yields the same selection and ordering.
- **Fail-soft / no false success:** an empty input is SKIPPED; an empty alterx
  output is a legitimate `0`; a missing output file, a timeout, or a non-zero
  exit are failures — never `0 candidates`.
- Normal domains (≤ 2000 valid known subdomains) are completely unchanged:
  all names are used, patterns are untouched (`-p` never passed), and puredns /
  wildcard / persistence semantics are identical.

---

## 7. Fail-soft behavior

- One domain failing (FAILED or TIMEOUT) is logged, notified, and the loop
  continues to the next domain.
- The final summary distinguishes `Success | Failed | Timeout | Skipped`.
- The process still exits non-zero and `mark_finished("failed", 1)` when any
  domain failed/timed out, so systemd/telemetry never see a green run for a
  failed domain.

---

## 8. Tests

New `tests/test_dynamic_dns_hardening.py` (19 tests, fully offline/mocked —
no alterx, puredns, dnsx, network, Mongo, or pipeline):

1. normal alterx success (bounded, streamed candidate file)
2. empty input → `ToolError`
3. duplicate input (dedup stats + sorted file)
4. malformed hostname rejection (`""`, `*.x`, `bad host`, `None`, `a..b`, `-a`)
5. alterx timeout → `ToolTimeout`
6. partial output on timeout is discarded (raw + candidate files removed)
7. candidate explosion protection (input sample, `-limit`, output cap)
8. subprocess non-zero exit → `ToolError`, no candidate file
9. per-domain failure does not stop other domains (`main` continues, returns
   failure count)
10. deterministic output ordering (sorted, evenly-spaced sample, streamed order)

Updated `tests/test_pipeline_tooling_failfast.py::TestRunAlterx` to the new
3-path `run_alterx` signature (still asserts missing alterx raises `ToolError`).

Commands run:

```
python3 -m unittest tests.test_dynamic_dns_hardening tests.test_pipeline_tooling_failfast
  -> Ran 38 tests ... OK
python3 -m py_compile ns/watch_dns_dynamic.py ns/dns_brute_common.py \
    ns/*.py tests/test_dynamic_dns_hardening.py tests/test_pipeline_tooling_failfast.py
  -> OK
git -c core.whitespace=cr-at-eol diff --check
  -> clean
```

Note: the `ns/` tree is stored with CRLF, so bare `git diff --check` flags the
CR at EOL on every added line; with the repo's CRLF convention declared
(`cr-at-eol`) there are no real whitespace errors. No line endings were
changed.

---

## 9. Regressions

- 38/38 focused + existing pipeline-tooling tests pass.
- Non-dynamic DNS (`watch_dns_static.py`, `watch_dns_precheck.py`,
  `watch_ns*.py`) untouched.
- `dnsx`, `puredns`, `alterx`, `httpx` invocations unchanged except the
  documented alterx hardening (`-silent -duc -limit`, argv instead of shell,
  `stdin=DEVNULL`); puredns flags and dnsx command shape are byte-identical.
- No systemd, scheduling, database, crawl, http, enum, or AI code changed.

---

## 10. Remaining risks

- The default input cap (2000) means a pathological domain is permuted from a
  deterministic representative sample rather than every known subdomain; the
  ceiling is a named, documented constant and can be tuned via
  `WATCH_DYNAMIC_MAX_INPUT_LINES` without a code change.
- alterx `-limit` bounds written output but not internal generation; the input
  cap is therefore the primary protection and must be reviewed if the shipped
  alterx pattern config changes materially.
- `resolve_ip_and_store()`'s dnsx call still has no explicit timeout (previously
  out of scope; the dynamic `dnsx` step is not the reported failure). Noted for
  a future pass.
- Full production pipeline was intentionally not run; validation is
  unit/mocked plus syntax checks. A real `--filter dell.com` run on the VM is
  the recommended final acceptance check.

---

## 11. Explicit statements

- No LLM used in the implementation or tests.
- No network used.
- No production live validation performed.
- No Go tools reinstalled (`dnsx`, `puredns`, `alterx`, `httpx` untouched).
- No systemd changes (units, slices, timers, paths untouched).
- No Git operations performed (no add/commit/push; working tree only).
- No push performed.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: Dynamic DNS Hardening
- Role: DNS Pipeline Reliability
