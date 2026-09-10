# DNS/NS Pipeline Failure Diagnosis

- Date: 2026-09-10
- Environment of analysis: WSL2 dev box (Ubuntu 24.04, hostname `DESKTOP-G0VG53D`)
- Target under diagnosis: Google VM (`/opt/watch`, Ubuntu, `pouya_behnia` user)
- Scope: `ns/` DNS pipeline + directly imported helpers + execution wrappers
- Constraints respected: no AI/R14/R15, no production validation/live chain, no
  crawl/httpx/enumeration changes, no Go tool reinstall, no timeout increases,
  no commit/push.

> **Important limit of this run:** the runtime file
> `/opt/watch/dns-bruteforce/work/dell.com.known.txt` **does not exist in this
> WSL checkout** (`dns-bruteforce/work/` is empty). `alterx` is **not installed**
> on WSL, and the production MongoDB is remote (`35.202.201.30`, do not touch).
> Therefore the alterx timeout could not be reproduced byte-for-byte here.
> Everything that *could* be proven deterministically was proven; the remaining
> VM-specific facts are called out explicitly with the exact command that
> confirms them (Section 14).

---

## 1. Executive summary

The failures are **not** caused by a missing binary anymore (the systemd PATH fix
`bedff46` covers the five heavy jobs) and they are **not** fixed by a larger
timeout. They are two different defects in two different layers:

1. **Dynamic DNS / alterx (primary, likely cause of the observed timeout):
   unbounded candidate explosion.**
   `watch_dns_dynamic.py` feeds the *entire* known-subdomain list for a domain to
   `alterx` with **no input dedup, no output cap, and no enrichment limit**.
   The default alterx pattern set (the local `permutation_v0.1.0.yaml` matches
   upstream defaults) produces **~696 permutations per input line**
   (`6 word-patterns × 111 words + 24 numbers + 6 regions`). For any known list
   above ~1,800 lines the alterx estimate exceeds 100 MB and alterx silently
   switches its deduplicator from an in-memory map to a **disk-backed
   LevelDB/hybrid map** (`projectdiscovery/utils/dedupe/dedupe.go`,
   `MaxInMemoryDedupeSize = 100 MB`). Writing tens of millions of keys through
   LevelDB is disk-bound and far exceeds 30 minutes. Even if alterx finished,
   `run_alterx` reads the whole output with `out_file.read_text()` into a Python
   list — hundreds of millions of lines under a **3 GB systemd cgroup limit**
   would OOM. This is consistent with the exact error
   `alterx timed out on /opt/watch/dns-bruteforce/work/dell.com.known.txt`.

2. **NS / DNS Resolution (core pipeline): failures are silently masked.**
   `run_command_in_zsh_ns()` (`utils/common.py:130`) does **not check the child
   exit code** and returns `[]` on any failure. `ns/watch_ns_all.py` therefore
   prints `dnsx_out=0 … stored=0`, returns `True`, and the pipeline step exits
   **0**. A dnsx that is missing, mis-PATH'd, refused by resolvers, or broken is
   reported as a *successful* ~6-second run. Proven locally (Section 3): a
   nonexistent tool returns `[]`, and `dnsx --badflag` returns the error text as
   if it were a result line. The core `watch.service` unit also still has **no
   `Environment=PATH` and no `RuntimeMaxSec`**, unlike the five heavy jobs.

No source file was modified in this task (see Section 11 / explicit statements).
The correct fix is small but requires the VM's actual `known.txt` size to pick a
non-arbitrary bound, so per the task rule ("implement only if root cause is
certain") this deliverable is a diagnosis plus a ready-to-apply minimal patch.

---

## 2. Pipeline failure map

Core pipeline (`setup-core-pipeline.sh`, `watch.timer`, `User=root`):

| Step | Command | Tool location | Failure mode |
|---|---|---|---|
| Sync Programs | `programs/watch_sync_programs.py` | python | ok |
| Enumeration | `enum/watch_enum_all.py` | go bin via `$HOME/go/bin` | works per VM observation |
| **DNS Resolution** | **`ns/watch_ns_all.py`** | dnsx | **failures masked as exit 0** |
| HTTP Scanning | `http/watch_http_all.py` | httpx at `/usr/local/bin` | works |
| Crawl Fresh | `crawl/watch_crawl_fresh.py` | katana etc. | out of scope |

Heavy weekly jobs (`setup-weekly-jobs.sh`, `watch-heavy.slice`, `User=root`):

| Job | Script | Entry tool chain | Observed |
|---|---|---|---|
| Precheck (Fri) | `watch_dns_precheck.py` | dnsx (via wildcard_detector) | reported failing |
| Static (Mon/Tue) | `watch_dns_static.py` | awk → puredns → dnsx | reported failing |
| **Dynamic (Wed/Thu)** | **`watch_dns_dynamic.py`** | **alterx → puredns → dnsx** | **alterx timeout** |

Shared execution context:
- All five heavy services run in `watch-heavy.slice`:
  `CPUQuota=60%`, `MemoryHigh=2500M`, **`MemoryMax=3G`** (`setup-weekly-jobs.sh:13-32`).
- Heavy-service PATH was fixed in `bedff46` to include
  `/home/pouya_behnia/go/bin` (`setup-weekly-jobs.sh:50,91,133,174,215`).
- The **core** `watch.service` (`setup-core-pipeline.sh:13-30`) has **no
  `Environment=PATH`** and **no `RuntimeMaxSec`**.
- `run-heavy-guarded.sh` adds `$HOME/go/bin` and a fixed dir list
  (`run-heavy-guarded.sh:19-24`) and `exec`s the command with no timeout.

---

## 3. NS root cause

**Classification: E — code bug (failure masking), with A/B/G as the masked
underlying causes that must be read from stderr.**

Exact command executed (`ns/watch_ns_all.py:25-29`):

```
dnsx -l <tmpfile> -silent -a -resp -json -t 10 -rl 30 \
     -r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222
```

Findings:

1. **The dnsx command shape itself is valid.** Verified locally with the same
   `dnsx` v1.3.x flag set (Section 12): it exits 0 and emits the expected JSON
   with a populated `a` field.

2. **The wrapper swallows every failure** (`utils/common.py:130-143`):

   ```python
   proc = subprocess.run(command, shell=True, executable="/bin/zsh",
                         capture_output=True, text=True, env=env)
   if proc.stderr:
       print(f"... stderr: {proc.stderr.strip()} ...")
   return [line for line in proc.stdout.splitlines() if line.strip()]
   ```

   It never inspects `proc.returncode`. Local proof:

   | Input | Wrapper result | Should be |
   |---|---|---|
   | `definitely_not_a_real_tool_xyz` | `[]` (stderr printed) | `ToolError` / non-zero |
   | `dnsx --this-flag-does-not-exist` | `['flag provided but not defined: …']` | `ToolError` / non-zero |
   | `printf 'a\nb\n'` | `['a','b']` | `['a','b']` |

   In `ns/watch_ns_all.py:39-67`, `out_count` is incremented *before* JSON
   parsing, so the error line even inflates `dnsx_out`; `stored=0`; the function
   returns `True`; the process exits 0. A broken NS run is indistinguishable
   from an empty one. This is exactly the "DNS Resolution finishes successfully
   in ~6 seconds" observation if dnsx is actually failing/mis-PATH'd.

3. **No timeout.** `subprocess.run(...)` has no `timeout=`. With no
   `RuntimeMaxSec` on `watch.service`, a hung resolver call blocks the step
   indefinitely (only the outer `flock` prevents overlap).

4. **Core PATH gap.** `utils/common.WATCH_TOOL_PATH` deliberately does **not**
   hardcode `/home/pouya_behnia/go/bin` (`utils/common.py:20-41`; enforced by
   `tests/test_pipeline_tooling_failfast.py::test_no_hardcoded_pouya_behnia_path`).
   It only adds `$HOME/go/bin`, i.e. `/root/go/bin` under `User=root`. If the
   Go tools live only in `/home/pouya_behnia/go/bin`, the core pipeline finds
   httpx (`/usr/local/bin`) but **not** dnsx, and the failure is masked as above.
   The `bedff46` PATH fix only touched `setup-weekly-jobs.sh`, not
   `setup-core-pipeline.sh`.

What is **not** the cause: the dnsx flags, the resolver string, the temp-file
handling, and `-a`/`-resp`/`-json` parsing were all validated as correct.

---

## 4. Static DNS root cause

**Classification: candidate-dependent; first failing operation is
network/wordlist build or the puredns wall-clock ceiling — to be confirmed from
the run log. Not proven locally (no VM wordlist/cache present).**

Order of operations in `ns/watch_dns_static.py`:

1. `ensure_static_wordlist()` (`:42-83`): if the cached merged wordlist is
   missing/empty it re-downloads assetnote lists via `curl` and rebuilds with
   `crunch 1 4 … | sort -u`. First concrete failure point: if the cache was
   previously deleted by the disk-full path described in the code comment, and
   network/disk is unavailable, it raises `ToolError` ("static wordlist build
   failed"). This is fail-fast and would appear as a clear error.
2. Candidate build (`:141-144`): `awk … > candidates`. **No return-code check**
   — a failed/partial awk (disk full) produces a short file that is then fed to
   puredns, under-counting candidates rather than failing.
3. `run_puredns()` (`ns/dns_brute_common.py:65-128`): timeout is **21600 s
   (6 h)** for a single domain. The job-level budget `--max-minutes 300` is only
   checked *between* domains (`:238-243`), and the systemd unit has
   `RuntimeMaxSec=330min`. So a single large static domain can run past both the
   argparse budget and the systemd ceiling; systemd then SIGTERMs the whole
   cgroup (`KillMode=control-group`) while puredns is still running, and the run
   is recorded as failed. The 6 h subprocess timeout can never fire inside a
   330 min unit.
4. The merged wordlist is ~3–4 M lines (`best-dns-wordlist` + `2m-subdomains`
   + `crunch 1 4` = 36+1296+46656+1679616 ≈ 1.73 M) and is rebuilt per domain as
   a candidate file. At `--rate-limit-trusted 1000`, each large domain is
   minutes-to-hours; several domains exceed a 5.5 h window.

The exact first failing operation and error text are in the job log
(`journalctl -u watch-dns-static.service`); Section 14 gives the command.

---

## 5. Dynamic DNS root cause

**Classification: A+E — unbounded candidate generation (alterx) plus
memory-unsafe post-processing. This is the reported failure.**

Trace (`ns/watch_dns_dynamic.py`):

```
known = [s.subdomain for s in Subdomains.objects(scope=domain)]     # :132  unbounded
known_file.write_text("\n".join(known))                             # :137-138  no dedup
candidates = run_alterx(known_file, alterx_out)                     # :141
    cmd = alterx -l <known> -o <out>                                # :56
    subprocess.run(cmd, shell=True, timeout=1800, env=tool_env())   # :59  per-domain
candidates_file.write_text("\n".join(candidates))                   # :148
resolved_names = run_puredns(candidates_file, resolved_file)        # :158
```

Exact stop point for the reported error: `run_alterx` raises `ToolError`
(`:60-64`) because `subprocess.run` hit `timeout=1800` on
`dell.com.known.txt`. `process_domain` aborts before `mark_dynamic_run`, the
exception propagates through `main()`, `mark_finished("failed", 1)` runs, and
the Telegram message `dynamicBF run FAILED: alterx timed out …` is sent
(`:268-279`). One slow domain kills the entire run because there is no
per-domain error isolation.

Downstream proof of concept: nothing downstream (puredns → WildcardDetector →
dnsx) is implicated by the error; the failure occurs strictly inside alterx.
Section 14 gives a bounded synthetic test that exercises puredns + wildcard
filtering without touching alterx.

---

## 6. alterx timeout analysis

### 6.1 Invocation (unchanged, for the record)

```
"<alterx>" -l "<known_file>" -o "<out_file>"        # watch_dns_dynamic.py:56
subprocess.run(cmd, shell=True, timeout=1800, env=tool_env())   # :59
```

- Timeout scope: **per domain** (1800 s = 30 min), not global.
- stdout/stderr: inherited (no `capture_output`); alterx writes results to
  `-o`, so stdout is not the bottleneck.
- The parent waits on `subprocess.run`; no incorrect wait.

### 6.2 Why it hangs (root cause)

`alterx` itself is fast (upstream: default tesla list → 8,312 permutations in
0.07 s; `-enrich` → 662,010 in ~4 s). The cost is:

1. **No cap on generated candidates.** Upstream `mutator.go::ExecuteWithWriter`
   only stops on `-limit` (default **0 = unlimited**) or `-max-size` (our
   invocation passes neither; alterx defaults `MaxSize = math.MaxInt`). We never
   pass `-limit`.
2. **Default pattern multiplier ≈ 696 / input line** (local
   `~/.config/alterx/permutation_v0.1.0.yaml`, byte-identical to upstream
   `permutations.yaml`; computed in Section 7).
3. **Disk-backed dedupe for anything non-trivial.** `dedupe.go`:
   `MaxInMemoryDedupeSize = 100 MB`; above it alterx uses
   `leveldb.go::NewLevelDBBackend` → `hybrid.HybridMap` with
   `DefaultDiskOptions`. alterx's byteLen = `EstimateCount() × maxkeylen`, so the
   threshold is crossed at only ~1,800 input lines. Every large domain runs the
   **LevelDB Get+Set per generated key**, which is orders of magnitude slower
   than the in-memory map and writes a large temp DB.

### 6.3 Secondary, certain code bugs (not necessarily the trigger)

- **stdin inheritance.** `subprocess.run` inherits stdin. Upstream
  `cmd/alterx/main.go` reads stdin when `fileutil.HasStdin()` is true
  (`utils/file/file.go`: true for any non-character-device fd, i.e. pipes,
  sockets, regular files) and then **overwrites `opts.Domains`**:
  `opts.Domains = strings.Fields(string(bin))`. `io.ReadAll(os.Stdin)` blocks
  until EOF. Under systemd (`StandardInput=null` → `/dev/null` → char device)
  and via the dashboard (`backend/task_runner.py:185` sets
  `stdin=subprocess.DEVNULL`) this is **not** triggered, but any manual run with
  a piped/`ssh`-forwarded stdin will hang to timeout and silently ignore `-l`.
- **Whole-file-in-memory read.** `run_alterx` returns
  `[l.strip() for l in out_file.read_text(...).splitlines()]`
  (`:73`) and then does `"\n".join(candidates)` (`:148`). For large outputs this
  is multiple × file size in RAM; under `MemoryMax=3G` it OOMs.
- **Automatic update check not disabled.** No `-duc`; alterx performs a startup
  network update check. Not a 30-min hang by itself, but an avoidable
  egress/slowness dependency.
- **Known input not deduplicated.** Subdomains are unique by
  `(program_name, subdomain)` (`database/db.py:67-71`), but
  `Subdomains.objects(scope=domain)` can return the same subdomain once per
  program sharing a scope, and blank/duplicate lines are never cleaned before
  alterx.

### 6.4 Candidate explosion quantification

Per-line generation from the confirmed config (`word`=111, `number`=24,
`region`=6):

| Pattern | Multiplier |
|---|---|
| `{{word}}-{{sub}}.{{suffix}}` | 111 |
| `{{sub}}-{{word}}.{{suffix}}` | 111 |
| `{{word}}.{{sub}}.{{suffix}}` | 111 |
| `{{sub}}.{{word}}.{{suffix}}` | 111 |
| `{{sub}}{{number}}.{{suffix}}` | 24 |
| `{{word}}.{{suffix}}` | 111 |
| `{{sub}}{{word}}.{{suffix}}` | 111 |
| `{{region}}.{{sub}}.{{suffix}}` | 6 |
| **Total per input line** | **696** |

(`clusterBomb` skips words already a prefix/suffix of the leftmost label, so the
real value is slightly lower; 696 is the upper bound.)

| known lines | candidates (max) | ~output @45 B/line | alterx dedupe backend |
|---:|---:|---:|---|
| 1,000 | 696,000 | 29.9 MB | Map (in-memory) |
| 1,800 | 1,252,800 | 53.8 MB | Map (threshold edge) |
| 2,000 | 1,392,000 | 59.7 MB | **LevelDB (disk)** |
| 10,000 | 6,960,000 | 298.7 MB | LevelDB (disk) |
| 50,000 | 34,800,000 | 1.5 GB | LevelDB (disk) |
| 100,000 | 69,600,000 | 2.9 GB | LevelDB (disk) |
| 200,000 | 139,200,000 | 5.8 GB | LevelDB (disk) |
| 500,000 | 348,000,000 | **14.6 GB** | LevelDB (disk) |

This is why a 30-minute ceiling is hit for a large program like `dell.com`,
while small domains pass.

**Which patterns cause it:** the five/six `{{word}}` patterns dominate
(666 of 696), then `number` (24) and `region` (6). `-enrich` is **not** used
here, so the explosion is from the *default* pattern×payload cross-product over
the *full* known list, not from enrichment.

**Safe cap/dedup strategy already available but NOT applied:** alterx exposes
`-limit`, `-max-size`, and `-es/estimate`; none are used. Our own `count_lines`
and `estimate_minutes` exist but are informational only. The known list is
never deduplicated, and the generated list is never deduplicated before puredns.

---

## 7. Exact file/input statistics

**Cannot be produced from WSL** — `dns-bruteforce/work/` is empty here and the
file exists only on the VM. The exact commands to obtain the real statistics are
in Section 14. Expected shape, based on the code path:

- `dell.com.known.txt` = `"\n".join([s.subdomain for s in Subdomains.objects(scope="dell.com")])`
  (`watch_dns_dynamic.py:132-138`), no trailing newline.
- File size / line count / duplicates / unique count → Section 14 step 1.
- Duplicate likelihood: low for a single program (unique Mongo index) but
  possible across programs sharing a scope.
- It is **already-expanded?** No — it is the raw known-subdomain list; alterx
  expands it (~696×).
- Expected alterx output for N known lines = up to `696 × N` (Section 6.4).
- Current alterx timeout value: **1800 s**, scope **per domain**
  (`watch_dns_dynamic.py:59`).

---

## 8. Resource observations

Collected on WSL (development box), **not** the VM. VM figures are the task's
stated constraints.

| Resource | WSL dev box | Google VM (target) | Implication for DNS |
|---|---|---|---|
| CPU | 8 vCPU | 4 vCPU | alterx + LevelDB are CPU/IO bound |
| RAM | 7.7 GiB | 12 GiB | heavy slice caps jobs at **3 GiB** (`MemoryMax=3G`) |
| Disk | 1 TB (3% used) | 48 GiB | dynamic output can reach 5–15 GB + LevelDB temp |
| `/tmp` | same fs | same fs (likely) | alterx LevelDB temp DB lives here |
| FDs | 1,048,576 | unknown | puredns/dnsx at `-t 100` are modest |

None of these is being exceeded by a *correct* run; the DNS job's own cgroup
limit (`MemoryMax=3G`) is the relevant ceiling, and the dynamic path can exceed
it via the in-memory `read_text()` even before puredns. The 48 GiB disk is the
other finite resource for the unbounded alterx output + LevelDB.

---

## 9. Root-cause ranking

| Pri | ID | Root cause | Evidence | Effect |
|---|---|---|---|---|
| **P0** | DYN-1 | alterx candidate explosion: full known list × ~696, no dedup, no `-limit`, LevelDB dedupe above 100 MB | `watch_dns_dynamic.py:132-141`; upstream `permutations.yaml`, `dedupe.go`, `mutator.go`; local config; Section 6.4 | 30-min per-domain timeout; disk/RAM pressure |
| **P0** | NS-1 | `run_command_in_zsh_ns` masks non-zero exit as `[]` (success) | `utils/common.py:130-143`; local proof Section 3 | NS failures invisible; "~6 s success" with 0 results |
| **P1** | DYN-2 | whole alterx output loaded into Python list (`read_text().splitlines()`), then re-joined | `watch_dns_dynamic.py:73,148` | OOM under 3 GiB even if alterx completes |
| **P1** | STAT-1 | per-domain puredns timeout 6 h > systemd `RuntimeMaxSec=330min`; budget checked only between domains | `dns_brute_common.py:105`; `watch_dns_static.py:238-243`; `setup-weekly-jobs.sh:181` | static job SIGTERM'd mid-domain, recorded failed |
| **P1** | CORE-1 | core `watch.service` has no `Environment=PATH`/`RuntimeMaxSec`; PATH fix only covered heavy jobs | `setup-core-pipeline.sh:13-30`; `bedff46`; `utils/common.py:20-41` | dnsx possibly unreachable in core (then masked by NS-1) |
| **P2** | DYN-3 | alterx inherits stdin; upstream replaces `-l` with stdin when non-TTY and blocks on `io.ReadAll` | upstream `cmd/alterx/main.go`, `utils/file/file.go`; not triggered by systemd/dashboard today | manual/ssh/piped runs hang |
| **P2** | DYN-4 | alterx update check not disabled (`-duc`), no `-silent` | upstream `runner.go` | avoidable network/slowdown |
| **P2** | STAT-2 | `awk` candidate build ignores exit code | `watch_dns_static.py:141-144` | partial candidate file passed to puredns |

---

## 10. Minimal fix recommendation

Do **not** increase the timeout. Apply the following, smallest-first. All are
localized to the DNS files and do not touch crawl/httpx/enumeration, AI, or
validation.

### Fix A (P0) — bound and stream alterx (dynamic)

In `ns/watch_dns_dynamic.py::run_alterx`:

1. `stdin=subprocess.DEVNULL` (kills the stdin hang/list-overwrite class).
2. Add `-silent -duc` (no banner/update network dependency).
3. Deduplicate the known input before invoking alterx.
4. Deduplicate the candidates and stream them to `candidates_file` (or return a
   count and keep the file) instead of `read_text().splitlines()` into memory.

Sketch (not applied here):

```python
def run_alterx(known_subs_file, out_file, limit=None):
    alterx_bin = require_tool("alterx")
    argv = [alterx_bin, "-l", str(known_subs_file), "-o", str(out_file),
            "-silent", "-duc"]
    if limit:
        argv += ["-limit", str(limit)]
    ...
    proc = subprocess.run(argv, timeout=1800, env=tool_env(),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True)
```

Use alterx's own `-limit` (do not invent a home-grown cap). Choose the limit
from the measured file size (Section 14) and the 3 GiB / 48 GiB budgets, e.g.
cap generated candidates at a small multiple of the known count or at a fixed
ceiling derived from the estimate, and log it.

### Fix B (P0) — stop masking NS failures

In `utils/common.py::run_command_in_zsh_ns`:

1. Raise `ToolError` (or return a sentinel) on non-zero exit, including 127.
2. Add a bounded `timeout=` and raise on `TimeoutExpired`.
3. Keep `watch_ns_all.py` fail-fast (it has no `try/except`, so a raise becomes
   a non-zero pipeline step, matching `pipeline_lib.sh`'s failure contract).

Note: `wildcard_detector.py` wraps both call sites in `try/except Exception`, so
they degrade safely; `watch_ns_all.py` / `watch_ns.py` will now fail loudly.

### Fix C (P1) — align static timeout with the unit

Either lower the puredns `timeout` below `RuntimeMaxSec`, or raise the systemd
ceiling — but only after the per-domain cost is measured. Add a per-domain
elapsed check so a single domain cannot consume the whole window.

### Fix D (P1/P2) — execution environment

Give `watch.service` an explicit `Environment="PATH=…"` matching the heavy jobs
(including `/home/pouya_behnia/go/bin`) and a `RuntimeMaxSec`, mirroring
`setup-weekly-jobs.sh`. This is the complementary half of `bedff46`. (Out of the
listed file scope; recommended rather than applied.)

### Do NOT

- Do not raise `timeout=1800` as the primary fix.
- Do not add an arbitrary cap without using alterx's `-limit` / the measured
  input size.

---

## 11. Implementation details if a fix was safely implemented

**No fix was implemented.** Per task Section 9, the root cause of the alterx
timeout is not certain without the VM's `dell.com.known.txt` statistics
(the trigger could be raw input size, the LevelDB dedupe, or manual stdin), and
choosing a candidate cap requires that measurement. Section 10 therefore
contains recommended patches only, not applied changes.

Explicit status:

- **Source modified: NO.**
- **Timeout changed: NO** (alterx `1800` and puredns `21600` untouched).
- **alterx invocation changed: NO.**
- **puredns invocation changed: NO.**
- **dnsx invocation changed: NO.**
- **NS code changed: NO.**
- **No Git operations performed. No push performed.**
- Working tree: only the untracked report file was added; `git diff --check` is
  clean (Section 12).

---

## 12. Tests

Executed on WSL (offline / bounded; no VM pipeline run):

- `python3 -m py_compile` on `ns/*.py` + `utils/common.py` → `PY_COMPILE_OK`.
- `bash -n` on `run-heavy-guarded.sh`, `run-pipeline.sh`,
  `setup-weekly-jobs.sh`, `pipeline_lib.sh` → all syntax OK.
- `git diff --check` → clean.
- `python3 -m unittest tests.test_pipeline_tooling_failfast -v` →
  **19/19 OK** (includes the alterx missing-binary, puredns fail-fast, and
  tool-discovery tests).
- Bounded local evidence runs (not the pipeline):
  - `dnsx -l <2-line file> -silent -a -resp -json -t 10 -rl 30 -r <resolvers>`
    → exit 0, valid JSON with populated `a` (command shape correct).
  - `run_command_in_zsh_ns` with a missing tool → `[]`; with a bad flag →
    error text returned as data (failure masking proven).
  - Deterministic permutation arithmetic from the local alterx config
    (Section 6.4).

No heavy pipeline, no target scanning, and no production DB access was
performed.

---

## 13. Remaining risks

- The alterx timeout trigger is inferred; only the VM can confirm whether
  `dell.com.known.txt` is large enough to cross the explosion/LevelDB threshold.
- The exact NS underlying failure (tool-not-found vs resolver/network) is
  currently hidden by the masking bug; it will only be visible after Fix B
  makes the stderr/exit code surface.
- Static DNS was not reproduced; its first failing operation must be read from
  the service log.
- Apply Fix A's `-limit`/dedup only after measuring real candidate counts, or
  findings could be silently dropped.
- `watch.service` PATH: confirm whether the Go tools are reachable as root in
  the core pipeline before concluding NS is a resolver problem.

---

## 14. Exact commands for Google VM verification

Replace `dell.com` with the failing domain as needed. Read-only except step 5.

```bash
# 0. Prove which alterx and version is actually used, and its config
command -v alterx; alterx -version
ls -la /root/.config/alterx 2>/dev/null; ls -la /home/pouya_behnia/.config/alterx 2>/dev/null

# 1. EXACT INPUT STATISTICS (do this first)
f=/opt/watch/dns-bruteforce/work/dell.com.known.txt
ls -la "$f"; wc -l "$f"; wc -c "$f"
sort "$f" | uniq -d | wc -l                 # duplicate lines (count of extra copies)
sort -u "$f" | wc -l                        # unique lines
awk 'NF==0{n++} END{print "blank lines:", n+0}' "$f"
grep -nE '[^A-Za-z0-9._-]' "$f" | head      # malformed lines, if any
stat -f -c '%S' "$f"                        # fs block size (context for disk)

# 2. Did the timed-out run leave partial output? Size proves explosion vs hang
ls -la /opt/watch/dns-bruteforce/work/dell.com.alterx.txt 2>/dev/null
wc -l /opt/watch/dns-bruteforce/work/dell.com.alterx.txt 2>/dev/null
df -h / /tmp

# 3. Estimate without generating (safe, bounded)
alterx -l /opt/watch/dns-bruteforce/work/dell.com.known.txt -es

# 4. Reproduce with a BOUNDED sample (tiny first, then representative)
head -100  /opt/watch/dns-bruteforce/work/dell.com.known.txt > /tmp/dell.100.txt
head -5000 /opt/watch/dns-bruteforce/work/dell.com.known.txt > /tmp/dell.5k.txt
/usr/bin/time -v alterx -l /tmp/dell.100.txt  -o /tmp/dell.100.alterx.txt -silent -duc
/usr/bin/time -v alterx -l /tmp/dell.5k.txt   -o /tmp/dell.5k.alterx.txt  -silent -duc
wc -l /tmp/dell.100.alterx.txt /tmp/dell.5k.alterx.txt
du -h /tmp/dell.100.alterx.txt /tmp/dell.5k.alterx.txt

# 5. Prove downstream (puredns + wildcard filter) works on a bounded synthetic set
printf 'www.dell.com\napi.dell.com\n' > /tmp/synthetic.txt
/opt/watch/venv/bin/python3 -c "import sys; sys.path.insert(0,'/opt/watch/ns'); \
from dns_brute_common import run_puredns; print(run_puredns('/tmp/synthetic.txt','/tmp/synthetic.out.txt'))"

# 6. NS: capture the currently-masked failure (stderr/exit) from the service log
journalctl -u watch.service --since "24 hours ago" --no-pager \
  | grep -nE 'dnsx|command not found|Executing dnsx|in=.*dnsx_out|stderr'
# and the core unit environment actually in effect:
systemctl show watch.service -p Environment -p ExecStart -p User

# 7. Static: capture the first failing operation/error
journalctl -u watch-dns-static.service --since "7 days ago" --no-pager | tail -200

# 8. Dynamic: confirm the timeout and what alterx left behind
journalctl -u watch-dns-dynamic.service --since "7 days ago" --no-pager | tail -200

# 9. NS direct reproduction under the same non-interactive shell the wrapper uses
printf 'www.dell.com\n' > /tmp/ns1.txt
env -i PATH="/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/home/pouya_behnia/go/bin:/usr/local/bin:/usr/bin:/bin" \
  /bin/zsh -c 'dnsx -l /tmp/ns1.txt -silent -a -resp -json -t 10 -rl 30 -r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222; echo EXIT=$?'
```

---

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: DNS Failure Diagnosis
- Role: DNS Pipeline Debugging
