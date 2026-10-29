# Installing the scanner and verifying it against a real binary

The engine's `capability_audit()` is the single source of truth for "is it usable".
When it reports the dependency missing, install it — do not park the milestone.

## 1. Install from the official release (no Git, no pipe-to-shell)

```bash
WORK=/tmp/dl; mkdir -p $WORK; cd $WORK
BASE=https://github.com/projectdiscovery/nuclei/releases/download/v<VER>
curl -sS -fL -o nuclei.zip "$BASE/nuclei_<VER>_linux_amd64.zip"
curl -sS -fL -o checksums.txt "$BASE/nuclei_<VER>_checksums.txt"
EXPECTED=$(grep "nuclei_<VER>_linux_amd64.zip" checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum nuclei.zip | awk '{print $1}')
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || { echo MISMATCH; exit 1; }
```

- Resolve `<VER>` from `api.github.com/repos/projectdiscovery/nuclei/releases/latest`
  (`tag_name` + the `linux_amd64.zip` / `*_checksums.txt` assets). Reading release
  metadata is not cloning a repository.
- **Verify the checksum before anything else.** Fail the install on mismatch.

```bash
# list before extracting; unzip may not exist, so use python zipfile
python3 -c "import zipfile;[print(n) for n in zipfile.ZipFile('nuclei.zip').namelist()]"
python3 -c "import zipfile;zipfile.ZipFile('nuclei.zip').extractall('extract')"
install -m 0755 extract/nuclei /usr/local/bin/nuclei
```

- Install into a path the engine already searches (`/usr/local/bin/nuclei` is in
  `SEARCH_PATHS`) so no discovery code changes.
- Confirm exactly one binary across every candidate path; a second copy earlier on
  `PATH` silently shadows the one you verified.
- Do not install a language toolchain to build from source when a release binary is
  available, and do not alter scope/rate/safety config to accommodate the binary.

## 2. Confirm installation through the engine, not by hand

```python
import nuclei; a = nuclei.capability_audit()
# expect: available True, binary <path>, version <x.y.z>, reason None,
#         permissions 0o755, supported_flags populated from `-h`
```

Record version, path, source and permissions from this call in the report. If it
still reports unavailable, the blocker is real — report it, never fake a result.

## 3. Minimal reviewed template set

Author 1–2 templates by hand into the approved directory. Keep them deterministic
and read-only:

- a single `GET` with a header matcher (e.g. `Server:`),
- a single `HEAD` with a header-presence matcher (e.g. HSTS/CSP/XCTO/XFO),
- tags drawn from the conservative set, `severity: info`,
- no parameters, no auth, no payloads, no OOB, no write verbs.

Confirm each classifies `TRUSTED` via the classifier (not the filename) and that
`verify_template()` passes, before building argv from it.

## 4. Assert argv, then run for real

Build argv with the real flag set and check it directly: `-rate-limit` at or below
2, `-concurrency` bounded, `-retries 0`, `-disable-redirects`/`-max-redirects 0`,
`-no-interactsh`, JSONL + explicit output path, and **no write method present**.
Then execute one in-scope host with one or two templates.

## 5. Independent process proof

Do not trust the executor's own report that a child ran. Sample the process table
from a watcher thread for the duration of the call:

```python
def watch(seen, secs):
    end = time.time() + secs
    while time.time() < end:
        r = subprocess.run(["ps","-eo","pid,ppid,etime,rss,args"],
                           capture_output=True, text=True, timeout=8)
        for ln in r.stdout.splitlines():
            if "/usr/local/bin/nuclei" in ln and "ps -eo" not in ln:
                seen.append(ln.strip())
        time.sleep(0.1)
```

Record: PID, argv, RSS growth, start/end, exit code, timeout state, output bytes,
parsed result count. Run the same watcher around every out-of-scope attempt and
assert **zero** samples — "no process started" is the claim worth making.

## 6. Real-binary safety matrix

Re-run these with the REAL binary after installing it (fixtures do not cover a real
engine). Each must not spawn a process except the in-scope case:

| case | expected |
|---|---|
| in-scope host | executes; exit 0; JSONL parsed |
| `attacker.example.com` | `BLOCKED_SCOPE`, argv `[]`, no process |
| `localhost` | same |
| `127.0.0.1` | same |
| private IP (`10.0.0.1`) | same |
| metadata endpoint (`169.254.169.254`) | same |
| redirect/result host out of scope | rejected by the validator |
| each dangerous template fixture | `BLOCKED_TEMPLATE`, no process |
| POST template | `BLOCKED_TEMPLATE`, no process |
| malformed JSONL | rejected with a reason; valid lines kept |
| after the run | `pgrep` for the child finds nothing |

## 7. Pipeline proof without polluting production

Copy `state/hermes.db` to a scratch path, seed the one in-scope host that genuinely
matches, set `HERMES_DB`/`HERMES_STATE`/`HERMES_LOCK_DIR` to the scratch dir, then run
the REAL job body twice. Assert: run 1 creates the canonical findings; run 2 creates
**0** new findings while each identity's `seen_count` increments; `source`/`sink`/
`source_to_sink_chain` are NULL; `extracted_results` is null when the engine supplied
none.

If the production run legitimately produced no match, production stays at
`nuclei_results = 0` — report that plainly and explain each row that WAS created
(executions, templates) rather than manufacturing a finding.

## 8. Environment-conditional test assertions

A test asserting `available is False` encodes the pre-install state and goes red the
moment the dependency is installed. Assert the invariant instead, and keep the
unavailable branch covered by stubbing the finder:

```python
if a["available"]:
    ok = bool(a["binary"]) and os.path.isfile(a["binary"]) and bool(a["version"])
else:
    ok = bool(a["reason"]) and a["binary"] is None

_orig = N.find_binary
N.find_binary = lambda: (None, "not found in PATH or known locations")
try:
    un = N.capability_audit()          # must stay honest and refuse to fabricate
finally:
    N.find_binary = _orig
```

State in the report which assertions were changed and why; never relax a safety
check to make a suite green.
