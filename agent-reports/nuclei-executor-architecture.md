# Phase 5F — Nuclei Executor
# READ-ONLY SECURITY ARCHITECTURE

> Mode: architecture/design only. No code was written, modified, or
> executed; no Nuclei invocation, no subprocess, no network, no DNS,
> no browser, no LLM, no MongoDB, no finding emission, no verdict
> was performed; no git operation was performed. All findings below
> come from read-only inspection of the repository at `/opt/watch`.

## 1. Executive verdict

**The Nuclei executor is architecturally specified as a
TEMPLATE-VALIDATION + IP-PINNED-EXECUTION-GATE. The central
property `SCOPE-EVALUATED == ACTUALLY-DIALED` CANNOT be guaranteed
in-process for a stock Nuclei binary: Nuclei owns its own DNS,
its own transport, its own redirect chain, and its own OOB /
callback paths. Therefore the PRIMARY architecture is:

> **5F v1 ships with `LIVE_NUCLEI = False` as the default state.
> The executor validates the authorized Nuclei template artifact
> and constructs a closed execution specification. The actual
> binary subprocess is launched only inside a future, separately
> reviewed sandbox / egress boundary (B3) that is BLOCKING for any
> live traffic. Until B3 closes, the deterministic offline
> `FakeNucleiRunner` is the only path through which the executor
> returns a sealed `EvidenceRecord`. No live Nuclei subprocess is
> ever spawned by 5F v1.**

The architecture is **D** (Nuclei in an isolated network namespace
with explicit egress) for the future sandbox design, with a
**local deterministic harness** as the only path available in
v1. The shipped v1 is a *closed-spec executor + offline harness*,
not a live-IO executor. This is the deliberate fail-closed answer
to the central architectural question (§6).

## 2. Existing implementation assessment

`ai/researcher/nuclei_runner.py` (326 lines) and
`ai/researcher/nuclei_pipeline.py` (432 lines) are the legacy
surface. Findings (read-only):

- **Subprocess construction is unsafe**:
  - `nuclei_binary` is a constructor parameter (default
    `"nuclei"`) — it is operator-controlled, not server-side
    trusted; a future caller could pass a hostile path. The new
    5F executor must own a server-controlled binary path
    constant.
  - `subprocess.run(command, capture_output=True, text=True,
    timeout=self.timeout)` is called with no `shell=` argument
    (default `False` — good), but `command` is a list whose
    first element is `nuclei_binary` and the rest comes from
    `build_command`. `build_command` accepts a `template_path`
    and a `target` and emits
    `[nuclei_binary, "-t", str(template_path), "-u", target,
    "-no-color"]`. `target` is supplied by `WatchTargetSelection`
    (an asset selector), not from the 5B/5C/5D binding, so a
    pre-existing path is selection-by-discovery, not
    selection-by-issued-authorization.
  - **No `cwd`**, **no `env=`**, **no `umask`**, **no resource
    limits**, **no user/group drop**, **no namespace**, **no
    seccomp**, **no stdin control** beyond defaults, **no
    fileset rlimit** beyond `capture_output=True` (which only
    caps Python's pipe buffer, not the underlying process's
    filesystem write visibility).
  - **`subprocess.TimeoutExpired` is caught but no
    process-tree termination** is performed; on Linux this
    leaves child subprocesses running. The new 5F executor
    must `process_group=True` + `os.killpg(SIGTERM)` then
    `SIGKILL` on a deadline.
- **`to_findings()` is the wrong abstraction** — it converts
  `process.returncode == 0 and bool(output.strip())` into
  `matched: bool` and emits a `NucleiFinding` with `severity:
  str`, `cve_id: str`, etc. NucleiFinding has no `verdict` field
  by name but it has `matched: bool` and `severity: str`; the
  verifier downstream has historically been the place that
  promoted a match into a finding. The 5F executor MUST NOT
  call `to_findings()` and MUST NOT instantiate `NucleiFinding`.
  Only `HttpObservation`/`NucleiObservation` + `EvidenceRecord`
  are emitted.
- **No template safety gate at runtime**: `build_command`
  passes whatever template path is provided straight to
  Nuclei. The new 5F executor must re-validate the template
  (H1 specificity, H2 safety, plus the new "no-dangerous-block"
  deny list) at every execution — a template whose bytes
  changed after issuance is a different artifact identity
  and may not be run.
- **Target is per-asset, not per-authorization**: each item in
  `selection.targets` becomes a Nuclei run. The new 5F executor
  is a *single* (authorization, target, template) tuple: the
  issued `IssuedExecutionAuthorization` binds exactly one
  `TargetBinding`; multi-target execution under a single
  authorization is not representable.
- **Dry-run vs live mode is a `bool`**: `execute: bool =
  False`. There is no other gating. The new 5F executor has
  a hard runtime gate (`LIVE_NUCLEI = False`) plus
  authorization + scope + artifact + template gates plus B3
  for any future live traffic.
- **`process.stdout` is stored raw** in `NucleiRunResult.output`
  and then forwarded into `NucleiFinding.raw_output`. The new
  5F executor scrubs stdout with the shared 5H scrubber and
  hashes the redacted sample (no raw stdout persists).
- **`NucleiTemplateGenerator` already builds safe HTTP-only
  templates** from a `DetectionSpec`; the new 5F executor
  treats generator output as one of the allowed `template`
  sources, but every byte is re-validated before use.
- **Frozen contracts reused, never duplicated**: 5B
  `IssuedExecutionAuthorization`, 5C `TargetResolution` /
  `DialBinding` / canonical target, 5D `ScopeEvaluation` /
  `require_allowed()`, 5E `BoundedHttpRequest` concepts and
  `LIVE_GATE_BLOCKED` discipline, 5H-core `EvidenceRecord` /
  `HttpObservation` / `NucleiObservation` /
  `EvidenceBuilder` / `InMemoryExecutionLedger` /
  `InMemoryAuditSink` / `RedactedUrl` /
  `sanitized_reason` / `hash_payload` / `scrubber`.

## 3. Frozen contracts consumed (normative)

- **5B (FROZEN):** `IssuedExecutionAuthorization` accepted only
  by typed reference; `(authorization_id, execution_id)`
  binding; `max_executions = 1`; liveness re-asserted
  pre-execution; method-pair contract for the 5E-pre-flight
  (`"http"` requests are 5E; Nuclei is `nuclei_scan` class and
  has no 5E method); CAS consume/revoke; `NEVER_ISSUERS`
  (LLM/scheduler/collector/verifier cannot mint).
- **5C (FROZEN):** `TargetResolution` (`RESOLVED`-only
  input); canonical tuple `(program_name, canonical_host,
  scheme, effective_port)`; `DialBinding{addresses,
  effective_port, sni_host, pin_required}`; 8-answer ceiling;
  global-unicast-only observation; deterministic ids/hashes;
  `scope_view()`.
- **5D (FROZEN):** exact-host + single-level wildcard +
  absolute exclusion matching; program isolation; drift
  detection; per-hop independent evaluation (5-edge cap,
  canonical visited set, per-hop policy re-read);
  `require_allowed()` triple gate; ALLOWED/DENIED/INCONCLUSIVE
  (INCONCLUSIVE never authorizes); no eTLD+1/CDN/IP
  inference; 5D performs no DNS.
- **5E (FROZEN):** IP-pinned transport seam (`SocketFactory`
  accepts literals only); `RealSocketFactory` permanently
  raises `LIVE_GATE_BLOCKED`; `BoundedHttpRequest` immutable
  contract; transport/evidence separation; `LIVE_GATE_BLOCKED`
  pattern is the v1 security stance; 5E ran *no live
  traffic* — 5F adopts the same posture.
- **5H-core (FROZEN):** `EvidenceRecord` lifecycle
  `BUILDING → SEALED | INCOMPLETE`; `REQUIRED_OBSERVATIONS`
  already maps `nuclei_scan → ("nuclei",)` (so the 5F
  executor MUST emit a `NucleiObservation` and the
  `EvidenceBuilder.begin(execution_class="nuclei_scan", ...)`);
  `NucleiObservation` carries
  `{template_id, template_hash, argv_digest, exit_code,
  timed_out, killed, stdout_hash, stderr_hash, stdout_sample,
  stderr_sample, finding_like_text_present}` and is the only
  observation channel for Nuclei.
- **Artifact (FROZEN):** `ArtifactReference` with
  `artifact_id = artifact_id_for(artifact_type="nuclei_template",
  test_plan_id, content_hash, schema_version="artifact/v1")`;
  identity bound to the issued `ArtifactBinding.artifact_id`;
  re-validation per `validate_reference_binding`.

## 4. Threat model

Attacker controls: template bytes (validated, not trusted),
target hostname/URL (validated, not trusted), redirect
`Location`s, secondary requests spawned by Nuclei
redirects/callbacks, response bodies/headers, DNS answers
(rebinding, rotation), historical inventory/TI, and sibling
hosts. Attacker goals: SSRF (loopback/link-local/RFC1918/
CGNAT/metadata/multicast/reserved/documentation space),
sibling-host escape, scope-drift execution, rebinding
(approve A, connect B), credential/secret exfiltration into
evidence, response-bomb DoS, double-execution of one-shot
authorization, OOB callback into attacker infrastructure
(dnsinteractsh, OAST, burp), subprocess escape (env, cwd,
file read, fork, privilege), Nuclei-only finding classification,
template-overridable target (template supplies its own host).
Out of scope for 5F: target-side exploit semantics, browser
(5G), HTTP executor (5E binary-stack), operator-key compromise,
CA compromise.

## 5. Security invariants

1. Only `require_allowed() == ALLOWED` plus a live, consumed-by-us
   authorization, plus a `RESOLVED` `TargetResolution` with a
   coherent `DialBinding`, plus a `VALID` template artifact whose
   content hash matches the bound `ArtifactBinding.content_hash`,
   plus a template that passes the 5F template safety gate, plus
   a closed `B3` (sandbox + egress) review, starts the
   subprocess. **At least B3 is BLOCKING in v1; the others are
   necessary but not sufficient.**
2. The actual Nuclei subprocess is launched only against a
   *single* canonical target derived from the binding — never a
   free-form URL.
3. Every external network destination reached by the subprocess
   is independently recorded and (when observable) re-validated
   against the current scope policy. Cross-host, cross-port,
   IP-literal, and OOB destinations are denied by the offline
   specification (the subprocess never runs in v1, so this
   property is enforced by the harness in v1 and by the
   sandbox in B3).
4. The subprocess executable path is server-controlled
   (`NUCLEI_BINARY_PATH` constant), not constructor-injected
   and not template-derived.
5. `argv` is a structured Python list — no `shell=True`, no
   `os.system`, no string concatenation. The argv shape is
   frozen at architecture time.
6. The subprocess runs with a minimal explicit environment
   (PATH, HOME, LANG, TMPDIR only — no proxy creds, no
   inherited secrets, no operator secrets, no tokens); cwd is
   a scratch directory; stdin is closed; stdout/stderr are
   bounded pipes; rlimits cap CPU, memory, FDs, subprocess
   count, file size; wall-time clock is enforced externally.
7. eTLD+1 / sibling / CDN / cert similarity / DNS answers
   authorize nothing.
8. Method set, port set, host set, redirect set, request
   count, payload count, template size, stdout size, stderr
   size, and observation count are all bounded and frozen.
9. Nuclei stdout/stderr is bounded, scrubbed, and hashed;
   no raw stdout persists.
10. Evidence distinguishes authorized / evaluated / executed /
    dialed / observed / matched — no `verdict` field ever
    appears.
11. At-most-once execution (ledger CAS) and at-least-once
    evidence (seal/index/audit) are separate.
12. No findings, no severity promotion, no `confirmed` /
    `vulnerable` / `not_vulnerable` / `matched` alias field
    ever appears in the sealed record.

## 6. Target / dial binding architecture (the central question)

Nuclei is **not** trusted as a transport engine. The
subprocess owns its own DNS, its own redirect chain, its own
OOB/callback paths, and its own protocol negotiation. None of
those can be bound to a 5C `DialBinding` in a stock binary.
A pure in-process SCOPE-EVALUATED == ACTUALLY-DIALED proof is
not available without a process-level sandbox that constrains
Nuclei's network access.

Five architectures were evaluated; the primary choice is
marked `P` and the others are documented with reasons:

- **A. Nuclei directly with pre-resolved IP targets
  (REJECTED as primary).** Nuclei accepts a `-target` URL
  that *it* resolves; even if we substitute a hostname, the
  binary will call `getaddrinfo` inside the process. It can
  also be told to use a different resolver (e.g. its own
  internal DNS client), and it can do CNAME-walking
  (querying the resolved IP, picking up CNAME aliases, dialing
  those). We cannot prove a stock binary never re-resolves.
  Tested against the existing 5B H2 safety list, the
  matchers in `NucleiTemplateContent` are typed and limited
  to word/regex/dsl/status; the broader Nuclei grammar
  (network, file, code, headless, dns, file) is supported
  by the binary. We canNOT enforce "no dns" in the binary
  itself. `REJECTED as primary; only viable if the binary is
  replaced with a frozen 5F-forked one that takes a `dial_ip`
  and does its own IP-literal connect — DEFERRED until
  such a fork exists.`
- **B. Nuclei with a wrapper/transport layer (REJECTED).**
  Same DNS-seam absence as A; wrapper cannot intercept
  template-driven `network:`, `dns:`, `file:`, `code:`
  blocks. The wrapper would also have to MITM TLS, which
  adds CA trust to the host. `REJECTED.`
- **C. Nuclei behind a mandatory egress proxy (DEFERRED as
  defense-in-depth).** The proxy must resolve nothing; it
  accepts only IP-literal `CONNECT` targets that the
  executor authorizes per hop. The proxy needs the same
  trust-anchor as the executor (system CA, IP-only dial).
  Strictly more code to trust, not less. The
  ip-executor-architecture §11 already deferred proxy
  design; 5F inherits that deferral and refuses to make
  proxy availability a precondition. `DEFERRED; may be added
  as a belt-and-braces layer once B3 lands.`
- **D. Nuclei in an isolated network namespace with explicit
  egress (BLOCKING B3, also PRIMARY for the future
  sandbox).** The executor creates a `netns` (Linux) for
  the subprocess, routes a single allowed `lo` interface,
  optionally dials an IP-pinned proxy inside the namespace,
  caps DNS to a literal-only stub, and uses `cgroups v2`
  for CPU/memory/IO caps. `rlimit` is also set inside
  the namespace. The `landlock` (Linux 5.13+) or
  `seccomp-bpf` filter prevents `open`/`connect` outside
  the namespace, the proxy, and the scratch dir. `BLOCKING
  B3 — the only path by which the future live executor
  could prove SCOPE-EVALUATED == ACTUALLY-DIALED.` Until
  B3 closes, v1 ships without it.
- **E. Nuclei against a generated local harness (PRIMARY
  v1).** The executor runs a deterministic local harness
  that returns scripted bytes — exactly like 5E's
  `FakeSocketFactory`. The harness cannot dial; it cannot
  resolve; it cannot touch the network. The
  `NucleiSubprocessRunner` is replaced by a
  `NucleiHarnessRunner` (a `Protocol` with the same
  shape), and the offline tests drive it. The harness
  produces a scripted `argv_digest`, `stdout_hash`, and
  `stderr_hash` exactly the way a real binary would, but
  never opens a socket. `PRIMARY v1: this is the only
  path that ships.`
- **F. (No other defensible architecture.)** Any
  alternative that runs a stock binary without
  namespace/sandbox/proxy collapses to A or B. The only
  other alternative is to not run Nuclei at all (which
  is what v1 does at runtime, while still shipping the
  closed-spec contract and the offline harness).

**Decision (DECIDED):** the primary architecture is `E`
(local harness) for v1. The `NucleiRunner` contract
(`launch(argv, stdin, env, cwd, rlimits) -> NucleiRunResult`)
is the only seam exposed by 5F. The default
implementation is `FakeNucleiRunner` (offline, scripted).
A future `B3NetnsNucleiRunner` is BLOCKING and is the
only implementation that may ever set `LIVE_NUCLEI = True`.
The frozen argv shape (§10) and the offline subprocess
cap tests are the same shape; only the runner
implementation differs.

## 7. Template safety model

Templates are hostile executable content. The 5F template
safety gate is a closed `TemplateSafetyReport` produced
deterministically from the artifact bytes by
`validate_nuclei_safety_template`. The gate
operates AFTER 5B H1 specificity and 5B H2 safety
(those are unchanged, frozen contracts from 4C and 5B);
5F adds the executor-time deny list:

- **Protocols ALLOWED:** `http` only.
- **Protocols DENIED:**
  `dns`, `network`, `file`, `code`, `headless`,
  `javascript`, `browser`, `workflow` (any other key at
  the template root is also denied).
- **Request blocks:** `http[0].raw` MUST be present and
  MUST contain exactly one request. The request MUST
  carry one of the 5B-allowed methods. The raw line
  MUST contain `HTTP/1.1` (no `HTTP/2.0`). The raw
  request MUST contain no `Host:`, no `Authorization:`,
  no `Cookie:`, no `Proxy-*:` (transport generates
  them), no absolute URL (`http://…`) inside the path
  field (per 5E translator rules).
- **Path:** per existing 5B H2 (relative, no shell,
  no controls, no absolute URL, no command-like
  tokens, no callback domain, no embedded script).
- **Query / headers / body:** per existing 5B H2
  (no credential headers, no CRLF, no control chars,
  no shell, no script, no callback domain, no
  metadata host, no unsafe IP).
- **Matchers:** types allowed: `word`, `regex`, `dsl`,
  `status`; values must be statically specific
  (≥ `MIN_SPECIFIC_TOKEN_LENGTH` chars and not in
  `GENERIC_TOKENS`); status-only is rejected.
- **Extractors:** DENIED in 5F v1 (any non-empty
  `extractors:` block ⇒ `TEMPLATE_REJECTED`).
- **Variables:** the `variables:` block is permitted
  but only when every name matches `^[a-z][a-z0-9_]{0,31}$`
  and every value is a literal (no `{{…}}`,
  no `\`-escapes, no command substitution markers
  `$(`, `` ` ``, `${`).
- **Payloads / fuzzing / attack mode / clustering:**
  DENIED in 5F v1.
- **Workflows:** DENIED.
- **Interactssh / OOB:** DENIED.
- **Redirects / `max-redirects`:** the executor
  itself controls redirects (its own redirect state
  machine runs in the harness; the binary is not
  told to follow redirects by default). If the
  template sets `redirects: true` or
  `max-redirects: > 0`, the gate REJECTS.

The `TemplateSafetyReport` is a typed record
(`Decision = ALLOW | DENY`, `reasons: tuple[str, ...]`,
`denied_features: tuple[str, ...]`). Only `Decision ==
ALLOW` reaches the subprocess. A template that has
been approved is frozen with its
`content_hash`; any byte change ⇒ new `artifact_id` ⇒
new issuance required (re-validation cannot be
short-circuited).

The re-validator runs at executor entry, not at
issuance. A template that was VALID at issuance but
DENIED at executor entry is refused before the
subprocess is launched.

## 8. Target binding

The target is constructed exclusively from
`(authorization, resolution, evaluation)`. The
executor never accepts a raw hostname / URL string.

Construction rule (DECIDED):

```
scheme = resolution.scheme
canonical_host = resolution.canonical_host
effective_port = resolution.effective_port
path = ""  # the binary fills the path from the template
base_url = f"{scheme}://{canonical_host}"
if effective_port not in (80, 443):
    base_url += f":{effective_port}"
target_string = base_url
```

- The target is the **scheme + canonical host + effective
  port** only. The path is supplied by the validated
  template's `raw` request line. The target is passed
  to the runner as a single string. The runner
  receives it from a typed record field, never from a
  free-form argv (only the frozen argv shape §10
  embeds it).
- The runner does **not** get a raw `template_path`;
  it gets the parsed `NucleiTemplateContent` (already
  H1+H2+5F-gated). The runner re-derives the bytes
  from the typed model with
  `canonical_template_bytes`; any byte difference
  between the canonical model and the original
  artifact is a hash mismatch and a new `TEMPLATE_REJECTED`.
- The runner does **not** get a working directory
  outside the scratch dir; the template file lives
  inside the scratch dir under a hash-named
  subdirectory.

## 9. DNS model

Nuclei subprocess MUST NOT perform arbitrary DNS in v1.
The harness simply does not resolve. The future
`B3NetnsNucleiRunner` blocks DNS at the namespace level
(`/etc/resolv.conf` is unmounted; a stub returns
`EAI_FAIL` for any query); the only allowed resolver is
a literal-IP stub that translates the pre-resolved
addresses (from 5C) into A records (a single
`.bind` resolver; not `unbound`/`dnsmasq`).

The 5C ceiling (`dns_answers = 8`) and the
`classify_address` denylist (loopback, link-local,
multicast, reserved, private, metadata, RFC1918,
CGNAT, documentation, mapped/zone) remain the
gate. The runner may not override the ceiling; if the
subprocess logs an A record count above the ceiling,
the gate is in violation and the execution is
`OUTCOME_UNKNOWN` with no evidence bytes.

## 10. Subprocess sandbox model

Frozen argv (DECIDED, never re-derivable by the
artifact):

```
[ NUCLEI_BINARY_PATH,            # server-controlled
  "-t", str(template_path),      # scratch-dir only
  "-u", str(target_string),      # typed target only
  "-disable-update-check",
  "-silent",
  "-no-color",
  "-stats-interval", "0",
  "-json",                        # the only stdout format we accept
  "-bulk-size", "1",              # one request at a time
  "-timeout", "5",                # per-request timeout, ≤ per-5E connect
  "-nc",                          # no color (defense-in-depth)
]
```

The argv is constructed exactly once, in
`build_nuclei_argv`, from typed records. The artifact
cannot influence any flag.

Environment (frozen, allowlist):

```
{
    "PATH": "/usr/bin:/bin",     # no /usr/local, no /opt
    "HOME": SCRATCH_DIR,
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": SCRATCH_DIR,
    # NO proxy, NO token, NO operator secret, NO Nuclei
    # config, NO Nuclei home, NO Nuclei update check.
}
```

`env=` is the only env passed; `os.environ` is NEVER
inherited. The runner asserts the env is exactly the
allowlist before spawn.

Working directory: a hash-named subdir of the
executor-owned scratch dir, mode 0o700, owner = the
executor UID, never group/world-writable. The
executor also `chdir`s only inside the runner; the
executor process itself never `chdir`s.

Stdin: closed (`stdin=subprocess.DEVNULL`).

Stdout/stderr: `PIPE` with bounded `read(limit)` and
a per-stream cap of `CEILINGS["nuclei_output_bytes"]`
(1 MiB). Reading more than the cap terminates the
subprocess with `killed=True`, `transport_outcome =
"killed"`.

Process-tree: `start_new_session=True` so the
subprocess is its own session leader, and the executor
controls the entire group with `os.killpg(SIGTERM)`
followed by `os.killpg(SIGKILL)` on a deadline.

Resource limits (`preexec_fn`):

```
RLIMIT_CPU       = 2 * nuclei_wall_seconds  (240s)
RLIMIT_AS        = subprocess_memory_bytes    (512 MiB)
RLIMIT_NPROC     = 1                          (no forks)
RLIMIT_FSIZE     = temp_storage_bytes         (16 MiB)
RLIMIT_NOFILE    = 64
RLIMIT_CORE      = 0
```

The exact values reuse the 5H-core ceilings (DECIDED);
`nuclei_wall_seconds = 120`, `subprocess_memory_bytes =
512 MiB`, `temp_storage_bytes = 16 MiB`.

`preexec_fn` is set on Linux only. On macOS/Windows
the runner raises `NUCLEI_RUNTIME_UNSUPPORTED` (the
narrowest closed code) — the runner NEVER silently
skips the limits.

Cleanup: the scratch dir is `shutil.rmtree`d in a
`finally` clause; the subprocess is reaped with
`os.waitpid(WNOHANG)` and a hard `killpg(SIGKILL)`
on a 5s secondary deadline if the graceful kill
does not succeed.

Crash: any exception in spawn ⇒
`SUBPROCESS_START_FAILED`; the executor never retries
under the same authorization. Any timeout/over-cap ⇒
`SUBPROCESS_TIMEOUT` / `SUBPROCESS_OUTPUT_LIMIT`; the
ledger row reaches `UNKNOWN`; no retry without a new
authorization (per 5H crash matrix).

## 11. Resource limits

All ceilings reuse the 5H-core `ai.limits.ceilings`
constants (DECIDED; never redefined):

- `nuclei_wall_seconds = 120`
- `subprocess_memory_bytes = 512 MiB`
- `subprocess_cpu_seconds = 60` (defense in depth;
  asserted inside `RLIMIT_CPU`)
- `nuclei_output_bytes = 1 MiB` (per stream)
- `temp_storage_bytes = 16 MiB`
- `redirect_hops = 5` (reused from 5E; if the runner
  ever returns multiple URLs, the executor applies
  the 5E redirect state machine verbatim)
- `requests_per_execution = 7` (reused from 5E; the
  argv carries `-bulk-size 1` and `-stats-interval 0`
  to keep the binary in single-request mode)
- `dns_answers = 8` (reused from 5C)
- `response transport` / `decompressed` / `ratio` /
  `sample` caps (5E) are not used by 5F — the
  subprocess is bounded by the `nuclei_output_bytes`
  cap, not by 5E transport caps.

Nuclei-specific additions (DECIDED, documented):

- `MAX_TEMPLATE_REQUESTS = 1` (only one raw request
  per template in v1).
- `MAX_TEMPLATE_MATCHERS = 4` (closed list, ≤ 4).
- `MAX_MATCHER_VALUE_LENGTH = 1024` (no giant regex
  DoS).
- `MAX_VARIABLE_VALUE_LENGTH = 1024` (no env-style
  payload injection).
- `MAX_REGEX_COMPLEXITY = 4 * 4096` (NFA size cap;
  uses the `regex` library's `MAXREPEAT` / length
  limit; a template that exceeds is `TEMPLATE_REJECTED`).
- `MAX_RAW_REQUEST_LINE_LENGTH = 1024` (one line in
  the raw block, no multiline CR/LF smuggling).
- `MAX_HEADER_COUNT_TEMPLATE = 16` (5B H2 allows
  16; 5F inherits and freezes the same number).

## 12. Redirect / secondary request model

Nuclei has two redirect surfaces:

- **Nuclei's own redirect following** (configurable
  per template with `redirects: true` /
  `max-redirects`). 5F REJECTS any template that
  enables this (5F's `TemplateSafetyReport.deny`
  includes `redirects-enabled`).
- **A `Location` returned by a Nuclei-driven
  request.** Even with `redirects: false`, Nuclei's
  HTTP transport may decide to follow a Location
  header opportunistically (this is a function of
  the binary's HTTP client). The harness cannot
  fully disable this in v1; the future `B3` namespace
  inspects the binary's outbound connect list and
  records every destination.

For v1 (no live subprocess), redirects are
n/a — the harness returns a single response, the
executor records the single observation, the chain
length is 0. The redirect state machine from 5E
(§5E.5) is **inherited** and **applied** to the
canonical hop list when the runner ever reports more
than one URL (the offline harness may return a
scripted `chain_urls` for tests; the live runner
will, when available, return the per-hop URLs the
binary dialed).

Redirect rules (DECIDED, inherited from 5E):
- max 5 edges
- 6th edge ⇒ `REDIRECT_LIMIT`
- canonical visited set (scheme + host + port + path
  + query)
- every hop re-evaluated by 5D against fresh policy
- IP-literal hop destinations ⇒ `REDIRECT_NOT_IN_SCOPE`
- https → http denied
- http → https allowed only for `http_probe` class
  (Nuclei is `nuclei_scan`, never upgrades)
- per-hop port allowlist `{80, 443, initial-effective-port}`
- every hop gets its own `DialBinding` (a future
  `B3NetnsNucleiRunner` reports per-hop
  `dial_ips`)
- the runner MUST report the dial IP for each hop
  when observable; if the runner cannot observe
  the dial IP, the per-hop observation carries
  `dial_ips = ()` and the executor marks the
  evidence as `transport_outcome =
  "aborted_limit"` with `dial_binding_unverifiable`
  as the incomplete reason (it is INCOMPLETE, not
  SEALED; the verifier never sees it as a positive
  observation).

## 13. OOB / interactsh model

**OOB is DENIED in 5F v1 (DECIDED).** No template
may enable a `dns:`, `interactsh`, `oast`, or
arbitrary callback URL block. The `TemplateSafetyReport`
explicitly denies any of these. A future design
proposing OOB must:
- ship a sealed per-execution callback collector
  inside the same namespace as the subprocess;
- record every callback as an observation, not as a
  finding;
- never accept an arbitrary callback URL — the
  collector's URL is the only URL the binary can
  reach;
- prove the callback cannot reach the public
  internet (namespace + eBPF + collector = same
  loopback).

This is a DEFERRED design; v1 does not even ship a
skeleton.

## 14. Execution lifecycle (DECIDED, exact 18-step order)

1. typed input validation (`TypeError` on dicts/JSON/
   template paths)
2. authorization liveness re-read from the store
   (no stale in-memory copy)
3. resolution + scope binding validation (5C + 5D
   reused exactly as 5E §5E.6)
4. fresh scope evaluation (re-read policy, re-
   evaluate, `require_allowed()` triple + scope hash
   drift check)
5. artifact revalidation (hash + identity + H2 safety
   re-run, fail-closed)
6. **Nuclei template safety gate** (the 5F §7 deny
   list, applied to the parsed `NucleiTemplateContent`
   re-derived from the canonical bytes)
7. **execution specification construction**
   (`NucleiExecutionSpec` — a frozen typed record
   with `argv`, `target_string`, `template_path`,
   `cwd`, `env`, `rlimits`, `stdin`, `stdout_cap`,
   `stderr_cap`, `argv_digest = sha256(canonical
   template bytes + target_string + schema_version)`
   )
8. ledger `put_new(REGISTERED)` (5H-core reused)
9. authorization consume (5B CAS, reused)
10. ledger `mark_started(STARTED)` (5H-core reused)
11. audit `AUTHORIZATION` (5H-core reused)
12. audit `EXECUTION_STARTED` (5H-core reused; any
    audit failure here blocks transport and propagates
    as `AUDIT_GAP`)
13. **subprocess launch** through the injected
    `NucleiRunner` (default = `FakeNucleiRunner`,
    offline, scripted; future = `B3NetnsNucleiRunner`,
    BLOCKING)
14. **resource enforcement** (rlimits, read caps,
    wall clock; runner raises closed code on
    violation)
15. **bounded stdout/stderr collection** (per
    `nuclei_output_bytes` cap, scrubbed, hashed)
16. **evidence construction** (`EvidenceBuilder.begin(
    execution_class="nuclei_scan", ...)` +
    `attach_nuclei(NucleiObservation)` +
    `seal`/`seal_partial`)
17. ledger terminal mark (`mark_sealed` /
    `mark_incomplete` / `mark_unknown`; reused)
18. audit `EVIDENCE_SEALED` + `EXECUTION_TERMINAL`
    (5H-core reused)

The audit pair at step 11–12 is the only network-
adjacent pre-launch check; if it fails, the
subprocess is never spawned.

## 15. Crash consistency

Reuses the 5H crash matrix (per phase
`executor-architecture-adversarial-review.md`):
- pre_start ⇒ safe re-registration path; same
  authorization reusable.
- post_consume ⇒ ledger UNKNOWN, audit gap, retry
  requires new authorization.
- post_start ⇒ ledger UNKNOWN, no evidence bytes,
  retry requires new authorization.
- transport_unknown (subprocess timed out after
  argv dispatched; partial stdout) ⇒ ledger
  UNKNOWN, no evidence bytes, retry requires new
  authorization.
- pre_seal (template gating refused; see §7) ⇒
  ledger UNKNOWN, audit gap.
- post_seal_pre_index ⇒ orphan reindex.
- post_index_pre_audit ⇒ AUDIT_GAP, evidence
  eligible.

5F-specific:
- **subprocess start failure (FILE_NOT_FOUND or
  permission denied):** never retry under the same
  authorization; the binary path is server-controlled
  and a missing binary is a deployment bug.
- **subprocess crashed (signal):** ledger UNKNOWN,
  no evidence bytes.
- **stdout overflow mid-read:** subprocess killed,
  ledger UNKNOWN if before seal, INCOMPLETE if after
  bytes have been collected; a partial stdout is
  scrubbed and the truncated sample is hashed.
- **scrubber refusal (e.g. secret-shaped stdout):**
  no raw stdout persists; the sample is
  `[REDACTED]`-replaced; hash covers the redacted
  sample.
- **orphan subprocess (parent dies, child keeps
  running):** `B3` namespace prevents this in the
  future; in v1 the harness cannot escape; in
  future live mode the executor reaps with
  `killpg(SIGKILL)` on a 5s secondary deadline.

## 16. Evidence model

The only sealed record is `EvidenceRecord` with
`http: None` and `nuclei: NucleiObservation` and
`complete = (NucleiObservation is complete)`. The
`NucleiObservation` carries (per
`ai/schemas/evidence.py`, FROZEN):

- `template_id` — the template's own id, hashed
  against `template_hash` (a re-derivation from
  canonical template bytes).
- `template_hash` — SHA-256 of the canonical
  template bytes.
- `argv_digest` — SHA-256 of the canonical
  `argv` list, computed in `build_nuclei_argv`
  before spawn. The artifact cannot influence the
  digest.
- `exit_code` — the runner-reported exit code
  (`None` when `timed_out` or `killed`).
- `timed_out` — `True` when the wall deadline
  triggered.
- `killed` — `True` when the executor killed the
  subprocess (output overflow, scratch cleanup
  failure, parent crash recovery).
- `stdout_hash` — SHA-256 of the scrubbed
  `stdout_sample`. Hash covers the stored redacted
  sample, never the raw bytes.
- `stderr_hash` — same.
- `stdout_sample` — scrubbed, newline-normalized,
  capped at `nuclei_output_bytes`. Bytes beyond
  the cap set `finding_like_text_present = True`
  AND raise the cap with a redacted placeholder.
- `stderr_sample` — same.
- `finding_like_text_present` — `True` when the
  raw stdout contains the regex
  `\b(vulnerable|exploited|confirmed|critical|high
  severity|matched|\\[vulnerability\\])\b` after
  newline normalization. This is a TEXT-LEVEL
  signal that the runner may have emitted a
  finding; the field is OBSERVATION, not a
  verdict. The verifier decides.

The four-identity separation is preserved:
- `bindings`: `authorization_id` + `execution_id`
  + `artifact_id` + `artifact_content_hash` +
  `template_hash` + `resolution_id` +
  `evaluation_id` + `program_name` + `target` tuple.
- `observations`: `argv_digest` + `dial_ips` (when
  the runner reports them; empty tuple otherwise)
  + `exit_code` / `timed_out` / `killed` +
  `stdout_hash` + `stderr_hash` +
  `finding_like_text_present`.
- `content`: the scrubbed sample bytes (text-
  eligible) or `[REDACTED]` placeholder; capped at
  `nuclei_output_bytes` per stream.
- hashes: `bindings_hash`, `observations_hash`,
  `content_hash` from the 5H-core hashing
  discipline. No timestamps.

`dial_ips` is the per-hop list of literal IPs the
runner reports; in v1 the harness never produces
real dials, so `dial_ips = ()`. The verifier
distinguishes "dial observed" from "dial unknown"
without reclassifying either as a verdict.

## 17. Failure vocabulary

Reuses the 5B/5C/5D/5E/5H vocabularies. 5F-specific
additions (closed, secret-free, deterministic):

- `TEMPLATE_REJECTED` — H1/H2/5F-gate refusal (typed
  reason in `denied_features`).
- `TEMPLATE_UNSAFE` — a specific feature in the
  deny list was present (a subtype of
  `TEMPLATE_REJECTED` for human-readable
  classification in audit).
- `SUBPROCESS_START_FAILED` — spawn returned
  `OSError` or `FileNotFoundError`.
- `SUBPROCESS_TIMEOUT` — wall deadline exceeded
  before subprocess exited.
- `SUBPROCESS_OUTPUT_LIMIT` — stdout or stderr
  exceeded `nuclei_output_bytes`; subprocess
  killed.
- `SUBPROCESS_KILLED` — executor killed the
  subprocess for any other reason (parent
  cleanup).
- `NUCLEI_RUNTIME_UNSUPPORTED` — platform cannot
  enforce rlimits (non-Linux); execution refused
  before spawn.
- `NUCLEI_EXECUTION_BLOCKED` — `LIVE_NUCLEI` is
  False and the runner is not the offline
  harness; the executor refuses the live
  subclass.
- `NETWORK_BINDING_FAILURE` — runner reported a
  destination outside the pinned `DialBinding`
  (only meaningful in a future live runner; in v1
  the harness never dials).
- `OOB_NOT_AUTHORIZED` — runner reported an
  interactsh/DNS callback target (closed; the
  runner MUST refuse and the executor MUST record
  this as `OOB_NOT_AUTHORIZED` and seal
  INCOMPLETE).
- `TARGET_EXPANSION_DENIED` — runner reported a
  hop to a host not in the current
  `scope_view().resolved_addresses` set.
- `REQUEST_LIMIT` — runner reported more than
  `requests_per_execution` hops.

Every code is bounded 200 chars, single-line, and
screened against the secret markers by
`ExecutorError` / `EvidenceError` (the existing
sealed constructors). The mapping to
`transport_outcome` is:

| error code               | transport_outcome |
|--------------------------|-------------------|
| `SUBPROCESS_TIMEOUT`     | `timeout`         |
| `SUBPROCESS_START_FAILED`| `connection_error`|
| `SUBPROCESS_OUTPUT_LIMIT`| `aborted_limit`   |
| `SUBPROCESS_KILLED`      | `killed`          |
| `OOB_NOT_AUTHORIZED`     | `killed`          |
| `REQUEST_LIMIT`          | `aborted_limit`   |
| `TARGET_EXPANSION_DENIED`| `aborted_limit`   |
| `TEMPLATE_REJECTED`      | `aborted_limit`   |
| (none, full obs)         | `responded`       |

## 18. Test architecture

Tests are deterministic, offline, stdlib `unittest`.
NO internet, NO real DNS, NO real external
connections, NO subprocess (the runner is
`FakeNucleiRunner`, which never spawns anything),
NO browser, NO Nuclei invocation, NO LLM, NO
MongoDB. Random IDs are asserted by format.

The runner interface is a `Protocol` with one
method, `launch(argv, env, cwd, rlimits, stdin,
stdout_cap, stderr_cap, deadline) ->
NucleiRunResult`. The `FakeNucleiRunner` records
every call and returns scripted results; the
default `LiveNucleiRunner` is a `LIVE_NUCLEI_BLOCKED`
class that raises `NUCLEI_EXECUTION_BLOCKED`
unconditionally (the 5F mirror of 5E's
`RealSocketFactory`/`SystemTlsWrapper`).

Fakes:
- `FakeNucleiRunner` — records argv, env, cwd,
  rlimits, stdin, the wall deadline, and returns
  scripted `NucleiRunResult` with a deterministic
  `argv_digest` and a known stdout/stderr blob.
- `FakeScratchDir` — hash-named subdir on a temp
  root; auto-cleanup in `finally`.
- `FakeAddressSource` / `FakeScopeEvaluator` /
  `FakePolicyStore` / `FakeLedger` / `FakeAudit`
  / `FakeAuthzStore` / `FakeEvidenceBuilder` —
  reused from 5E (the 5E fakes are 5F fakes; no
  new fakes for shared surfaces).

Test matrix (minimum):

- **AUTHORIZATION (8):** expired / consumed / revoked
  / forged / wrong execution id / wrong target /
  wrong program / wrong artifact.
- **ARTIFACT (8):** wrong hash / modified template
  / unsafe template / broad target expansion
  (template with `-u` override blocked) / forbidden
  protocol (dns, network, file, code, headless,
  workflow) / OOB (interactsh) / shell/code
  execution.
- **TARGET (7):** out-of-scope / sibling / excluded
  / IP / cross-port / cross-program / malformed.
- **PROCESS (8):** executable mismatch (wrong path)
  / shell injection (argv shape) / environment
  injection / cwd escape (cwd outside scratch) /
  template path escape (template outside scratch)
  / timeout / stdout overflow / stderr overflow.
- **NETWORK (8):** DNS bypass (tested against
  `B3NetnsNucleiRunner` — BLOCKING stub) /
  alternate IP / redirect / secondary request /
  arbitrary port / Host override / SNI mismatch /
  OOB callback.
- **RESOURCE (6):** request ceiling /
  concurrency / payload explosion / template size
  / response size / timeout.
- **EVIDENCE (5):** raw stdout not trusted /
  matcher ≠ verdict / secrets scrubbed / hashes
  correct / artifact binding.
- **BOUNDARY (5):** no LLM / no finding logic / no
  verifier logic / no uncontrolled subprocess / no
  unrestricted network.
- **CRASH (5):** pre-start / post-consume /
  subprocess timeout / subprocess killed / orphan
  scrub.

## 19. Rejected alternatives

The following are explicitly REJECTED in 5F v1:

- `subprocess.run(..., shell=True)` — REJECTED.
- `subprocess.Popen(command_string)` — REJECTED.
- Arbitrary Nuclei CLI flags supplied by the
  artifact — REJECTED.
- Raw user-controlled target URL — REJECTED.
- Nuclei direct DNS (relying on `/etc/resolv.conf`
  inside the subprocess) — REJECTED in v1; the
  B3 namespace stub replaces it when live.
- Treating Nuclei's own scope filtering
  (`-severity`, `-tags`) as the sole authority —
  REJECTED. 5D is the sole authority.
- Pre-run DNS check only — REJECTED. The check
  is TOCTOU and Nuclei resolves internally.
- Treating Nuclei JSON `output` as a verdict —
  REJECTED. `finding_like_text_present` is an
  observation, not a verdict.
- Allowing `interactsh` / OOB in v1 — REJECTED.
- Allowing arbitrary workflows (`workflows:`
  block) — REJECTED.
- Allowing the binary to be a `nuclei_binary`
  constructor parameter — REJECTED in v1 (the
  binary is a server-controlled constant).
- Templates that generate a *new* target (template
  with `host: "{{BaseURL}}"` set to an attacker-
  controlled value) — REJECTED. The 5F gate
  inspects the parsed `NucleiTemplateContent`
  and refuses any reference to attacker-controlled
  substitution.
- Shell-style header values (`X-Forwarded-Host: $…`,
  command substitution `$(…)`, env lookup `${…}`) —
  REJECTED. The 5B H2 gate already denies these;
  5F re-asserts.

## 20. Legacy compatibility

`ai/researcher/nuclei_runner.py` and
`ai/researcher/nuclei_pipeline.py` are NOT modified
in 5F. They continue to exist as the
`correlator`-side template-preparation pipeline
(parsing, decisioning, generation, semantic
validation, dry-run, finding normalization). The
5F executor is a separate code path that consumes
the 5B-bound `ArtifactReference` and never reaches
`to_findings()`. The two paths do not share
executable state. Concretely:

- **REUSED:** `NucleiTemplateContent` (frozen
  schema), `NucleiFixture` (frozen schema), the
  shared H1 specificity gate
  (`validate_nuclei_specificity`), the H2 safety
  gate (`validate_nuclei_safety`), the H1/H2
  validation entrypoint in
  `build_validated_reference`, the
  `canonical_template_bytes` round-trip.
- **WRAPPED:** `NucleiTemplateGenerator` — the 5F
  executor's `TemplateSource` accepts a
  `NucleiTemplateContent` produced by the
  generator OR a pre-existing template
  re-derived from canonical bytes. The executor
  never calls the generator at execution time
  (the generator is a 4C concern, not 5F).
- **RETIRED:** `NucleiRunner.run(..., execute=True)`
  (any code path that spawns Nuclei with the
  legacy runner is a v1 execution-blocked path;
  the 5F executor does not import or call
  `NucleiRunner`). `to_findings()` is NEVER
  called by 5F.
- **FORBIDDEN:** `to_findings()` instantiation in
  5F (boundary test), `NucleiFinding`
  instantiation in 5F (boundary test), any
  import of `ai.researcher.nuclei_runner` in
  5F (boundary test).

The 5F executor lives at
`ai/execution/nuclei_executor.py` and is the only
public call path that consumes an
`IssuedExecutionAuthorization` for
`execution_class = "nuclei_scan"` and produces a
sealed `EvidenceRecord`. No other code path
performs 5F IO.

## 21. Open decisions

- **5F.OD.1 (DECIDED, OPEN) — Host override in raw
  request lines.** A template may carry a
  `Host:` header in the `raw:` block. 5E's
  translator already denies the `Host` header at
  the artifact level. 5F REJECTS templates that
  carry a `Host:` line in the raw block (the
  transport generates `Host: <canonical_host>`
  from the binding). Open: should 5F instead
  REWRITE the `Host` header to the canonical
  host? DECIDED: REJECT. A template that needs
  to fix `Host` is a sign the template is wrong;
  rewriting silently would hide the bug.
- **5F.OD.2 (DEFERRED) — Per-hop URL reporting in
  v1.** When the live runner is available, it
  MUST report per-hop `dial_ips`. In v1 the
  harness returns the initial URL only. A
  `FakeNucleiRunner` that returns a scripted
  multi-hop chain is added for the redirect
  tests; the runner interface includes an
  optional `chain_urls: list[str]` field.
- **5F.OD.3 (DEFERRED) — Per-program Nuclei rate
  limits.** The 5H-core `nuclei_rate_per_second`
  ceiling is reused in spirit but not yet bound
  to a 5F executor rate limiter (the operator
  can throttle by issuing fewer authorizations;
  5J will own the cross-program rate limit).
- **5F.OD.4 (DEFERRED) — Template signing.** A
  server-side HMAC over canonical template bytes
  is not yet designed; the 5F gate accepts any
  template whose hash matches the bound
  `ArtifactBinding.content_hash`. Signing would
  add an additional proof that the bytes were
  not replaced after issuance; the existing
  5B artifact identity already provides this via
  re-validation, so signing is DEFERRED.
- **5F.OD.5 (DEFERRED) — Egress proxy as belt-
  and-braces.** May be added on top of the
  `B3` namespace to provide a single audit
  choke-point for every outbound packet. The
  proxy's design is the same as in 5E §11
  (DEFERRED, not blocking).

## 22. Blocking gates

- **B1 (BLOCKING, lifted by 5E) — production
  `AddressSource` selection + review.** 5F
  inherits the 5E lift; the harness does not
  resolve, and the future B3 namespace stub
  reuses 5C's `DnsResolver` protocol. **Status:
  ready for live when B3 lands.**
- **B2 (BLOCKING) — production Mongo adapters
  for authorization store, execution ledger,
  audit, evidence backends, and orphan sweep.**
  5F uses only the in-memory adapters
  (`InMemoryAuthorizationStore`,
  `InMemoryExecutionLedger`,
  `InMemoryAuditSink`, `EvidenceBuilder.begin()`).
  **Status: BLOCKING for live (same as 5E).**
- **B3 (NEW, BLOCKING) — Nuclei sandbox / egress
  boundary.** The future
  `B3NetnsNucleiRunner` is the only path that
  may ever set `LIVE_NUCLEI = True`. The B3
  review must cover:
  - Linux `netns` + `cgroups v2` lifecycle;
  - `landlock`/`seccomp-bpf` policy;
  - literal-IP-only DNS stub;
  - rlimit enforcement inside the namespace;
  - the `killpg(SIGKILL)` reaper on parent
    death;
  - the operator review of the canonical argv
    shape;
  - the operator review of the canonical
    environment;
  - the production binary trust path (signing,
    SHA-256 of the canonical binary).

  Until B3 closes, `LIVE_NUCLEI` stays `False`
  and the offline harness is the only runner.

- **B4 (BLOCKING for v1.1+) — production
  template source of truth.** The
  `nuclei_template` collector (5C.1) currently
  maintains a corpus; the 5F executor is
  agnostic to where the canonical bytes came
  from (it only re-validates). A future review
  should approve the operator-controlled
  template corpus identity so a corrupted
  template cannot be issued. **Status:
  BLOCKING for v1.1 (not v1.0).**

## 23. Exact implementation plan for 5F

5F.1 — `NucleiExecutionSpec` (frozen typed record)
+ `build_nuclei_argv` (canonical argv shape; no
artifact influence).
5F.2 — `NucleiRunner` Protocol + `FakeNucleiRunner`
+ `LiveNucleiRunner` (LIVE_NUCLEI_BLOCKED, the
mirror of 5E's `RealSocketFactory`).
5F.3 — `NucleiTemplateContent` extension with the
5F §7 deny list + `TemplateSafetyReport` (no
network I/O, pure parser over canonical bytes).
5F.4 — `validate_nuclei_safety_template(content,
template_bytes)` — closed, deterministic, fail-
closed. Unit matrix.
5F.5 — `NucleiObservationBuilder` (wraps the
5H-core `NucleiObservation` and the `scrub_text`
+ `find_finding_like_text` helpers; never
imports `NucleiFinding` or `to_findings`).
5F.6 — execution lifecycle (5F §14, exact 18-step
order); ledger / audit / evidence integration
following the 5E pattern.
5F.7 — `NucleiExecutor` class + `execute_nuclei`
public function. The only public call path
performing IO. `LIVE_NUCLEI = False` constant +
`LIVE_NUCLEI_BLOCKED` closed code.
5F.8 — subprocess sandbox (5F §10). Linux-only
`preexec_fn` rlimits; raises
`NUCLEI_RUNTIME_UNSUPPORTED` on other platforms.
5F.9 — adversarial offline test suite (5F §18)
+ local-harness readiness review (harness is
5F's own work; the future local-harness E2E is
5J work, but 5F proves harness-testability).

Each step lands with tests; no step enables
live Nuclei (B3+B4 gates are documented in code
as runtime guards, not comments).

## 24. Security invariant checklist

- [ ] `ALLOWED`-triple + live authz + valid binding +
  valid template + closed B3 review precede any
  subprocess launch.
- [ ] Wire target = canonical host + effective port
  only (no raw URL authority parameter).
- [ ] Every subprocess is a server-controlled
  binary; argv is a frozen Python list; no shell
  parsing.
- [ ] SNI = Host = canonical host — enforced by the
  B3 namespace stub; the harness does not connect.
- [ ] Hop *h+1* never inherits hop *h* (per-hop
  re-evaluation; reuse of 5E redirect state machine).
- [ ] eTLD+1 / sibling / CDN / cert / interactsh /
  OOB authorizes nothing (5F §7, §13).
- [ ] Method set closed; no implicit redirects; raw
  request is a single line (5F §7).
- [ ] No pooling / cookies / proxy-env / OOB /
  arbitrary-callback / interactsh / fuzzing /
  attack-mode / clustering / workflows (5F §7,
  §13).
- [ ] Bounds enforced at every layer (5F §11;
  reused 5H-core ceilings; closed `nuclei_output_bytes`
  cap).
- [ ] Secrets banned from wire and store with
  fixture proofs (scrubber + argv + env; no
  inherited env, no proxy creds).
- [ ] Evidence separates authorized / evaluated /
  executed / dialed / observed / matched (5F §16).
- [ ] At-most-once (ledger CAS) vs at-least-once
  (seal/index/audit) separated; crash matrix
  green (5F §15).
- [ ] No verdict / finding / severity / confirmed /
  not_vulnerable / matched alias ever appears in
  the sealed record (5F §16; boundary test).

---

- files created: `agent-reports/nuclei-executor-architecture.md`
  (this report only)
- files modified: none (read-only phase; verified
  by inspection discipline — no editor write to
  any source file occurred)
- tests run: none (architecture phase; no code to
  test — existing suites untouched and
  unexecuted)
- live execution performed: NO (no Nuclei
  invocation, no subprocess, no network, no DNS,
  no browser, no LLM, no MongoDB, no finding, no
  verdict, no subprocess escape path tested)
- Nuclei executed: NO
- network: NO
- DNS: NO
- Git operations: NO
- blocking decisions: B1 ready (5E lift), B2
  BLOCKED (production adapters), B3 BLOCKED
  (Nuclei sandbox / egress), B4 BLOCKED for
  v1.1+ (production template source of truth)
- next implementation phase: 5F implementation
  per §23 (5F.1→5F.9), gated by B2 + B3 + B4
  runtime guards

REPORT:
 /opt/watch/agent-reports/nuclei-executor-architecture.md
