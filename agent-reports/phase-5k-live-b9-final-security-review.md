# Phase 5K-live B9 — Final Security Review Before Controlled Validation

Review date: 2026-09-08
Scope: Offline adversarial review of the Phase 5K-live controlled-validation
path (CVE-2026-1557 nuclei_scan), security review only.
Decision: **GO_FOR_CONTROLLED_VALIDATION**

---

## 1. Scope

This review examines the complete chain that would, only after explicit
operator activation, run one pinned Nuclei template against one controlled
target through a default-deny network namespace:

1. **Authorization Boundary** — `ai/authorizer/`, `ai/scope/`, `ai/schemas/execution_authorization.py`
2. **DNS / Network Escape** — `ai/resolver/` (dns.py, canonicalization.py, resolver.py), `ai/execution/b3_boundary.py`
3. **Nuclei Execution Boundary** — `ai/execution/nuclei_launcher.py`, `ai/execution/nuclei_executor.py`, `ai/execution/netns_sandbox.py`
4. **Evidence Security** — `ai/evidence/scrubber.py`, `ai/evidence/builder.py`, `ai/evidence/hashing.py`
5. **Resource / DoS** — `ai/limits/ceilings.py`, launcher rlimit + wall-clock handling
6. **Host Hardening** — running services, API surface, binaries, namespace tooling
7. **Live Activation Gate** — `ai/live_validation/`, `nuclei_executor.LIVE_NUCLEI`, `nuclei_launcher.LIVE_LAUNCH_ENABLED`

Review constraints (honored): REVIEW ONLY. No code or test modifications. No
commits, no pushes. No live egress. No `WATCH_AI_LIVE_VALIDATION=true`. No
`LIVE_LAUNCH_ENABLED=true`. No Nuclei against real targets, no external
IPs/domains, no external DNS lookups, no LLM/provider APIs. Verification had
to be performed by static analysis plus already-running local test suites;
anything beyond that is explicitly labeled as not-runtime-proven.

## 2. Method

- Read the enforcement code end to end: authorizer service + store contract,
  scope evaluator (`require_allowed`), resolver + canonicalization + DNS
  classification, launcher gate chain, executor spec/argv builders, sandbox
  lifecycle/rules/verify, evidence scrubber + builder hashing.
- Checked the running workload surface: `watch-api.service` (PID 6021,
  `api.py`) process environment and the FastAPI router layer for any path
  that can reach live execution.
- Host-state probes (read-only): environment variables of shell and workload,
  `/proc/<pid>/environ`, presence of scratch/template paths, binaries and
  symlinks, default IPv4 forwarding.
- Weighted the prior runtime proofs (this workspace, same host, run in
  earlier phases) as runtime evidence: B8.1 sandbox lifecycle tests
  (69 tests, incl. as-root) and the B8 retest packet-level boundary proof
  (RUNTIME_BOUNDARY_PROVEN) executed in an isolated topology.
- Applied the hard rule throughout: "implemented" is never treated as
  "securely proven". Where enforcement is proven only by static analysis (no
  runtime observation), the finding says so explicitly.

## 3. Findings

### 3.1 Authorization Boundary — CLOSED

**Status:** CLOSED (runtime-proven by existing suites; static confirmation of
every gate in the chain).

**Evidence**
- Typed issuance only: `issue_authorization` (ai/authorizer/service.py)
  accepts only `AuthorizationRequest`; validated issuer identity, caller
  scope, method pair, expiry-after-issuance, and XSS derivation-source
  binding. No `authorize_from_dict/json` exists anywhere.
- Typed retrieval: `get_issued_authorization` re-validates the stored record
  through `IssuedExecutionAuthorization.model_validate` (service.py
  `get_issued_authorization`), so a store facsimile cannot smuggle authority.
- Liveness re-read: the executor re-reads the authorization from the store at
  execution time and refuses CONSUMED / REVOKED / EXPIRED / past-expiry
  (`_is_live`).
- Single-use consume: `consume_authorization` is an atomic CAS
  ISSUED→CONSUMED with version conflict ⇒ `AUTHZ_ALREADY_CONSUMED`, no retry.
- Cross-binding mandatory: scope evaluator `_base_context`
  (ai/scope/evaluator.py) verifies execution_id format
  `^ex-[0-9a-f]{32}$`, execution↔resolution↔authorization binding, program
  name, canonical host equality (re-canonicalized), scheme + effective port,
  recomputed `canonical_target_hash`, and dial pin (addresses == resolved
  addresses, SNI == canonical host, `pin_required is True`).
- `require_allowed` (ai/scope/evaluator.py) is the only transport entry gate
  and requires `decision == "ALLOWED"` plus an exact
  (authorization_id, execution_id, resolution_id) triple; anything else
  raises closed `ScopeError`.
- The scope policy is re-read fresh per evaluation with `scope_lists_hash`
  drift detection (`SCOPE_DRIFT`), so a mid-chain policy change stops
  execution.

**Residual Risk:** Authorization is time-of-use checked to the microsecond of
the observed clock; a race where policy changes between evaluation and dial
is detected by hash re-check at both the scope gate and the egress-policy
builder (policy version + allowlist re-check of every resolved address).
Acceptable for a manually-started controlled validation.

**Required Action:** None before controlled validation; re-verify a live
authorization record is issued, in `ISSUED` state, and not expired at
activation time.

### 3.2 DNS / Network Escape — CLOSED (with a documented fail-closed capability gap)

**Status:** CLOSED; one NFC (non-failure, capability) note must be understood
before controlled validation.

**Evidence**
- `classify_address` (ai/resolver/dns.py) is a pure deny-check over
  loopback/unspecified/private/link-local/multicast/reserved/mapped/metadata
  classes; only globally routable unicast passes; unparseable fails.
- `validate_answers`: ceiling 8 (never truncated), empty set
  `DNS_RESOLUTION_FAILED`, any unsafe/malformed answer fails the whole set
  (no "first clean wins"), deterministic numeric ordering.
- DNS rebinding cannot cross the boundary: the resolution is performed once
  and pinned (`resolved_addresses`, dial pin), and the egress policy is built
  from the same pinned set with `check_destination_allowed` re-asserted per
  address. There is no re-resolution in the child path.
- The sandbox denies DNS by construction: `udp dport 53` DROP and all-UDP
  DROP, no default route, and the child is in a fresh network namespace (no
  nameserver of its own). The GCP metadata resolver 169.254.169.254 is
  explicitly dropped for both TCP and UDP.
- Runtime-proven (B8 retest, isolated topology): only the allowlisted
  IP:port responded (200 OK); unauthorized addresses, loopback, and
  non-approved ports were unreachable (silent TIMEOUT, no RST); UDP was
  refused with EPERM.
- Metadata service, loopback, and any non-allowlisted destination are
  unreachable even if the child tries to dial them.

**Capability gap (no escape):** the child receives the target string
`{scheme}://{canonical_host}`. For a DNS-name host the sandbox has no
resolver, so a hostname target cannot resolve in-namespace and the scan fails
closed (never executes against an un-pinned address). As built, only
IP-literal targets are executable in live mode. This is fail-closed, but
controlled validation must therefore use an IP-literal controlled target.

**IPv6 note (no escape, static analysis only):** `build_target_string`
never brackets an IPv6 host, so an unbracketed `https://2001:db8::1`-shaped
URL is produced; Nuclei will reject the malformed URL in the child and the
scan fails closed. Not runtime-proven (no authorized v6 target exists), so it
is treated as deny-with-error by construction.

**Residual Risk:** scope is host-based while the firewall is IP-allowlist
granular; two different hosts sharing one approved IP are both reachable. Not
an escape; relevant only if shared-IP infrastructure is ever authorized. The
controlled target must be a dedicated operator-owned IP.

**Required Action:** Controlled validation uses an operator-owned controlled
IP literal verified to serve only the expected application on the approved
port.

### 3.3 Nuclei Execution Boundary — CLOSED (one hardening item for the activation wiring)

**Status:** CLOSED for the gate chain that exists; one wiring-level
recommendation recorded so it is not silently lost at activation.

**Evidence**
- Frozen constants: `SERVER_CONTROLLED_NUCLEI_BINARY = "/usr/bin/nuclei"`
  (executor), `PINNED_NUCLEI_VERSION = "v3.11.1"`, `LIVE_NUCLEI = False`
  (executor), `LIVE_LAUNCH_ENABLED = False` (launcher:85). Binary contract
  verified on-host: `/usr/bin/nuclei -> /usr/local/bin/nuclei`, v3.11.1.
- Full pre-launch gate order (`launch_nuclei_bounded`, ai/execution/nuclei_launcher.py):
  1. clean launch environment (proxy/CA/resolver shapers fail closed),
  2. server binary presence + executable,
  3. pinned-version proof (`-disable-update-check -version` under a
     PATH-only `_PROBE_ENV`),
  4. `assert_single_target_argv` — exactly one `-u`/`-t`;
     `-retries 0`, `-disable-redirects`, `-no-interactsh`,
     `-bulk-size 1`, `-concurrency 1`, `-timeout 5`, `-jsonl`,
     `-restrict-local-network-access`; template operand must start with
     `/srv/watch/scratch/nuclei/`,
  5. spec argv digest coherence (argv the executor built, nothing else),
  6. production sandbox capability probe (refuses on this host today),
  7. master `LIVE_LAUNCH_ENABLED` switch — frozen False with a
     second unreachable raise (`# pragma: no cover`).
- `run_bounded_process` (launcher): `shell=False` always (string argv
  rejected), env allowlist re-checked, wall-clock via `communicate(timeout)`,
  output caps, rlimits via child-side `setrlimit` with honest
  `AppliedLimits` accounting.
- Template confinement: `build_nuclei_argv` requires the template under
  `/srv/watch/scratch/nuclei/` and the launcher re-asserts it. The scratch
  template directory does not exist on this host, so nothing is executable
  even past the gates.
- Runtime-proven (B8.1 + B8 retest, same host): full sandbox lifecycle
  CREATE→CONFIGURE→VERIFY→EXECUTE→COLLECT→TEARDOWN with 0 orphans on both the
  nft and iptables legs; VERIFY failure raises before spawn; CONFIGURE failure
  still tears down; no host-network fallback exists.

**Wiring hardening item (not a blocker today):**
`run_nuclei_in_sandbox` (ai/execution/netns_sandbox.py) type-checks the spec
and re-derives the rules, but it does not itself re-run the frozen-argv /
digest / single-target gates. It trusts a genuine `NucleiExecutionSpec`.
Today this is unreachable from production code — no production caller exists,
and both live runners (`LiveNucleiRunner`, `B3NetnsNucleiRunner`) raise
`NUCLEI_EXECUTION_BLOCKED` before any process primitive — so the adversarial
surface is tests only. Required action: the controlled-validation wiring must
route through the full `launch_nuclei_bounded` gate chain (or explicitly
re-validate argv/digest inside `run_nuclei_in_sandbox`).

**Residual Risk:** trusted-but-subverted nuclei binary capability (inherent —
the server-controlled binary runs with the host's privileges; bounded by the
netns firewall, resource limits, wall clock, and operator supervision).

**Required Action:** wire activation exclusively through the gate chain;
re-assert argv/digest in the sandbox entry before first enablement.

### 3.4 Evidence Security — CLOSED

**Status:** CLOSED (static confirmation; scrub-on-all-paths established).

**Evidence**
- One shared scrubber (ai/evidence/scrubber.py): secret-shaped header values
  and query parameters redacted by name (casefold + compact markers),
  URL userinfo stripped, high-confidence operator-secret shapes in free text
  redacted (`[REDACTED]`), and secret-shaped detail strings *refused* at
  error boundaries rather than persisted.
- Every Nuclei output stream flows through `_observe_stream`
  (ai/execution/nuclei_executor.py): normalize CRLF→LF, `scrub_text`, then
  hash the scrubbed capped sample; raw bytes never persist and never reach
  exceptions. The hash covers exactly the stored (scrubbed) sample.
- Evidence structure: the observations hash carries hashes only
  (`argv_digest`, `stdout_hash`, `stderr_hash`, `template_hash`, exit facts);
  raw samples live only under the content hash, in scrubbed, capped form
  (8 KiB samples / 1 MiB stream caps per ceilings).
- Redaction-bypass probes considered during review: case/whitespace/
  multiline/JSON-nesting/header+cookie framing. Mitigations confirmed:
  casefold + `(?i)` patterns cover casing; `\s*` tolerates spacing;
  multiline content is scanned line-wise with `\S+` run capture;
  JSONL lines are matched as text. A JSONLine remainder beyond a matched
  secret is over-redacted (safe direction).
- Observation-only design respected: `NucleiObservation` and
  `finding_like_text_present` are facts, never verdicts; findings are not
  auto-confirmed.

**Residual Risk:** regex-based scrubbing cannot guarantee detection of every
adversarial encoding (e.g., base64/hex-wrapped secrets); the rate of
forwarding such shapes is unproven, and a missed shape propagates into the
stored hash. Impact is bounded to small capped samples; accept for a
controlled, single-target validation whose target does not echo secrets.

**Required Action:** controlled target must not echo credentials/secrets in
responses; operator reviews the sealed evidence record after each run.

### 3.5 Resource / DoS — PARTIALLY CLOSED (RLIMIT_NPROC root bypass; see §4 Decision)

**Status:** PARTIALLY CLOSED — effective bounds present; one kernel-level
limit is not effective for a root child and is recorded as an accepted
residual with a required hardening path.

**Evidence**
- Frozen ceilings (ai/limits/ceilings.py): nuclei wall 120 s, concurrency 1,
  rate 5/s, output 1 MiB, subprocess memory 512 MiB, cpu 60 s, fd 64,
  proc 1. Configuration may only tighten; unknown/unbounded values fail boot.
- Wall-clock enforced at the parent (`communicate(timeout)` + kill and reap).
- `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE` are applied
  child-side via `setrlimit` and ARE enforced for a uid-0 child.
- `RLIMIT_NPROC` is applied but the Linux kernel does not enforce the
  process-count limit against uid 0 / CAP_SYS_RESOURCE processes, and the
  sandbox child runs as root. `proc_limit=1` therefore does not bound a
  fork-bombing root child. The honest-accounting object records NPROC as
  "applied" (the setrlimit call succeeds), which overstates its enforcement.
- Mitigating stack that remains effective against a forking child: memory
  (AS) ceiling, fd ceiling, wall-clock kill, and the netns firewall (a fork
  storm cannot egress).

**Residual Risk:** a compromised or buggy nuclei binary/template could spawn
processes until AS/fd/wall limits bite; grandchildren could briefly outlive
the direct-child kill. Egress remains firewalled. Not exploitable against
other hosts or the network boundary.

**Required Action:** add a cgroup `pids` controller (and ideally a process
group kill) around the child before any wider/resource-facing enablement; see
§4 Decision.

### 3.6 Host Hardening — PARTIALLY CLOSED (conditions required for controlled validation)

**Status:** PARTIALLY CLOSED — no activation surface exists today; two
host-state conditions are recorded for the activation runbook.

**Evidence**
- No workload or network surface can trigger live execution:
  - The running `watch-api.service` (PID 6021, `api.py`) process environment
    contains no `WATCH_AI_LIVE_VALIDATION`, live-launch, or proxy variables
    (verified via `/proc/<pid>/environ`).
  - The FastAPI router layer (`backend/routers/*`, `config/`) has zero
    references to `live_validation`, `launcher`, `run_nuclei`, `netns_sandbox`,
    or the gates. The API cannot reach any live-execution path.
  - The master switches are frozen constants in code (`LIVE_NUCLEI = False`,
    `LIVE_LAUNCH_ENABLED = False`); only a direct source edit can change them.
- The scratch template root `/srv/watch/scratch/nuclei/` does not exist; even a
  routed execution would find no approved template.
- Namespace tooling verified present: unshare + CAP_SYS_ADMIN/CAP_NET_ADMIN,
  `nft v1.0.9`, `iptables v1.8.10 (nf_tables)`; namespace creation and nft
  rule application proven at runtime.
- Nuclei binary contract verified on-host: `/usr/bin/nuclei ->
  /usr/local/bin/nuclei` at v3.11.1 (previous missing-binary blocker closed).
- Host condition: `net.ipv4.ip_forward = 1` (GCE default). With
  default-deny namespaces and no NAT this does not open sandbox egress;
  nonetheless the activation runbook should confirm the sandbox never
  installs NAT/forward hooks (it does not — verified in rule rendering) and
  that Docker bridge traffic (nft `table ip nat` DOCKER dnat toward a bridge
  LAN) is unrelated to `watch-*` namespaces.

**Residual Risk:** host-level physical breakout of the sandbox (VM
compromise) is outside this review's threat model; the reviewer notes the
host is a dedicated GCP VM running as root for sandbox operations.

**Required Action:** controlled validation happens on this disposable VM with
the operator holding the only allowed egress address; document the absence of
any other listener on the target's port (`ss -tlnp` check in the runbook).

### 3.7 Live Activation Gate — GO_FOR_CONTROLLED_VALIDATION (conditioned)

**Status:** CLOSED (decision word: GO_FOR_CONTROLLED_VALIDATION)

**Evidence**
- Default-off kill switches: `WATCH_AI_LIVE_VALIDATION` must be literally
  `1/true/yes/on` (case-insensitive) AND an explicit caller-supplied target
  flag is required (ai/live_validation/config.py). Current state: not set
  anywhere.
- Template/identity gates (ai/live_validation/gates.py): hard-scoped to
  CVE-2026-1557, template pinned in code with a canonical digest, arbitrary
  template paths rejected, safety + specificity validation deterministically
  run before anything can launch.
- Frozen runtime switches in code (`LIVE_NUCLEI = False`,
  `LIVE_LAUNCH_ENABLED = False`) with the launcher's switch after the
  sandbox capability gate, so even a source flip to `True` cannot launch
  without a provisionable default-deny namespace.
- The two residuals (NPROC root bypass §3.5, sandbox-entry re-validation
  item §3.3) are documented, bounded, and have explicit activation-runbook
  steps.

**Required Action (activation checklist for CONTROLLED validation):**
1. Issue a fresh `nuclei_scan` authorization (ISSUED, unexpired) for the
   operator-owned controlled target IP and the pinned template digest.
2. Confirm the controlled target answers only on the approved port to the
   approved allowlisted address, and does not echo secrets.
3. Materialize `/srv/watch/scratch/nuclei/` with the pinned template and
   verify its digest matches `PINNED_TEMPLATE_DIGEST`.
4. Route execution exclusively through `launch_nuclei_bounded`-style gates
   (re-assert argv/digest at the sandbox entry before the run).
5. Leave `LIVE_NUCLEI`, `LIVE_LAUNCH_ENABLED`, and
   `WATCH_AI_LIVE_VALIDATION` at their frozen/absent defaults for the
   first run; enable only under explicit operator supervision, one run.

These are runbook preconditions, not code changes; failing any of them the
verdict for that run is no-run.

## 4. RLIMIT_NPROC Decision

**ACCEPTED RESIDUAL RISK.**

Rationale: the child runs as root; the Linux kernel does not enforce
RLIMIT_NPROC for uid-0 / CAP_SYS_RESOURCE processes, so `proc_limit=1`
(`nuclei_executor.default_resource_limits`) is not an effective fork-bomb
bound for the sandbox child. The residual is bounded by the limits that ARE
enforced (RLIMIT_AS, RLIMIT_NOFILE, RLIMIT_FSIZE, RLIMIT_CPU, wall-clock
kill), by the netns firewall (fork storms cannot egress), and by the pinned
binary + pinned HTTP-only template + disposable VM + operator supervision
during controlled validation. Impact is confined to the host and to the run's
own duration. Acceptance is time-boxed: a cgroup `pids` controller (plus a
process-group kill at wall-timeout) is a required hardening item before any
wider or resource-facing enablement, and this decision must be re-reviewed at
that point. No network-boundary exposure is associated with this residual.

## 5. Live Activation Decision

**GO_FOR_CONTROLLED_VALIDATION**

The runtime network boundary is proven (B8 retest: RUNTIME_BOUNDARY_PROVEN on
both nft and iptables legs; only the approved IP:port reachable; unauthorized
addresses, loopback, and extra ports silently unreachable; UDP refused); the
authorization, scope, binary-pin, and evidence paths each fail closed on
every adversarial class examined; live egress remains DISABLED structurally
and environmentally; and the two documented residuals are bounded, accepted
with required actions, and have explicit runbook steps. Proceeding to the
controlled single-target validation is allowed under the §3.7 checklist.

Identified preconditions that must hold at activation time (else no-run):
controlled IP-literal target, single pinned template, gated wiring,
frozen/disabled switches, operator supervision.

## 6. Live Egress State

**DISABLED** (verified at review time)

- `nuclei_executor.LIVE_NUCLEI = False` (frozen constant).
- `nuclei_launcher.LIVE_LAUNCH_ENABLED = False` (frozen constant; switch sits
  after the sandbox capability gate).
- `WATCH_AI_LIVE_VALIDATION` not set in the shell or in the running
  `watch-api.service` environment (the gate demands literal `true/1/yes/on`).
- No proxy/PAC/CA-shaping variables in either environment.
- No service or API route can reach launcher, sandbox, or executor live paths.
- No approved template exists (`/srv/watch/scratch/nuclei/` absent), so even
  a hypothetical routed launch has no template to run.

## 7. Final Security Statement

The Phase 5K-live controlled-validation channel (CVE-2026-1557, pinned
template, verified binary, default-deny network namespace, typed
single-use authorization, scrubbed evidence) is, on the evidence available
and by the standards of this review, secure to proceed to a single,
operator-supervised controlled run against an operator-owned dedicated IP
target. Every escape class examined — authorization tampering, DNS
rebinding/re-resolution, local+metadata targets, redirects, unbounded
output/memory/time, secret leakage into evidence, and API/service-triggered
activation — fails closed in the code as reviewed, and the network-boundary
enforcement is backed by a runtime proof from this same host and codebase.
The two accepted residuals (kernel-level RLIMIT_NPROC non-enforcement for a
root child; wiring-level re-validation to be asserted at the sandbox entry)
are bounded, documented, and carry explicit activation-runbook actions.
This is a security-review position and does not by itself enable anything:
activation still requires the frozen switches/environment to be changed by an
operator with the §3.7 checklist satisfied.