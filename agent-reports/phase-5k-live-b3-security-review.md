# Phase 5K-live B3 — Security / Egress Gate Review

**STAGE:** Phase 5K-live B3 — Security / Egress Gate Review (REVIEW-ONLY)
**Date (UTC):** 2026-09-07
**Scope:** `ai/live_validation/`, `ai/research_cli.py`, plus all depended-on
components: `ai/execution/` (5F/5E/B1/B3), `ai/authorizer/` (5B),
`ai/resolver/` (5C), `ai/scope/` (5D), `ai/evidence/`, `ai/limits/`,
`ai/schemas/`, `ai/verification/deterministic/`, `ai/researcher/nuclei_pipeline.py`,
`ai/config.py`
**Method:** static code-path tracing + offline adversarial input matrix
(no network, no DNS, no subprocess, no browser, no LLM, no Mongo).
**Verdict: NO-GO** (3 blockers; real egress must not be enabled until fixed)

---

## 1. Executive verdict

**NO-GO for real egress.**

The offline gate chain (config → target → candidate → template →
authorization → scope → execution → verification) is correctly ordered,
fail-closed, and genuinely offline today: `LIVE_NUCLEI = False`
(`ai/execution/nuclei_executor.py:123`), `LiveNucleiRunner.launch` and
`B3NetnsNucleiRunner.launch` unconditionally raise
`NUCLEI_EXECUTION_BLOCKED` (`nuclei_executor.py:891-911`), and the dry-run
path never touches the runner (`ai/live_validation/lane.py:311-330`,
`test_runner_never_touched_in_dry_run`). No pre-authorization network
activity exists on the lane path.

However, enabling real egress (i.e. replacing the fake runner with any
runner that actually dials) would activate three structural gaps that
today's offline tests cannot see, because the fakes never resolve,
dial, or follow redirects:

| # | Blocker | File / function |
|---|---------|-----------------|
| B1 | **Redirect scope bypass** — Nuclei follows redirects internally; lane never re-authorizes/re-scopes/re-resolves them | `ai/live_validation/lane.py:501-536` (`_evaluate_scope` calls `evaluate`, never `evaluate_chain`); `ai/execution/nuclei_executor.py:736-767` (`build_nuclei_argv`, no redirect flags) |
| B2 | **DNS resolution bypass + rebinding** — lane builds `TargetResolution` by hand from `dns_mapping`/default `8.8.8.8`, never calls `TargetResolver`/`validate_answers`; a real Nuclei subprocess resolves the hostname itself via system DNS, ignoring the `DialBinding` pin | `ai/live_validation/lane.py:501-595` (`_evaluate_scope`, `_build_resolution`) |
| B3 | **Unbounded Nuclei network behavior** — argv has no OOB/interactsh disable, no update pinning beyond `-disable-update-check`, no egress sandbox/netns wired; B3 boundary helpers exist but the lane never calls them | `ai/execution/nuclei_executor.py:736-767`; `ai/execution/b3_boundary.py` (not referenced by lane) |

Additionally 3 HIGH findings (evidence redaction gap, target-normalization
bypass of the shared canonicalizer, unreviewed unblock step) must be fixed
before egress. Counts: **BLOCKER 3 / HIGH 3 / MEDIUM 3 / LOW 3 /
INFORMATIONAL 2.**

Nothing in this review required or performed live execution. The
`LiveNucleiRunner currently blocked` claim is **verified true** — which is
also why "enabling egress" is necessarily a future code change that must
itself go through B3 review rather than a flag flip.

---

## 2. Runtime call graph (complete path, traced, not assumed)

```
ai/research_cli.py::run_validate_live (l145)
  mode = "live" iff args.live else "dry_run"
  └─ ai/live_validation/lane.py::ControlledLiveValidationLane.run (l207)
       Gate 1 config  (l238-249)
         live mode → config.require_live_validation_enabled()
           └─ ai/live_validation/config.py::require_live_validation_enabled
                reads WATCH_AI_LIVE_VALIDATION (false by default) → raises
                LiveValidationDisabled → BLOCKED("LIVE_VALIDATION_DISABLED")
       Gate 2 target  (l252-264)
         _parse_host / _scheme_for / _port_for  [urlparse only — §3]
       Gate 3 candidate (l267-274)
         └─ ai/live_validation/gates.py::resolve_pinned_candidate
              CVE != "CVE-2026-1557" → ValueError → BLOCKED("CVE_MISMATCH")
       Gate 4 template (l277-286)
         └─ gates.validate_template_safety → H1/H2 validators
              (ai/researcher/nuclei_artifact_validator.py)
       Gate 5 authorization (l289-296)
         └─ lane._issue_and_verify_authz (l448-499)
              builds AuthorizationRequest (issuer "human-review-board",
                caller_scope "manual", execution_class "nuclei_scan")
              └─ ai/authorizer/service.py::issue_authorization
                   └─ InMemoryAuthorizationStore.put_new
              └─ get_issued_authorization → lifecycle must be ISSUED
       Gate 6 scope (l299-308)
         └─ lane._evaluate_scope (l501) + lane._build_resolution (l538)
              addresses = dns_mapping.get(host, ("8.8.8.8",))  [NO DNS]
              resolution = hand-built TargetResolution (RESOLVED)
              └─ ai/scope/evaluator.py::ScopeEvaluator.evaluate
                   (NOT evaluate_chain — no hops) → must be ALLOWED
       dry_run → record execution/verification NOT_PERFORMED, return
                 BLOCKED("DRY_RUN_NOT_PERFORMED"), zero network (l311-330)
       Gate 7 execution (l336-372) [live mode only]
         runner = runner_factory()          # default FakeNucleiRunner
         deps = NucleiExecutorDeps(InMemory ledger/audit, injected clocks)
         artifact_reference = build_artifact_reference(...VALID...)
         └─ ai/execution/nuclei_executor.py::execute_nuclei (l1637)
              └─ _NucleiExecutor.run — 20-step order (l1308):
                 1 typed validation → 2 authz liveness re-read →
                 3 _check_binding → 4-5 require_allowed →
                 6 _revalidate_artifact → 7 validate_nuclei_safety_template →
                 8 closed spec (build_target_string / build_nuclei_argv /
                    build_nuclei_environment / scratch_dir_for) →
                 9-10 ledger claim + CAS consume + STARTED →
                 11-12 pre-launch audit pair → 13-14 runner.launch(spec)
                 → 15 _observe_stream (scrub+cap) → 16 NucleiObservation →
                 17 EvidenceBuilder.seal → 18-19 ledger/audit terminal
         LiveNucleiRunner.launch → raises NUCLEI_EXECUTION_BLOCKED (l891)
         B3NetnsNucleiRunner.launch → raises NUCLEI_EXECUTION_BLOCKED (l907)
         FakeNucleiRunner.launch → records spec, returns scripted result (l862)
       Gate 8 verification (l378-404) [live mode only]
         envelope = canonical_envelope_bytes(evidence)
         handoff = assemble_handoff / bind_provenance
         seam = OfflineVerifiedSeam (ai/live_validation/seam.py)
         └─ ai/verification/deterministic/pipeline.py::verify_handoff
         accepted → VERIFIED / NO_MATCH / MATCH_UNVERIFIED via
           _resolve_final_status (l598): nuclei_advisory_weak → VERIFIED
           (advisory POTENTIAL ceiling, finding_eligible=False),
           nuclei_no_advisory_signal → NO_MATCH, else MATCH_UNVERIFIED
```

What the lane does **not** call (verified by import/read): `TargetResolver`
(`ai/resolver/resolver.py`), `FakeDnsResolver`/`ProductionAddressSource`,
`ScopeEvaluator.evaluate_chain`, any B3 helper (`build_egress_policy`,
`check_egress_dial`, `require_fresh_scope_for_redirect`,
`acquire_sandbox`), `NucleiPipeline` (research pipeline with
`subprocess.run(["nuclei", "-validate", ...])` at
`ai/researcher/nuclei_pipeline.py:99` — correctly **not** on the lane
path), any 5J finding/alert writer, any LLM entry point.

---

## 3. Target authority analysis

**Authority root: CLI `--target` string only.** `run_validate_live`
passes `args.target` straight to `lane.run` (`research_cli.py:158`); no
research artifact, LLM payload, template field, or DB value feeds the
target. The pinned candidate carries no target field
(`PinnedCveCandidate`: cve_id/template/bytes/digest/fixtures,
`gates.py:84-92`); the template supplies path/query/body only. Template
cannot change target — confirmed structurally (`NucleiTemplateContent`
has no host/scheme/authority field,
`nuclei_artifact_validator.py:72-89`; executor 5F gate denies
`absolute-url`/`authority-override`, `nuclei_executor.py:545-569`).

**Normalization is NOT the shared canonicalizer.** Gate 2 uses three
`urlparse`-only helpers (`lane.py:104-130`):

- `_parse_host`: `urlparse.hostname` (lowercased by stdlib) or raise.
  No trailing-dot strip, no IDNA, no numeric-IP unfolding, no `@`/`#`/`?`
  policing beyond what `hostname` already drops.
- `_scheme_for`: any scheme string (or `"https"` default when no `://`).
- `_port_for`: explicit port or `effective_port_for(scheme, None)` —
  which **raises for unknown schemes** (accidental fail-closed for
  `ftp://example.com` without port, observed `TARGET_INVALID`).

Downstream layers re-police most of this fail-closed (verified offline):

| Adversarial input | Observed dry-run outcome |
|---|---|
| `http://127.0.0.1`, `http://0.0.0.0`, `http://[::1]`, `10.0.0.1`, `192.168.1.1`, `169.254.169.254`, `fe80::1`, `::ffff:127.0.0.1` | `BLOCKED SCOPE_DENIED` (policy rejects IP entries → `SCOPE_POLICY_INVALID` → DENY) |
| decimal `http://2130706433`, hex `http://0x7f.0.0.1`, octal `http://0177.0.0.1`, short `http://127.1` | `BLOCKED SCOPE_DENIED` (same path; `_build_resolution` hardcodes `host_kind="dns"` so binding/policy disagree with canonical form) |
| `http://localhost` | `BLOCKED SCOPE_DENIED` |
| `http://user:pass@example.com`, `http://user@example.com` | **PASSES scope as `example.com`** (userinfo silently stripped by `hostname`) — LOW finding L1 |
| `http://example.com@attacker.com` | passes scope as `attacker.com` (correct dial host, but caller-intent masking) — LOW |
| `ftp://example.com` (no port) | `BLOCKED TARGET_INVALID` (via `effective_port_for`) |
| `ftp://example.com:21` (explicit port) | `BLOCKED ISSUANCE_FAILED` (`TargetBinding.scheme` Literal rejects `ftp`) — reaches issuance before failing; HIGH finding H2 |
| `file:///etc/passwd`, `data:…`, `//example.com/x`, `not a host://`, `javascript:…` | `BLOCKED TARGET_INVALID` |
| unusual ports `:21`, `:80`, `:443`, `:8443` | pass scope (any 1–65535 admitted; no port allowlist — by design, executor preserves exact port) |
| `:0`, `:99999` | `BLOCKED` (issuance validator / urlparse range) |
| trailing dot `https://example.com.` | `BLOCKED SCOPE_DENIED` (policy canonicalizes to `example.com`, binding mismatches raw `example.com.`) — fail-closed but inconsistent vs `EXAMPLE.COM` (passes) |
| `example.com%2eattacker.com`, `example.com%40attacker.com` | `BLOCKED SCOPE_DENIED` |
| bare `example.com`, `example.com:8080/path?q=1` | pass scope as https (documented default-scheme behavior) |

Resolution is performed before execution (Gate 6 precedes Gate 7;
executor re-checks bindings + `require_allowed` at steps 3–5), and no
pre-authorization network exists: Gates 1–4 are pure; Gate 5 touches only
the in-memory store; Gate 6 reads only `dns_mapping`/default tuple.
**Target-authority verdict: PASS with two LOW/HIGH hardening notes**
(userinfo silent-strip L1; non-shared normalization H2) — the IP/loopback/
private matrix is blocked, but only incidentally via policy-compile
failure rather than an explicit canonical address gate in the lane.

---

## 4. DNS / rebinding analysis

**No real DNS exists on the lane path, and no pinning would survive real
egress. This is BLOCKER B2.**

Exact mechanism (`lane.py:511-526, 550-595`):

1. `addresses = tuple(self._dns_mapping.get(host, list(_DEFAULT_PINNED_ADDRESS)))`
   — default `("8.8.8.8",)`; comment states it is "NEVER dialed
   (FakeNucleiRunner performs no transport)".
2. `_build_resolution` embeds those addresses directly into
   `TargetResolution.resolved_addresses` + `DialBinding` with
   `pin_required=True` (default), `sni_host=host`. It never calls
   `canonicalize_host`, `classify_address`, or `validate_answers`, and
   never instantiates `TargetResolver` or any `DnsResolver`.
3. The only DNS-shaped check before execution is `ScopeEvaluator`'s
   `_address_gate` (`evaluator.py:439-474`), which re-runs pure
   `classify_address` over the *supplied strings* — effective against a
   hostile `dns_mapping` (verified: `dns_mapping={example.com:
   [127.0.0.1]}` → `SCOPE_DENIED`, matching existing test
   `test_scope_denied_on_unsafe_address`), but it cannot observe real DNS.
4. `build_nuclei_argv` passes `target_string =
   scheme://canonical_host[:port]` — **the hostname, not a pinned IP**
   (`nuclei_executor.py:1418-1427, 718-733`). Any real Nuclei subprocess
   resolves that hostname through system DNS at dial time, completely
   bypassing `resolved_addresses`/`DialBinding`. Nothing in the lane or
   executor pins, re-checks, or aborts on re-resolution mismatch; the
   modules that do (`LiveSocketFactory` IP-literal-only dial,
   `verify_socket_peer`, B1 `ProductionAddressSource`,
   B3 `check_egress_dial`/`assert_dial_matches_egress`) are not wired
   into this lane.

Consequences if egress were enabled:

- Hostname resolving safe at Gate 6 can resolve private/loopback/
  link-local/metadata (`169.254.169.254`) at dial time → private-network
  access / SSRF.
- Classic rebinding (safe answer → attacker flips DNS to `127.0.0.1`
  with short TTL between validation and dial) has no TTL-pinning,
  single-resolution, or peer-verification defense on this path.
- IPv4/IPv6 differ in the wrong direction: `_build_resolution`
  hardcodes `host_kind="dns"` even for IP-literal hosts, so the
  `DialBinding`/`sni_host` semantics for literals are incoherent
  (today this only yields fail-closed DENYs; after any "fix" that
  special-cases literals it could become an allow path — must be
  reviewed then).
- `dns_source` is the static string `"live-validation-dns/v1"`, not a
  real resolver identity — audit would misrepresent provenance under
  real egress.

The 5C `TargetResolver` docstring is explicit that it "preserves the
binding; enforcement belongs to 5E/5F/5G" (`resolver.py:55-61`) — the
live lane skipped both halves (no resolver, no enforcement).

**Required fix (§16):** resolve once per execution through the reviewed
address source, `validate_answers`, single pinned address set; pass an
IP-literal-only dial path (B1 `LiveSocketFactory` + `verify_socket_peer`
or B3 `EgressPolicy`/`check_egress_dial`) to the runner instead of a
hostname `-u`; abort on any re-resolution/peer mismatch; stamp the real
`dns_source`. Until then, NO-GO.

---

## 5. Redirect analysis

**BLOCKER B1: redirects bypass authorization/scope entirely.**

- Lane calls `evaluator.evaluate` (initial target only). `evaluate_chain`
  and `HopObservation` are never constructed; no `Location` header is
  ever read, joined, canonicalized, or re-evaluated on this path.
- `build_nuclei_argv` emits no redirect control flags (no
  `-max-redirects`, no `-disable-redirects`-equivalent; the frozen argv
  is `(-t, -u, -disable-update-check, -silent, -no-color,
  -stats-interval 0, -json, -bulk-size 1, -timeout 5, -nc)`).
  Real Nuclei follows HTTP redirects by default, so a `302 Location:
  http://127.0.0.1/...` or `Location: http://private-network-host/...`
  from an authorized public target would be followed **inside the
  subprocess** with no re-authorization, re-scope, re-resolution, or
  scheme/host/port check.
- The 5D redirect machinery (`MAX_REDIRECT_EDGES = 5`,
  `_evaluate_hop` with per-hop policy re-read, downgrade/port/IP
  rules, `evaluator.py:213-306, 541-703`) and the B3 redirect gates
  (`check_redirect_target`, `require_fresh_scope_for_redirect`,
  `b3_boundary.py:593-724`) exist but are **not invoked** by the lane.
  The 5F template gate's denial of `redirects`/`max-redirects` *template
  keys* (`nuclei_executor.py:276-277`) constrains template YAML, not
  transport redirect behavior.
- Offline tests pass only because `FakeNucleiRunner` performs no
  transport — redirect handling is untested on this path by construction.

A redirect-crossing-scope event (public → `127.0.0.1`/metadata/
alternate host/port/scheme) is therefore an authorization/scope bypass
under real egress. **Required fix:** either disable redirects in the
closed argv (if Nuclei supports a hard disable flag, pin it in
`build_nuclei_argv` and test the flag is honored) or wire every
observed hop through `evaluate_chain` + fresh resolution + fresh egress
policy before the next dial (B3 `require_fresh_scope_for_redirect`
semantics), with the redirect budget enforced. No live requests were
made to verify; this is static reasoning + the argv evidence above.

---

## 6. Authorization + scope ordering

Verified order in `lane.run`: config → target → candidate → template →
`_issue_and_verify_authz` → `_evaluate_scope` → (dry-run return) →
`execute_nuclei` → `verify_handoff`. No network operation occurs before
authorization/scope:

- No preflight HTTP, fingerprinting, DNS, probing, or redirect
  resolution anywhere in Gates 1–6 (pure parsing, pinned bytes,
  in-memory store/policy; `NucleiPipeline._validate_with_nuclei`'s
  `subprocess.run(["nuclei", "-validate", …])` and
  `WatchAssetSelector` fingerprinting are **not imported** by the lane).
- No Nuclei auto-update/template-fetch on the lane path (no subprocess
  at all in dry-run; fake runner in live-offline).
- Executor defense-in-depth re-verifies at steps 2–5 (liveness re-read
  from store, `_check_binding`, fresh `require_allowed`) and revalidates
  the artifact at steps 6–7, so a stale caller copy cannot widen
  authority. CAS single-consume (`consume_authorization`, at-most-once
  via ledger claim) prevents replay.
- Issuer is hardcoded `"human-review-board"` with `caller_scope
  "manual"`; `NEVER_ISSUERS` includes `llm-researcher`
  (`execution_authorization.py:145-147`); expiry is far-future
  `2030-12-31` (lane constant — acceptable for offline review, must
  become short-lived for production; noted as LOW L3-adjacent).

**Ordering verdict: PASS.** (Redirect/DNS findings above concern what
happens *during/after* execution, not pre-auth activity.)

---

## 7. Nuclei subprocess boundary

Inspected: `LiveNucleiRunner`, `B3NetnsNucleiRunner`, `execute_nuclei`,
`NucleiExecutorDeps`, artifact handling, argv/environment builders
(`nuclei_executor.py:736-814, 838-911, 918-939`).

- **No `shell=True`, no shell interpolation, no `os.system`/`popen`.**
  The module does not import any process-creation facility at all
  (verified by line scan: `subprocess` appears only in ceiling key names
  and comments; no `import subprocess/os`). `LiveNucleiRunner.launch`
  raises before any process primitive could exist.
- **Executable fixed:** `SERVER_CONTROLLED_NUCLEI_BINARY =
  "/usr/bin/nuclei"` constant (`nuclei_executor.py:153`); not
  constructor-injected, not artifact-derived, not caller-supplied; argv
  always starts with it.
- **Template path not caller-controlled:** `template_path =
  f"{cwd}/{report.template_hash[:16]}.json"` where `cwd =
  scratch_dir_for(execution_id)` (must match `ex-[0-9a-f]{32}`) and
  `build_nuclei_argv` rejects any path outside
  `/srv/watch/scratch/nuclei/` (`TARGET_EXPANSION_DENIED`). Candidate is
  pinned (`resolve_pinned_candidate`); arbitrary template paths/bytes
  are rejected by hash + identity + binding revalidation
  (`_revalidate_artifact`, steps 6–7, including executor-time
  `validate_nuclei_safety_template` with the OOB/absolute-URL/identity-
  header/raw-request/matcher-specificity deny rules).
- **Arguments structural:** frozen argv tuple, `argv_digest_for`
  SHA-256, runner-return digest equality enforced
  (`run_result.argv_digest != spec.argv_digest` → `OUTCOME_UNKNOWN`).
- **Environment closed:** `build_nuclei_environment` allowlist
  (`HOME/LANG/LC_ALL/PATH/TMPDIR` only, from validated scratch dir; no
  caller env, no proxy inheritance). Stdin closed.
- **Runner allowlist:** `_NucleiExecutor` accepts only
  `(FakeNucleiRunner, LiveNucleiRunner, B3NetnsNucleiRunner)`; anything
  else → `TypeError` → lane maps to `BLOCKED execution:` (covered by
  `test_live_runner_injection_does_not_open_network`).
- **Update behavior:** `-disable-update-check` is pinned in argv; no
  other update mechanism exists in the module.

**Subprocess-boundary verdict: PASS for command/template injection.**
(Network-behavior scope of the same binary is BLOCKER B3, §8 — the
binary, once actually spawned, is a network actor the current argv
does not fully constrain.)

---

## 8. Nuclei network behavior

**BLOCKER B3: bounded network behavior cannot be guaranteed with the
current argv + wiring.**

What is pinned (good): single template (`-t` pinned hash path),
single target (`-u` + `-bulk-size 1`), `-disable-update-check`,
`-timeout 5`, `-stats-interval 0`, `-silent -no-color -nc -json`.

What is **missing / unwired**:

1. No OOB/callback disable flags (no `-disable-interactsh` /
   `-no-interactsh`-equivalent, no `-duc`-style containment). Current
   safety rests solely on the pinned template containing no OOB markers
   (true today — verified §9) rather than on a binary-level prohibition.
   Any future template change (or Nuclei default behavior emitting
   telemetry/DNS) is not defense-in-depth constrained.
2. No redirect budget flags (see B1).
3. No DNS pinning (see B2) — Nuclei performs its own resolution,
   retries, and (if it chooses) Happy-Eyeballs/IPv6/DoH-adjacent
   behavior outside the reviewed transport.
4. No egress sandbox: `B3NetnsNucleiRunner` is a raising placeholder;
   no netns/veth/nftables/egress-allowlist is created or checked by the
   lane; `acquire_sandbox`/`check_egress_dial`/`assert_dial_matches_egress`
   are never called.
5. Secondary requests (redirects, Favicons/conditional follow-ups per
   Nuclei internals, update/stat pings despite the flag on some
   versions, OCSP/CRL fetches during TLS verification) have no
   accounting on this path; `requests_per_execution = 7` /
   `redirect_hops = 5` ceilings are recorded in `ai/limits/ceilings.py`
   but **not enforced** by the lane/runner (enforcement "belongs to the
   future B3 boundary" per `nuclei_executor.py:647-656`).

For CVE-2026-1557 specifically the *intended* exchange is exactly **1
HTTP GET** (single path+query, `bulk-size 1`, `timeout 5`), but the
*deterministic maximum* under real egress today is unbounded for the
reasons above (redirect chain × re-resolution × OOB). **Required fix:**
pin the full closed flag set (redirect-disable-or-budget,
interactsh/OOB-disable, update-disable, retry/concurrency caps already
partially present), wire the B3 egress policy + sandbox + dial proof,
and account every socket against the ceilings. Nuclei was not executed
against the Internet (nor at all — no subprocess exists on this path).

---

## 9. CVE-2026-1557 template boundary

Verified against actual bytes, not comments:

- Hard scope: `HARD_SCOPE_CVE_ID = "CVE-2026-1557"` (`gates.py:27`);
  `lane.run` blocks `CVE_MISMATCH` before any other work; test asserts
  frozen digest `f5ba287d…0b1b8d` and 354-byte length
  (`test_live_validation.py:40-70`).
- Pinned content (`gates.py:34-55`): `GET
  /wp-content/plugins/wp-responsive-images/image_handler.php?src=/wp-config.php`,
  empty headers, matchers `status_code==200 || status_code==403` (dsl)
  + `word(DB_NAME, DB_PASSWORD)` on body. Single-exchange shape;
  fixtures benign(500)/vulnerable(403+DB markers) enforce specificity.
- Provenance: digest computed at import from canonical bytes
  (`content_hash_for_bytes`); authorization binds
  `artifact_id_for(...)` + content hash; executor revalidates exact
  bytes + identity + H1/H2 + 5F gate at steps 6–7. Caller cannot supply
  template path/bytes (no such parameter on `lane.run` or
  `execute_nuclei`'s trusted path — `artifact_bytes` is the pinned
  `candidate.canonical_bytes`, `lane.py:356`); LLM output cannot reach
  the template (lane never reads research artifacts; `research_cli`
  research and validate-live paths share no data channel).
- Multi-request behavior: none representable — typed content has no
  workflow/raw/fuzz/extractors/callback fields (`extra="forbid"` +
  5F `_DENIED_TEMPLATE_KEYS` deny them).

**Template-boundary verdict: PASS.** (Binary-level OOB concern in §8 is
about Nuclei-the-product, not this template.)

---

## 10. Evidence / redaction analysis

Path: `_observe_stream` (`nuclei_executor.py:1117-1133`) → `scrub_text`
→ capped sample persisted in `NucleiObservation.stdout_sample/
stderr_sample` → `EvidenceBuilder.seal` → `assemble_handoff/
bind_provenance` → verifier. Caps: `nuclei_output_bytes = 1 MiB` per
stream (over-cap → `SUBPROCESS_OUTPUT_LIMIT`, fail-closed); evidence
sample bytes 8 KiB / transport 512 KiB / decompressed 2 MiB ceilings
exist in 5H-core for the HTTP path.

**HIGH finding H1 — response-data redaction gap.** `_observe_stream`
applies only `scrub_text` (operational-secret URI/key/bearer/basic
patterns). Verified offline that it does **not** redact:

- `Set-Cookie: sessionid=abc123`, `Cookie: sess=xyz` (persist verbatim),
- `X-Api-Key: 12345`, `token=abcdef` query echoes,
- `DB_PASSWORD secret123` body echoes,
- internal hostnames (`Host: internal.corp.local`).

`scrub_headers` *would* redact `Cookie/Set-Cookie/Authorization/
proxy-*/*token*/*secret*/*session*/*auth*` — but it is never called on
this path because Nuclei stdout is free text/JSON, not a header dict.
Consequence: a validation against a real target can persist session
tokens, cookies, and internal hostnames in sealed evidence samples
(up to 1 MiB each). The lane sends no credentials itself (fixed GET,
empty headers — header *leakage of our secrets* is not the risk), but
*target-returned* sensitive response data is stored insufficiently
scrubbed. **Required fix:** extend observation scrubbing to response
samples (cookie/set-cookie/session/token patterns + internal-hostname
handling) or prove Nuclei `-json` output fields are individually
scrubbed before `EvidenceBuilder.attach_nuclei`; re-run the scrubber
matrix as a unit test.

Other evidence properties verified: `finding_like_text_present` is
observation-only (never a verdict); error details bounded 200 chars,
single-line, secret-screened (`ExecutorError`); `result_hash` 64-hex
only when verified; no `Authorization`/`Cookie` request headers exist
to leak (pinned template headers `{}`).

---

## 11. Resource / DoS analysis

Ceilings recorded (`ai/limits/ceilings.py`, reused by
`default_resource_limits`: wall 120 s, CPU 60 s, mem 512 MiB, fd 64,
proc 1, output 1 MiB/stream, scratch 16 MiB) but **enforcement lives in
the future B3 boundary** (`nuclei_executor.py:647-656` states "No
active enforcement lives here"). `FakeNucleiRunner` ignores all limits
(by design, offline). Under real egress the lane imposes: Nuclei
`-timeout 5`, `-bulk-size 1`, retries ceiling 0 — but no wall-time
kill, no memory/cgroup cap, no request counter, no output-truncation
beyond the post-hoc 1 MiB raise, no per-execution socket count wired
to `requests_per_execution = 7`.

Deterministic maximum for CVE-2026-1557: **1 intended request**
(single GET). Achievable maximum today if egress were enabled:
unbounded (redirect following × Nuclei-internal retries/follow-ups;
see B1/B3). Disk: evidence + audit in-memory only (no spill path on
this lane). CPU/mem: one subprocess at a time per lane run, but no
cgroup/rlimit applied by the lane.

**MEDIUM finding M2:** wire wall-time kill, rlimits/cgroup, request +
redirect counters, and output caps into the runner/sandbox before
egress; keep the single-request determinism claim for this CVE only
after redirects are disabled/budgeted.

---

## 12. LLM trust-boundary analysis

Proven air-gap (traced, not asserted):

1. `research_cli research/batch` (LLM path via `SecurityResearcher`)
   writes `ai_data/research/*.cli.json` with `authoritative=False`.
2. `validate-live` reads **only** `args.cve` + `args.target` + `args.live`
   (argparse, `research_cli.py:577-597, 600-610`). It never reads
   `ai_data/research/`, never takes template/path/executable/headers/
   artifact arguments, never imports the researcher.
3. Lane inputs are `(cve_id, target, mode)`; candidate/template come
   from code constants; executable/argv/env from frozen builders.
4. Executor type-gates reject dicts/JSON/LLM output as authority
   (`issue_authorization`/`get_issued_authorization`/
   `_NucleiExecutor.run` all `isinstance`-gate genuine records).
5. Issuer allowlist excludes `llm-researcher` (`execution_authorization.py:145`).

The LLM cannot choose target, executable, template path, command,
headers, redirect, or network destination on this path. **Verdict:
PASS.** Residual: model-generated research text may *suggest* a target
to a human operator who then types it — that is a human-factor channel,
correctly outside the code boundary (operator + env-gate + explicit
`--target` remain the authorization root; see MEDIUM M1).

---

## 13. Failure / fail-closed analysis

Traced per failure (all verified in code + covered by
`ai/test_live_validation.py` gate-block tests):

| Failure | Behavior | Fail-closed? |
|---|---|---|
| env missing/false + `--live` | `BLOCKED LIVE_VALIDATION_DISABLED` before anything | Yes |
| target missing/empty/non-string | `BLOCKED TARGET_REQUIRED` | Yes |
| malformed target | `BLOCKED TARGET_INVALID` | Yes |
| CVE mismatch | `BLOCKED CVE_MISMATCH` | Yes |
| template unsafe | `BLOCKED TEMPLATE_UNSAFE` (unreachable for pinned bytes; gate still runs) | Yes |
| issuance failure (e.g. `ftp` scheme, bad port) | `BLOCKED ISSUANCE_FAILED` | Yes |
| authz not found / not live | `BLOCKED AUTHZ_NOT_FOUND / AUTHZ_NOT_LIVE` | Yes |
| scope deny / policy-invalid / unsafe address | `BLOCKED SCOPE_DENIED / SCOPE_ERROR` | Yes |
| resolution failure | N/A (hand-built; cannot fail — itself an observation, §4) | — |
| executor error (incl. `NUCLEI_EXECUTION_BLOCKED` for live runners, unknown runner types) | `BLOCKED execution: <CODE>` | Yes |
| verifier reject / error | `MATCH_UNVERIFIED` with evidence retained (`_unverified`, `lane.py:420`) — no verdict emitted | Yes (no fall-through to VERIFIED) |
| evidence seal failure | `EXECUTION_FAILED/EVIDENCE_SEAL_FAILED`, ledger `mark_unknown` | Yes |
| timeout/killed/output-over-cap | `SUBPROCESS_TIMEOUT/KILLED/OUTPUT_LIMIT`, ledger unknown | Yes |
| unexpected exception in `execute_nuclei` | caught → `BLOCKED execution:` (lane.py:362-365) | Yes |

No path falls through to execution or to VERIFIED on failure. The
`MATCH_UNVERIFIED`-with-evidence state is the correct inconclusive
sink. **Verdict: PASS.**

---

## 14. Double-check of prior implementation claims

| Claim | Verification | Result |
|---|---|---|
| `WATCH_AI_LIVE_VALIDATION=false` by default | `os.environ.get(..., "")` + truthy-set; test `test_disabled_by_default` | **TRUE** |
| explicit `--live` required | `mode = "live" if args.live` + config gate; `test_live_without_env_gate_blocks`, `test_cli_live_flag_blocks_without_env` | **TRUE** |
| explicit `--target` required | Gate 2 `TARGET_REQUIRED`; `--target default None` | **TRUE** |
| hard-scoped CVE-2026-1557 | `HARD_SCOPE_CVE_ID`, `CVE_MISMATCH` block | **TRUE** |
| pinned template digest | frozen `f5ba287d…`, 354 bytes, `test_pinned_digest_is_frozen` | **TRUE** |
| existing 5B authorization | genuine `issue/get/consume` via `InMemoryAuthorizationStore` | **TRUE** |
| existing 5D scope | `ScopeEvaluator.evaluate` + `require_allowed` re-check in executor | **TRUE with caveat**: manual `TargetResolution`, no `TargetResolver`, no `evaluate_chain` |
| verdict-free result | schemas forbid verdict fields; `test_boundary_forbids_verdict_fields`; `finding_eligible=False` ceiling | **TRUE** |
| no 5J / no alerts | no imports of finding/alert writers on lane path | **TRUE** |
| LiveNucleiRunner currently blocked | `LIVE_NUCLEI=False` literal; both live runners raise unconditionally; `test_live_nuclei_runner_keeps_executor_block` | **TRUE** |

---

## 15. Findings with severity

**BLOCKER (must fix before real egress):**

- **B1 — Redirect scope bypass.** Authorized-target redirect to
  `127.0.0.1`/private host followed inside Nuclei with no
  re-authorization/re-scope/re-resolution. Files:
  `ai/live_validation/lane.py:501-536`, `ai/execution/nuclei_executor.py:736-767`.
- **B2 — DNS bypass + rebinding.** Hostname dial path ignores the
  `DialBinding` pin; resolution-time safety does not bind dial-time
  addresses; `dns_source` is a static string. Files:
  `ai/live_validation/lane.py:501-595`.
- **B3 — Unbounded Nuclei network behavior.** Missing OOB/redirect/
  update/pinning flags + no egress sandbox/dial-proof wiring. Files:
  `ai/execution/nuclei_executor.py:736-767` (argv),
  lane (no `ai/execution/b3_boundary.py` usage).

**HIGH (fix before real egress):**

- **H1 — Evidence redaction gap.** `scrub_text`-only observation
  persists cookies/session tokens/internal hostnames in
  `stdout_sample`/`stderr_sample` (1 MiB each). Files:
  `ai/execution/nuclei_executor.py:1117-1133`, `ai/evidence/scrubber.py`.
- **H2 — Lane bypasses shared canonicalizer.** `urlparse`-only parsing
  reaches issuance (`ftp://host:port` → `ISSUANCE_FAILED` instead of
  `TARGET_INVALID`); userinfo/trailing-dot/encoding handled
  incidentally downstream. Consolidate on `canonicalize_target` at
  Gate 2. File: `ai/live_validation/lane.py:104-130, 252-264`.
- **H3 — Unblocking is itself an unreviewed change.** `LIVE_NUCLEI`,
  both live runners, `HTTP_PROBE_PILOT_ENABLED`, `LIVE_TRAFFIC_ENABLED`
  are frozen `False`/raising; any "enable egress" diff must return
  through B3 review (this report's blockers are the acceptance
  criteria). No file to fix — process gate.

**MEDIUM:**

- **M1 — Caller-is-authority design.** Single-host explicit policy
  means CLI+env holders can validate any public host; no independent
  allowlist/approval record. Document the operator-trust assumption and
  add audit logging of (cve, target, operator) before egress.
- **M2 — Resource ceilings recorded, not enforced.** Wire wall/CPU/mem/
  request/redirect/output enforcement (B3 sandbox + runner) — §11.
- **M3 — Far-future authz expiry (`2030-12-31`) + frozen clock
  (`NOW_ISO`).** Fine offline; production needs short-lived authz and
  real clocks.

**LOW:**

- **L1 — Userinfo silently stripped** (`user:pass@host` authorized as
  `host`). Reject userinfo at Gate 2 instead of stripping.
- **L2 — `_deterministic_ex_id` uses `secrets.token_hex`** (fresh ID per
  run despite the name). Rename or document.
- **L3 — `_build_resolution` hardcodes `host_kind="dns"`,
  `resolved_at=NOW_ISO`.** Replace with canonical kind + real time
  when production wiring lands.

**INFORMATIONAL:**

- **I1 — `NucleiPipeline._validate_with_nuclei` (`subprocess.run(["nuclei",
  "-validate"…])`) is correctly NOT on the lane path** (research-only
  preparation). Keep it that way; any future lane reuse must re-audit.
- **I2 — Pre-existing unrelated test failure:**
  `ai.test_nuclei_cve_2026_1557_dryrun…test_template_content_is_safe_and_grounded`
  fails on the word "version" inside a research description string —
  untouched by this stage, noted for the owning track.

---

## 16. Required fixes (exact, no code changed in this stage)

1. **Redirects (B1):** pin redirect-disable/budget flags in
   `build_nuclei_argv` AND route every observed hop through
   `ScopeEvaluator.evaluate_chain` + fresh `TargetResolution` +
   `build_egress_policy`/`require_fresh_scope_for_redirect` before the
   next dial; add offline tests with hostile `Location` values
   (`http://127.0.0.1/`, metadata, cross-port, downgrade, loop, 6th hop).
2. **DNS/pinning (B2):** resolve once via the reviewed address source +
   `validate_answers`; construct the real `TargetResolution` through
   `TargetResolver` (or an audited equivalent that calls
   `canonicalize_target`); dial IP literals only (`LiveSocketFactory` +
   `verify_socket_peer`) with `check_egress_dial` /
   `assert_dial_matches_egress`; stamp the real `dns_source`; add
   rebinding tests (safe-at-validate → private-at-dial, TTL flip,
   IPv4-mapped IPv6, mixed safe/unsafe answer sets).
3. **Nuclei network bounds (B3):** extend the frozen argv with
   interactsh/OOB-disable, confirm `-disable-update-check` semantics
   for the pinned Nuclei version, pin retry/concurrency, and execute
   inside the B3 sandbox/egress policy with dial proof; account every
   socket against `requests_per_execution`/`redirect_hops`.
4. **Redaction (H1):** scrub response samples for cookie/set-cookie/
   session/token shapes + internal hostnames before
   `EvidenceBuilder.attach_nuclei`; add a scrubber-matrix unit test.
5. **Canonicalization (H2):** Gate 2 must call `canonicalize_target`
   (scheme/host/port) and reject userinfo explicitly; keep downstream
   re-checks as defense in depth.

---

## 17. Tests executed (all offline, zero network)

- `python3 -m unittest ai.test_live_validation` → **40 tests OK**.
- `python3 -m unittest ai.test_nuclei_executor ai.test_scope_evaluator
  ai.test_evidence_core ai.test_live_validation
  ai.test_nuclei_cve_2026_1557_dryrun` → 374 tests, 1 failure: the
  pre-existing unrelated `test_template_content_is_safe_and_grounded`
  ("version" substring in research prose), documented as I2.
- `ai.test_nuclei_executor ai.test_scope_evaluator ai.test_target_resolver`
  (correct local names where resolvable) included in the above; two
  guessed module names (`ai.test_authorization`, `ai.test_canonicalization`,
  `ai.test_dns`) do not exist as modules — related coverage comes from
  `ai.test_scope_evaluator` / `ai.test_nuclei_executor` / lane tests.
- Adversarial target matrix (§3 table, ~40 inputs incl. `127.0.0.1`,
  `localhost`, `0.0.0.0`, `[::1]`, private/link-local/metadata IPv4/IPv6,
  decimal/hex/octal/short dotted numerics, IPv4-mapped IPv6, userinfo,
  `ftp/file/gopher/data/javascript`, unusual/out-of-range ports,
  trailing-dot/case/percent forms) via temporary `python3 -c` (not
  persisted) against dry-run lane — results tabulated in §3.
- Scrubber matrix (`scrub_text` vs cookie/token/hostname samples) +
  argv/`shell=True`/subprocess-import scan — §7/§10 evidence.
- No test requiring network was run; Nuclei binary never invoked.

---

## 18. Confirmation of zero real network execution

No live HTTP/DNS/subprocess/browser/LLM/Mongo execution was performed
or triggered by this review. All dynamic evidence comes from offline
`unittest` suites (`FakeNucleiRunner`, `InMemory*` stores, injected
`dns_mapping`) and pure-local `python3 -c` parsing/classification.
`git status` shows no new process, socket, or egress artifacts from
this stage beyond this report file.

## 19. Confirmation of zero Git changes (production code)

No production file was modified, staged, committed, or pushed. No test
files were added. Pre-existing unrelated working-tree modifications
(e.g. `M AGENTS.md`, `M ai/config.py`, `M ai/research_cli.py` among
others shown by `git status --porcelain`) were left untouched. The only
new file is this report (required deliverable). `git diff --check`
reports only pre-existing whitespace notes in unrelated files.

## 20. Final verdict

**NO-GO.**

Real egress must not be enabled for the Controlled Live Validation lane
until blockers **B1 (redirect re-scope), B2 (DNS pinning/rebinding),
B3 (Nuclei network bounds)** and HIGH findings **H1 (evidence
redaction), H2 (shared canonicalizer at Gate 2)** are fixed and
re-reviewed, with the unblock diff itself (H3) passing B3 review. The
offline lane is correctly built and genuinely blocked today — the task
now is to close the dial-time gaps before that block is ever lifted.
