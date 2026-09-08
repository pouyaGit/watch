# Phase B10.3 — Controlled Validation Activation Preflight

**Date:** 2026-09-08
**Host:** Google VM hosting `/opt/watch`
**Scope:** Deterministic preflight ONLY for the single controlled CVE-2026-1557
validation. No Nuclei scan, no `lane.run(mode="live")`, no live switches, no
external target contact, no DNS/network reconnaissance, no live authorization,
no application-code modification, no git pull/push/commit/reset/stash/checkout.
All pre-existing working-tree changes preserved.

Prior reports followed exactly: B10.1 preflight, B10.2 production-Mongo
verification, B8/B9 security reviews, plus `ai/live_validation/`,
`ai/execution/`, `ai/persistence/mongo_authz.py`, `nuclei_launcher.py`,
`netns_sandbox.py` as implemented.

## 1. Environment

- Host: Google VM, repo `/opt/watch`, reviewer shell euid 1001 (non-root).
- MongoDB: localhost `watch` database reachable (B10.2-proven; reconfirmed §5).
- `unshare` / `ip` / `nft` / `iptables` present (§6).
- No `TARGET_IP` / `APPROVED_PORT` / target env vars set; no target configured
  in non-test application code.

## 2. Target status — BLOCKED

- Target seam inspected: `lane._parse_raw_target` + `canonicalize_target`
  parse IP literals offline with zero DNS (`https://192.0.2.1:8443` →
  `('https', '192.0.2.1', 8443)`, kind `ipv4`); hostname targets would resolve
  only through the reviewed resolver + `validate_answers` + B3 egress guard.
- No operator-controlled dedicated IP-literal target exists anywhere in
  configuration: env scan empty, code scan (non-test) empty.
- Approved TCP port: none. Ownership/control evidence: none. Credentials /
  secrets required: none (nothing to require them for).
- No target invented or selected. **BLOCKED.**

## 3. Template status — BLOCKED

- Pinned in code (`ai/live_validation/gates.py`): digest
  `f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d`
  (354 bytes) — matches the B10.1/B10.2 recorded value exactly.
- `/srv/watch/scratch/nuclei/CVE-2026-1557.yaml`: **ABSENT**
  (`sha256sum: No such file or directory`; directory holds only a stale
  `ex-cc…` subdirectory). No digest comparison possible. **BLOCKED.**
- Template NOT created, modified, or executed in this phase.
- Confinement verified in-process: `build_nuclei_argv` rejects `/tmp/evil.yaml`,
  `/srv/watch/other/t.yaml`, `/etc/passwd` with `TARGET_EXPANSION_DENIED` —
  only `/srv/watch/scratch/nuclei/` is admissible, re-asserted by the launcher.
- Authorization binding verified by inspection: artifact `content_hash` is
  bound at issuance (`ArtifactBinding`), re-checked at execution
  (`_revalidate_artifact`: hash + plan-bound identity + safety re-run), and
  sealed into evidence (`template_hash`); any drift aborts before launch.

## 4. Nuclei binary + launcher/argv — READY

- `/usr/bin/nuclei → /usr/local/bin/nuclei` exists.
- Version (offline probe `nuclei -disable-update-check -version`, no scan):
  **v3.11.1** — matches `PINNED_NUCLEI_VERSION`.
- SHA-256: `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251`
  — **byte-identical to the B10.1/B8 recorded value**.
- Frozen argv contract verified end-to-end in-process for the exact intended
  shape (`-t /srv/watch/scratch/nuclei/CVE-2026-1557.yaml -u
  https://192.0.2.1:8443 …`): server-controlled binary first token ✓,
  `assert_frozen_argv_supported` ✓, `assert_single_target_argv` ✓, every flag
  in `SUPPORTED_NUCLEI_FLAGS` ✓, argv digest
  `52dd317f…a8ea5244` ✓.
- Disabled as required: `-disable-update-check` ✓, `-no-interactsh` ✓ (and
  `-disable-interactsh` absent), `-disable-redirects` ✓, `-retries 0` ✓,
  `-concurrency 1` / `-bulk-size 1` ✓, `-restrict-local-network-access` ✓,
  `-jsonl` ✓. No scan executed.

## 5. Authorization readiness — READY (store) / BLOCKED (issuance)

- Production factory `production_authz_store()` constructed OK (ping passed);
  collection `execution_authorizations`, **0 documents** (no live
  authorization exists — required pre-activation state); indexes present
  (`_id_`, `idempotency_key_1` unique, `lifecycle_1`, `expires_at_epoch_1`,
  `execution_class_1`). Read-only checks; **nothing issued**.
- Schema confirmed: `authorization_id` matches `authz-[0-9a-f]{16}`;
  `execution_class ∈ {http_probe, nuclei_scan, http_verification,
  browser_verification}`; `max_executions` literally `1`; canonical
  `TargetBinding`, plan-bound `ArtifactBinding` (template digest binding),
  `expires_at`, lifecycle set present.
- Single-use semantics: version-guarded CAS + atomic `consume_single_use`
  (B10.2-proven against real Mongo, incl. 6-thread exactly-once).
- Expiry ≤ 4h is a runbook/operator rule (service enforces `expires_at >
  issued_at`; the 4h bound must be verified at issuance time).
- Operator must still supply, via `issue_authorization` + `AuthorizationRequest`
  (`issuer_identity="human-review-board"`, `caller_scope="manual"`):
  (a) dedicated IP-literal target + approved port + scope hash,
  (b) pinned template digest `f5ba287d…b8d` as artifact identity,
  (c) `execution_class="nuclei_scan"`, (d) expiry ≤ 4h from issuance.
  No live authorization exists; none was created here.

## 6. Sandbox/egress readiness — READY (mechanism) / OPERATOR-CONTEXT REQUIRED

- Tooling: `unshare`, `ip`, `nft`, `iptables` all present.
- Read-only capability probe (`probe_netns_capabilities`, local only, no
  namespace created, no packets): `unshare_ok=False` (no CAP_SYS_ADMIN in
  this euid-1001 shell), `ip/netfilter=True` → `can_create_netns=False`.
  This is the DESIGNED fail-closed outcome, not a code bug: B9 documents the
  controlled run executes with root/caps on this disposable VM. **Activation
  must run in a privileged operator context; the sandbox gate
  (`require_production_sandbox`) will otherwise refuse.**
- Mechanism verified by inspection: default-deny OUTPUT+INPUT policy, exact
  `(ip, port, tcp)` allowlist tuples derived from the reviewed `EgressPolicy`
  (no ranges/CIDR/wildcards), explicit metadata/DNS/UDP drops, INPUT limited
  to ESTABLISHED TCP return path, `check_nft_ruleset`/`check_iptables_state`
  reject any NAT (`type nat` fails verification), no host-network fallback
  exists in code. No packets sent to any target.

## 7. Live-switch state — DISABLED (asserted)

- `LIVE_NUCLEI == False`, `LIVE_LAUNCH_ENABLED == False`
  (frozen constants, asserted in-process).
- `WATCH_AI_LIVE_VALIDATION` unset (asserted non-truthy).
- No Nuclei process running (`pgrep`: none).

## 8. Exact tests/checks run

- Env/config grep (target vars, hardcoded targets): none found.
- In-process offline checks: IP-literal parse ×2, canonicalization kind,
  pinned digest/length, 3× confinement rejections, full argv-chain build
  (builder → frozen-contract → single-target → flag/digest audit).
- Host probes: `ls/sha256sum` (template, absent), nuclei binary hash +
  offline `-disable-update-check -version`, tooling presence, euid/caps,
  read-only `probe_netns_capabilities`, pgrep.
- Read-only production Mongo: factory construction (ping), doc count (0),
  index listing.
- Unit suites: `ai.test_mongo_authorization_store +
  ai.test_execution_authorization + ai.test_stage2_production_reads +
  ai.test_live_validation` → **220 tests, 0 failures, 0 errors (OK)**.
- `git diff --check`: clean. No application code modified (no preflight bug
  found — the non-root capability refusal is specified fail-closed behavior).

## 9. Remaining operator prerequisites (explicit)

1. Designate + evidence the dedicated IP-literal target (ownership proof,
   single approved TCP port, expected service, no redirects/credentials/
   sensitive data/shared infra).
2. Materialize `/srv/watch/scratch/nuclei/CVE-2026-1557.yaml` with content
   hashing to `f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d`
   (verify before proceeding).
3. Issue the fresh single-use `nuclei_scan` authorization (§5 a–d) with
   expiry ≤ 4h; confirm it reads back ISSUED and unexpired.
4. Run activation from a privileged context (root / CAP_SYS_ADMIN +
   CAP_NET_ADMIN) so the default-deny namespace can be provisioned and
   VERIFY passes; otherwise the sandbox gate refuses.
5. Record the explicit go-decision for this single execution, then enable
   BOTH `WATCH_AI_LIVE_VALIDATION=true` and the launch switch together under
   supervision (rollback: unset both, `pkill -f "nuclei.*CVE-2026-1557"`,
   `ip netns delete`, evidence `chmod 444`).

## 10. Final classification

**BLOCKED**

Rationale: technical mechanisms are READY (binary pin + hash, frozen argv,
store + indexes + atomic consume all re-verified; switches DISABLED), but
three activation preconditions are unmet: no operator target, no template
file, no live authorization. A READY result requires every prerequisite
satisfied. This report authorizes nothing — not even a READY state would
authorize execution.

---
Report generated:
`agent-reports/phase-5k-live-b10.3-activation-preflight.md`
