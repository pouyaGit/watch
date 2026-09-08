# Phase 5K-live B10.1 — Controlled Validation Activation Preflight

**Date:** 2026-09-08
**Scope:** Preflight checks only — NO live egress, NO Nuclei execution, NO external targets, NO authorization issuance

---

## 1. TARGET

| Check | Status | Evidence |
|-------|--------|----------|
| Operator-controlled dedicated IP-literal target available? | **BLOCKED** | No target IP has been designated or verified. The runbook requires a dedicated operator-owned IP with signed attestation + infrastructure inventory match. |
| Approved TCP port known? | **BLOCKED** | No port has been pre-approved in authorization. |
| Ownership/control evidence recorded? | **BLOCKED** | No attestation or inventory match exists. |
| DNS resolution NOT required (IP literal)? | **NOT_APPLICABLE** | No target to verify. |

**Classification: BLOCKED**

---

## 2. TEMPLATE

| Check | Status | Evidence |
|-------|--------|----------|
| `/srv/watch/scratch/nuclei/` exists? | **READY** | Directory exists (owned by root, drwx------). |
| `CVE-2026-1557.yaml` present? | **BLOCKED** | File does NOT exist. Directory contains only an empty `ex-cccccccccccccccccccccccccccccccc/` subdirectory. |
| Approved pinned template? | **READY (code)** | Template is pinned in code at `ai/live_validation/gates.py:PINNED_TEMPLATE` with frozen content. |
| Expected digest (project)? | **READY** | `f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d` (354 bytes, SHA-256). |
| Template matches expected digest? | **BLOCKED** | Template file absent — cannot verify. |

**Classification: BLOCKED**

---

## 3. AUTHORIZATION

| Check | Status | Evidence |
|-------|--------|----------|
| Authorization interface exists? | **READY** | `ai/authorizer/service.py:issue_authorization()` accepts `AuthorizationRequest` → returns `IssuedExecutionAuthorization`. |
| Store implementation available? | **READY (test)** | `InMemoryAuthorizationStore` implements the `AuthorizationStore` protocol (single-process CAS). Production Mongo adapter NOT implemented (requires 5H-core). |
| Exact command/code path for `nuclei_scan` authorization? | **READY** | Code path: `issue_authorization(store, AuthorizationRequest(...))` with `execution_class="nuclei_scan"`, `caller_scope="manual"`, `issuer_identity="human-review-board"`, pinned template digest, IP-literal target, expiry ≤4h. |
| Single-use CAS consume verified? | **READY** | `consume_authorization()` performs atomic ISSUED→CONSUMED CAS with version conflict guard. |
| All 7 required fields verifiable? | **READY (schema)** | `authorization_id` (authz-*), `execution_id` (ex-*), `resolution_id`, `expiry` (RFC3339), `scope_hash`, `target_hash`, `pinned_address` — all enforced by schema. |

**Classification: READY** (code path exists; production store adapter pending 5H)

---

## 4. ENVIRONMENT

| Check | Status | Evidence |
|-------|--------|----------|
| `/usr/bin/nuclei` exists? | **READY** | Symlink: `/usr/bin/nuclei → /usr/local/bin/nuclei` (executable). |
| Nuclei version `v3.11.1`? | **READY** | `nuclei -version` → `Nuclei Engine Version: v3.11.1`. |
| Nuclei binary SHA-256? | **READY** | `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251` |
| Proxy environment clean? | **READY** | No `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` set in shell or `watch-api.service` (verified via `/proc/<pid>/environ`). |
| Namespace capability works? | **READY** | `unshare -n true` → exit code 0; `ip`, `nft`, `iptables` present. |
| `LIVE_NUCLEI` switch OFF? | **READY** | `ai/execution/nuclei_executor.py:130` — `LIVE_NUCLEI = False` (frozen constant). |
| `LIVE_LAUNCH_ENABLED` switch OFF? | **READY** | `ai/execution/nuclei_launcher.py:85` — `LIVE_LAUNCH_ENABLED = False` (frozen constant). |
| `WATCH_AI_LIVE_VALIDATION` unset? | **READY** | Not set in shell or service environment. |
| Production API cannot reach live execution? | **READY** | FastAPI routers (`backend/routers/*`) have zero references to live_validation, launcher, sandbox, or gates. |

**Classification: READY**

---

## 5. EXECUTION WIRING

| Check | Status | Evidence |
|-------|--------|----------|
| Raw `nuclei ...` CLI invocation prevented? | **READY** | Launcher enforces: `shell=False` only, frozen argv from `build_nuclei_argv()`, template path confined to `/srv/watch/scratch/nuclei/`, single `-u`/`-t`, pinned flags only. |
| Production-safe call path identified? | **READY** | Entry point: `ControlledLiveValidationLane.run(cve_id, target, mode="live")` with injected: reviewed resolver (`ProductionAddressSource`), production runner (wraps `run_nuclei_in_sandbox`), `InMemoryAuthorizationStore` (or production adapter), explicit policy store. |
| Gate chain enforced? | **READY** | 1. `require_live_validation_enabled()` (env gate) → 2. Target canonicalization → 3. CVE identity (CVE-2026-1557 only) → 4. Template safety+specificity → 5. `issue_authorization` + `get_issued_authorization` → 6. `ScopeEvaluator` + policy (allow explicit target only) → 7. B3 egress boundary (`check_destination_allowed` per address) → 8. `execute_nuclei` via injected runner → 9. `verify_handoff` (5I). |
| Authorization → scope → egress → sandbox → frozen argv → execution all enforced? | **READY** | Each gate fails closed; `launch_nuclei_bounded` re-asserts clean env, binary presence, pinned version, frozen argv digest, production sandbox capability, master switch. Sandbox entry (`run_nuclei_in_sandbox`) re-derives rules from policy and verifies before EXECUTE. |

**Classification: READY**

---

## 6. EVIDENCE

| Check | Status | Evidence |
|-------|--------|----------|
| Evidence destination `/srv/watch/scratch/evidence/` available? | **READY** | Directory created (root:root, drwxr-xr-x). |
| Expected artifact paths defined? | **READY** | Runbook specifies: `CVE-2026-1557-execution-<timestamp>.json`, `CVE-2026-1557-stdout-<timestamp>.log`, exit status, argv digest, template digest. |
| Scrubber + hashing pipeline verified? | **READY** | `ai/evidence/scrubber.py` + `ai/evidence/hashing.py` + `EvidenceBuilder` — all outputs scrubbed, capped (8 KiB samples / 1 MiB streams), hashes cover scrubbed content only. |

**Classification: READY**

---

## 7. ROLLBACK

| Check | Status | Evidence |
|-------|--------|----------|
| Documented rollback mechanism exists? | **READY** | Runbook §Rollback Plan: `unset WATCH_AI_LIVE_VALIDATION && unset LIVE_LAUNCH_ENABLED` (immediate), `pkill -f "nuclei.*CVE-2026-1557"` (if started), `ip netns delete validation-ns-<execution_id>`, `chmod 444 /srv/watch/scratch/evidence/CVE-2026-1557-*`. |
| Rollback completes within 30s? | **READY** | Commands are synchronous shell operations; namespace teardown is sub-second on this host. |
| Rollback preserves evidence? | **READY** | `chmod 444` makes artifacts read-only for review. |

**Classification: READY**

---

## Missing Preconditions

1. **TARGET**: No operator-controlled dedicated IP-literal target designated. Requires: signed attestation, infrastructure inventory match, single approved TCP port, service banner verification, no redirects, no credentials, no sensitive data, no shared infrastructure.
2. **TEMPLATE**: `CVE-2026-1557.yaml` must be materialized at `/srv/watch/scratch/nuclei/CVE-2026-1557.yaml` with content matching pinned digest `f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d`.
3. **AUTHORIZATION**: Fresh `nuclei_scan` authorization must be issued via `issue_authorization()` with all 7 required fields, in `ISSUED` state, unexpired, bound to the target IP+port and template digest.
4. **PRODUCTION STORE**: `InMemoryAuthorizationStore` is single-process only; cross-process deduplication requires production Mongo adapter (5H-core, not yet implemented).

---

## Exact Next Actions

```bash
# 1. Materialize pinned template (as root)
sudo tee /srv/watch/scratch/nuclei/CVE-2026-1557.yaml >/dev/null <<'YAML'
{"template_id":"CVE-2026-1557","method":"GET","path":"/wp-content/plugins/wp-responsive-images/image_handler.php","headers":{},"query_params":{"src":"/wp-config.php"},"body":null,"matchers":[{"matcher_type":"dsl","part":"status","values":["status_code==200 || status_code==403"]},{"matcher_type":"word","part":"body","values":["DB_NAME","DB_PASSWORD"]}]}
YAML

# 2. Verify template digest
sudo sha256sum /srv/watch/scratch/nuclei/CVE-2026-1557.yaml
# Must equal: f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d

# 3. Designate operator-controlled target (REQUIRES OPERATOR ACTION)
#    - Provide IP literal (e.g., TARGET_IP=203.0.113.42)
#    - Provide approved port (e.g., APPROVED_PORT=8443)
#    - Record signed attestation + infrastructure inventory match
#    - Verify: ss -ltnp | grep LISTEN.*:8443, curl -I http://IP:8443/, nmap -p 8443 -Pn IP

# 4. Issue fresh nuclei_scan authorization (REQUIRES OPERATOR ACTION)
#    python3 -c "
#    from ai.authorizer.service import issue_authorization
#    from ai.authorizer.store import InMemoryAuthorizationStore
#    from ai.schemas.execution_authorization import AuthorizationRequest, ArtifactBinding, TargetBinding
#    from ai.schemas.artifact import artifact_id_for
#    store = InMemoryAuthorizationStore()
#    request = AuthorizationRequest(
#        test_plan_id='tp-<16hex>',
#        artifact=ArtifactBinding(artifact_id=artifact_id_for('nuclei_template', 'tp-<16hex>', '<digest>'), ...),
#        target=TargetBinding(program_name='explicit:<IP>', host='<IP>', scheme='https', effective_port=<PORT>, scope_lists_hash='<hash>'),
#        execution_class='nuclei_scan',
#        plan_method='GET', artifact_method='GET',
#        expires_at='2026-09-08T16:00:00+00:00',  # ≤4h from now
#        caller_scope='manual',
#        issuer_identity='human-review-board',
#    )
#    authz = issue_authorization(store, request)
#    print('authorization_id:', authz.authorization_id)
#    "

# 5. Verify all preconditions, then operator enables both switches simultaneously:
#    export WATCH_AI_LIVE_VALIDATION=true
#    export LIVE_LAUNCH_ENABLED=true
#    python -m ai.research_cli validate-live --cve CVE-2026-1557 --target https://<IP>:<PORT> --live
```

---

## Live Egress

**DISABLED** (verified)

- `LIVE_NUCLEI = False` (frozen constant in `nuclei_executor.py:130`)
- `LIVE_LAUNCH_ENABLED = False` (frozen constant in `nuclei_launcher.py:85`)
- `WATCH_AI_LIVE_VALIDATION` unset in shell and `watch-api.service` environment
- No proxy/PAC/CA-shaping variables present
- No service/API route reaches launcher, sandbox, or executor live paths
- No approved template exists at `/srv/watch/scratch/nuclei/CVE-2026-1557.yaml` (absent)

---

## Final Status

**BLOCKED**

### Rationale

The preflight identifies **4 missing preconditions** (Target, Template file, Authorization issuance, Production store adapter) that must be satisfied before the controlled validation can proceed. The environment, wiring, evidence, and rollback are READY. The code path enforces all required gates (authorization → scope → egress policy → sandbox → frozen argv → execution) and will fail closed if any precondition is unmet.

Per B10 runbook: final status remains **BLOCKED** until all five checklists are COMPLETE, template digest is frozen and recorded, authorization is issued with all 7 fields, operator confirms all preconditions, and explicit go-decision is recorded.

---

Report generated: `agent-reports/phase-5k-live-b10.1-activation-preflight.md`