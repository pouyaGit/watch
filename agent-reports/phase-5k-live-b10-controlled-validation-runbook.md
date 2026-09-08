# Phase 5K-live B10 — Controlled Validation Runbook

## Scope

This runbook governs exactly **one** controlled validation execution against a single operator-owned target using a pinned Nuclei template for CVE-2026-1557.

**Approved scope:**
- ONE operator-owned controlled target
- IP-literal addressing (no DNS resolution)
- Single approved TCP port
- No credentials, secrets, or sensitive data
- No shared infrastructure
- Pinned Nuclei template only (CVE-2026-1557)
- Pinned nuclei v3.11.1 binary
- Default-deny namespace execution
- Typed authorization with expiry
- Scrubbed evidence collection only

**Current state:** LIVE EGRESS = DISABLED (must remain DISABLED until final operator action)

---

## Preconditions

The following must be **true before any activation consideration**:

| Precondition | Required State | Verification |
|--------------|----------------|--------------|
| B8 Runtime Boundary | PROVEN | `RUNTIME_BOUNDARY_PROVEN` |
| B9 Go Decision | GO_FOR_CONTROLLED_VALIDATION | Explicit operator approval |
| Live egress | DISABLED | `WATCH_AI_LIVE_VALIDATION=false`, `LIVE_LAUNCH_ENABLED=false` |
| Target ownership | Operator-controlled | Documented proof (see Target Checklist) |
| Template integrity | Verified digest | SHA-256 match for CVE-2026-1557 template |
| Authorization | Issued and valid | Active typed authorization with scope hash |
| Environment | Clean | No proxy vars, correct nuclei version, namespace capable |

---

## Target Checklist

### Target Requirements

| Requirement | Specification | Verification Method |
|-------------|---------------|---------------------|
| **Ownership/Control Proof** | Operator owns/controls the target infrastructure | Signed attestation + infrastructure inventory match |
| **IP Literal** | Target specified as IP address (no hostname) | `TARGET_IP=<ipv4-or-ipv6-literal>` |
| **Approved Port** | Single TCP port pre-approved in authorization | `APPROVED_PORT=<port>` |
| **Expected Service** | Known service listening on approved port | Service banner/version verification |
| **No Redirects** | Service does not redirect to unknown hosts | Static analysis + `curl -I` verification |
| **No Credentials** | No authentication required for validation path | Anonymous access confirmation |
| **No Sensitive Data** | Target contains no PII, secrets, or production data | Data classification review |
| **No Shared Infrastructure** | Target isolated from production/shared systems | Network topology verification |

### Operator Verification Commands

```bash
# 1. Socket/TCP verification - confirm listening port
ss -ltnp | grep -E "LISTEN.*:${APPROVED_PORT}"

# 2. Service identity verification - confirm expected service
curl -s -m 5 "http://${TARGET_IP}:${APPROVED_PORT}/" | head -20
# or for non-HTTP:
nc -vz "${TARGET_IP}" "${APPROVED_PORT}"

# 3. Port confirmation - verify only approved port is reachable
nmap -p "${APPROVED_PORT}" -Pn "${TARGET_IP}"

# 4. Redirect check - verify no external redirects
curl -s -I -L -m 10 "http://${TARGET_IP}:${APPROVED_PORT}/" 2>&1 | grep -i location

# 5. Credential check - verify anonymous access
curl -s -o /dev/null -w "%{http_code}" "http://${TARGET_IP}:${APPROVED_PORT}/"

# 6. Infrastructure isolation check
ip route get "${TARGET_IP}"
```

**All commands must pass before proceeding. Any failure = BLOCKED.**

---

## Template Checklist

### Template Location

```
/srv/watch/scratch/nuclei/CVE-2026-1557.yaml
```

### Required Digest Verification

```bash
# Expected SHA-256 (to be populated at template freeze time)
EXPECTED_TEMPLATE_SHA256="<sha256-to-be-recorded-at-freeze>"
ACTUAL_TEMPLATE_SHA256=$(sha256sum /srv/watch/scratch/nuclei/CVE-2026-1557.yaml | cut -d' ' -f1)

# Verification
[[ "${ACTUAL_TEMPLATE_SHA256}" == "${EXPECTED_TEMPLATE_SHA256}" ]] || { echo "DIGEST MISMATCH"; exit 1; }
```

### Template Identity

- **CVE ID:** CVE-2026-1557
- **Template name:** `CVE-2026-1557.yaml`
- **Author:** Watch project (pinned, not community)
- **Severity:** As defined in template metadata
- **Protocol:** As defined in template (TCP/HTTP/etc.)

### Pinned Template Hash Requirement

The template **must** match the frozen digest recorded at authorization time. Any deviation = immediate rejection.

### Rejection Conditions

| Condition | Action |
|-----------|--------|
| Modified template (mtime changed) | REJECT |
| Unexpected path (not `/srv/watch/scratch/nuclei/`) | REJECT |
| Digest mismatch | REJECT |
| Template references interactsh/oast | REJECT |
| Template contains workflows/multiple requests | REJECT |
| Template version drift | REJECT |

**Do NOT create the template. Do NOT execute it. This is preparation only.**

---

## Authorization Checklist

### Exact Activation Sequence

```
REQUEST
  │
  ▼
AUTHORIZE  ──► Typed authorization issued (scope, target, expiry, template hash)
  │
  ▼
STORE      ──► Authorization persisted to audit store
  │
  ▼
VERIFY ISSUED STATE  ──► Confirm authorization_id, execution_id, resolution_id, expiry, scope hash, target hash, pinned address
  │
  ▼
RESOLVE TARGET  ──► IP literal confirmed (no DNS)
  │
  ▼
CANONICALIZE  ──► Target + template + authorization bound into execution context
  │
  ▼
BUILD EGRESS POLICY  ──► Default-deny namespace + single egress rule for TARGET_IP:APPROVED_PORT
  │
  ▼
EXECUTE    ──► Operator triggers with WATCH_AI_LIVE_VALIDATION=true + LIVE_LAUNCH_ENABLED=true
```

### Required Checks at VERIFY ISSUED STATE

| Field | Required | Validation |
|-------|----------|------------|
| `authorization_id` | YES | UUID v4, matches request |
| `execution_id` | YES | UUID v4, unique per run |
| `resolution_id` | YES | UUID v4, binds target resolution |
| `expiry` | YES | RFC3339, future, ≤ 4 hours from issuance |
| `scope_hash` | YES | SHA-256 of approved scope (target IP + port + template) |
| `target_hash` | YES | SHA-256 of canonical target identity (IP + port) |
| `pinned_address` | YES | Exact IP literal from authorization |

**All fields must be present and valid. Any mismatch = BLOCKED.**

---

## Environment Checklist

### Activation Checklist (Verify Before Final Go)

| Check | Expected State | Command |
|-------|----------------|---------|
| `LIVE_NUCLEI` | NOT SET / empty | `env \| grep LIVE_NUCLEI` |
| `LIVE_LAUNCH_ENABLED` | `false` or unset | `echo ${LIVE_LAUNCH_ENABLED:-false}` |
| `WATCH_AI_LIVE_VALIDATION` | `false` or unset | `echo ${WATCH_AI_LIVE_VALIDATION:-false}` |
| Proxy variables | NONE SET | `env \| grep -i proxy` |
| Nuclei version | `v3.11.1` | `nuclei -version` |
| Nuclei binary path | Known, pinned path | `which nuclei` / `sha256sum $(which nuclei)` |
| Scratch template dir | `/srv/watch/scratch/nuclei/` | `ls -la /srv/watch/scratch/nuclei/` |
| Namespace capability | Available (unshare/clone) | `unshare --help \| head -1` |
| Default-deny netns | Configurable | `ip netns list` |

### Expected State Before Activation

```
LIVE_NUCLEI=                          # empty/unset
LIVE_LAUNCH_ENABLED=false
WATCH_AI_LIVE_VALIDATION=false
http_proxy=                           # unset
https_proxy=                          # unset
all_proxy=                            # unset
no_proxy=                             # unset
```

**All live switches remain OFF until final explicit operator action.**

---

## Execution Plan

### Exact Intended Execution

| Parameter | Value |
|-----------|-------|
| Targets | 1 (single IP literal) |
| Templates | 1 (CVE-2026-1557.yaml only) |
| Runs | 1 (single execution, no retries) |
| Concurrency | 1 (serial only) |
| Operator | Present and monitoring |
| Namespace | Default-deny, single egress rule |
| Template updates | DISABLED |
| Interactsh/OAST | DISABLED |
| Redirects | NOT followed |
| Workflows | NOT used |

### Execution Command Template (NOT TO BE RUN)

```bash
# This documents the exact command structure. DO NOT EXECUTE.
# Final execution requires WATCH_AI_LIVE_VALIDATION=true LIVE_LAUNCH_ENABLED=true

WATCH_AI_LIVE_VALIDATION=true \
LIVE_LAUNCH_ENABLED=true \
nuclei \
  -target "${TARGET_IP}:${APPROVED_PORT}" \
  -t /srv/watch/scratch/nuclei/CVE-2026-1557.yaml \
  -version \
  -no-interactsh \
  -no-meta \
  -silent \
  -json \
  -o /srv/watch/scratch/evidence/CVE-2026-1557-execution-$(date -u +%Y%m%dT%H%M%SZ).json \
  2>&1 | tee /srv/watch/scratch/evidence/CVE-2026-1557-stdout-$(date -u +%Y%m%dT%H%M%SZ).log
```

### Expected Evidence Artifacts

| Artifact | Path Pattern | Description |
|----------|--------------|-------------|
| Nuclei JSON output | `/srv/watch/scratch/evidence/CVE-2026-1557-execution-<timestamp>.json` | Structured findings |
| Stdout/stderr log | `/srv/watch/scratch/evidence/CVE-2026-1557-stdout-<timestamp>.log` | Full execution log |
| Exit status | Captured in wrapper script | Process exit code |
| Argv digest | SHA-256 of executed command line | Reproducibility |
| Template digest | SHA-256 of template at execution time | Integrity proof |

---

## Failure Conditions

### No-Run Conditions (Must Fail Closed)

| Condition | Detection Point | Action |
|-----------|-----------------|--------|
| Target IP mismatch (not matching authorization) | PRE-EXEC | ABORT |
| Authorization expired (expiry < now) | PRE-EXEC | ABORT |
| Scope drift (scope_hash ≠ expected) | PRE-EXEC | ABORT |
| DNS resolution attempted (target not IP literal) | PRE-EXEC | ABORT |
| Template digest mismatch | PRE-EXEC | ABORT |
| Firewall/namespace verification failure | PRE-EXEC | ABORT |
| Sandbox/namespace creation failure | PRE-EXEC | ABORT |
| Evidence directory not writable | PRE-EXEC | ABORT |
| Unexpected Nuclei output (non-JSON, errors) | DURING/POST | ABORT + INVESTIGATE |
| Multiple findings where zero/one expected | POST | QUARANTINE + REVIEW |
| Template executed against wrong target | POST | INVESTIGATE |
| Network egress beyond approved target:port | DURING | ABORT + ALERT |

**All failure conditions result in immediate termination and investigation. No partial execution.**

---

## Evidence Review Plan

### Post-Run Review Checklist

| Review Item | Method | Pass Criteria |
|-------------|--------|---------------|
| Evidence hash | `sha256sum` on all artifacts | Matches recorded manifest |
| Scrubbed output | Manual review | No secrets, IPs beyond target, credentials |
| Stdout/stderr samples | Head/tail review | Expected Nuclei output only |
| Exit status | `$?` capture | 0 (success) or expected non-zero |
| Argv digest | Compare to pre-exec record | Exact match |
| Template digest | Compare to authorization record | Exact match |
| Target identity | Verify in output matches authorization | IP:port exact match |

### Confirmation Policy

- **NO automatic vulnerability confirmation**
- All findings marked `model_generated` or `requires_verification`
- Human analyst review required before any classification
- Evidence preserved for audit trail

---

## Rollback Plan

### Activation Switches (Who Enables)

| Switch | Enabled By | Method |
|--------|------------|--------|
| `WATCH_AI_LIVE_VALIDATION` | Lead Operator | `export WATCH_AI_LIVE_VALIDATION=true` |
| `LIVE_LAUNCH_ENABLED` | Lead Operator | `export LIVE_LAUNCH_ENABLED=true` |

**Both must be enabled simultaneously by the same operator in the same shell session.**

### Rollback Procedure

```bash
# IMMEDIATE ROLLBACK (at any point):
unset WATCH_AI_LIVE_VALIDATION
unset LIVE_LAUNCH_ENABLED

# Verify rollback:
echo "LIVE_VALIDATION=${WATCH_AI_LIVE_VALIDATION:-unset}"
echo "LIVE_LAUNCH=${LIVE_LAUNCH_ENABLED:-unset}"

# If execution started, terminate:
pkill -f "nuclei.*CVE-2026-1557"

# Verify namespace teardown:
ip netns delete validation-ns-<execution_id> 2>/dev/null || true

# Preserve evidence for review:
chmod 444 /srv/watch/scratch/evidence/CVE-2026-1557-*
```

**Rollback is always available and must complete within 30 seconds.**

---

## Final Status

### Readiness Assessment

| Checklist | Status | Notes |
|-----------|--------|-------|
| Deterministic Target Checklist | ☐ COMPLETE / ☐ INCOMPLETE | All 8 requirements verified |
| Template Checklist | ☐ COMPLETE / ☐ INCOMPLETE | Digest frozen, rejection conditions documented |
| Authorization Checklist | ☐ COMPLETE / ☐ INCOMPLETE | All 7 fields verified, sequence documented |
| Environment Checklist | ☐ COMPLETE / ☐ INCOMPLETE | All 9 checks passing, switches OFF |
| Evidence Checklist | ☐ COMPLETE / ☐ INCOMPLETE | Artifact paths defined, review process documented |

### Final Status

**BLOCKED**

### Rationale

This runbook is **preparation only**. The final status remains **BLOCKED** until:

1. All five checklists are marked COMPLETE by the operator
2. Template digest is frozen and recorded
3. Authorization is issued with all 7 required fields
4. Operator explicitly confirms all preconditions met
5. **Explicit go-decision** recorded for this specific execution

### Live Egress State

**DISABLED** — Must remain DISABLED until final operator action enables both switches simultaneously.

---

**Report generated:** `agent-reports/phase-5k-live-b10-controlled-validation-runbook.md`

**This document authorizes preparation only. It does NOT authorize execution.**