# Phase B10-LAB.1 — Isolated CVE-2026-1557 Laboratory Environment

**Date:** 2026-09-08
**Scope:** LAB BUILD ONLY on the Google VM. No Watch live validation, no
`lane.run(mode="live")`, no live switches, no Nuclei, no exploitation, no
external-target contact, no Internet reconnaissance, no production Watch
pipeline change, no production Mongo writes, old VPS untouched, no git
operations of any kind. All pre-existing working-tree changes preserved.

## 1. CVE research facts established (from stored artifacts, nothing invented)

Sources: `ai_data/research/CVE-2026-1557.cli.json`,
`ai_data/nuclei/generated/CVE-2026-1557.yaml`, pinned lane template
(`ai/live_validation/gates.py`).

| Fact | Value | Status |
|------|-------|--------|
| Product/component | WP Responsive Images WordPress plugin, vendor stuartbates | CONFIRMED |
| Vulnerable version | ≤ 1.0 (`Stable tag: 1.0`; single-release plugin) | CONFIRMED |
| Fixed version | UNKNOWN (research explicitly unknown; no patch established) | UNKNOWN — documented |
| Endpoint | `/wp-content/plugins/wp-responsive-images/image_handler.php` | CONFIRMED |
| Method / parameter | GET, `src` | CONFIRMED |
| Auth | None (unauthenticated) | CONFIRMED |
| Behavior | `src` traversal → arbitrary local file read; response carries file bytes | CONFIRMED |
| Detection pattern | status 200 or 403 AND body contains `DB_NAME`, `DB_PASSWORD` | CONFIRMED (template + lane) |
| References | WP trac tag-1.0 source links (L28/L33/L265), Wordfence, nuclei-templates PR #15592, CrowdSec hub PR #1749 | on record |

Research did NOT establish a fix version — the lab therefore reproduces the
vulnerable 1.0 code only and makes no claim about patched behavior.

## 2. Vulnerable-version acquisition (STEP 4)

Canonical download (`downloads.wordpress.org/...1.0.zip`) → **404**; SVN
`tags/` → **empty** (plugin closed, tags wiped); directory page → "closed".
`trunk/` at SVN r3686762 still serves the full 17-file tree. Provenance that
trunk == v1.0: `readme.txt` declares `Stable tag: 1.0` (only release ever),
and all three research line anchors match byte-for-byte
(`image_handler.php:28` src handling, `SBOutputFile.php:33` `sendFile`,
`WPResponsiveImages.php:265` extension gate). PHP-8 compat scan of the plugin
path: no `create_function`/`each()`/`mysql_*`/curly-offsets/`ereg` — plus
`php -l` clean on the mounted file inside the runtime container.

Determinism decision: all 17 files **vendored** under
`/opt/watch-lab/cve-2026-1557/plugin/` with per-file SHA-256 manifest
(`plugin/SHA256SUMS`, re-fetch verified byte-identical). Key files:
`image_handler.php 7873a3cd…`, `SBOutputFile.php 9eaeea5a…`,
`WPResponsiveImages.php ba8b7597…`. No `latest`, no moving tag at runtime.

## 3. Lab architecture (`/opt/watch-lab/cve-2026-1557/`)

```
Watch / test runner (this VM only)
        |  dedicated bridge watch-cve1557-lab (172.31.209.0/24, internal)
        v
cve1557-lab-wp   wordpress:6.8.3-php8.1-apache @ eeef49fc…  (.10:80)
  + vendored plugin v1.0 bind-mounted read-only at the production plugin path
cve1557-lab-db   mysql:8.0.43-debian @ bced38c0…            (.11:3306)
one-shot installer wordpress:cli-2.12-php8.1 @ ab5fb76c… (run once, removed)
```

Files: `docker-compose.yml`, `init.sh`, `healthcheck.sh`, `README.md`,
`VERSIONS.md`, `plugin/` (+`SHA256SUMS`). No `.env` reuse, no production
credentials, no production Mongo contact. DB/admin bootstrap values are
documented disposable fixtures; the CVE endpoint requires no auth.

## 4. Images/artifacts + versions/digests

- `wordpress:6.8.3-php8.1-apache` — `sha256:eeef49fcf96858412e393d73d7b2894610ade3af929da3975ae463584ff7ce46` — Docker Hub library — WP runtime
- `mysql:8.0.43-debian` — `sha256:bced38c0ca97bd00c8fbc877a019ff141f014608b0762e6e1978cc76e63f473f` — Docker Hub library — WP database
- `wordpress:cli-2.12-php8.1` — `sha256:ab5fb76caa861f32c21e1d95a057f52007f4af7130fb16a0f68874dabe0549a4` — Docker Hub library — one-shot install only
- plugin v1.0, 17 files, SHA-256 manifest — WP.org SVN trunk r3686762 — the vulnerable component

## 5. Network topology + isolation checks

- Dedicated bridge `watch-cve1557-lab`, `internal:true`; static IPs
  wp `172.31.209.10`, db `172.31.209.11`, gateway `.1`.
- **Zero published ports** (initial loopback-publish attempt proven inert —
  Docker programs no host NAT for internal networks — so it was removed, not
  worked around). Container `Ports` readback: `null`; no host listener.
- In-container routing table (`/proc/net/route`): single link route
  `172.31.209.0/24`, **no default gateway** → containers cannot route
  anywhere off-subnet, including the Internet (verified without sending any
  packet).
- No privileged containers, no `network_mode: host`, no docker-socket mount,
  no reference to production Mongo or Watch credentials anywhere in lab files.
- Host reaches the lab only via the bridge addresses (VM-local).

## 6. Production-data isolation

Lab database is its own MySQL in its own volume (`cve1557-lab-db-data`);
production Watch Mongo was never connected, written, or referenced by the lab.
Lab directory lives outside the repo (`/opt/watch-lab/`), so `git status`
shows no lab files.

## 7. Health-check results (no payloads, no Nuclei)

`healthcheck.sh` checks ONLY: compose states (both `running healthy`),
`GET http://172.31.209.10/` → **200**, `GET .../wp-responsive-images/readme.txt`
→ **200** (static file proving the plugin mount; no PHP executed).
`image_handler.php` was NEVER requested; no `src` parameter ever sent; no
Nuclei process started. Additionally verified (setup evidence, not health):
`wp-config.php` defines `DB_NAME` + `DB_PASSWORD` (template matcher
precondition present), plugin files visible in-container, `php -l` clean.

## 8. Recreate test results

`down` (network removed) → `up -d` → `init.sh` (idempotent no-op:
"already installed") → `healthcheck.sh` → **HEALTH OK**. Reproducible from
the lab directory alone (`down -v` + bring-up = full reset path documented).

## 9. Intended future target binding (documentation only)

- scheme `http`, host `172.31.209.10`, port `80`
- service: Apache + WordPress 6.8.3 + WP Responsive Images 1.0
- identity: IP-literal `172.31.209.10:80`, anonymous access
- NOT activated: no runner wired, no authorization issued, no switches set.

## 10. Deliberately NOT executed

Nuclei (any mode), `lane.run(mode="live")`, exploit payloads, template
execution, Internet reconnaissance, external-target contact, production
pipeline changes, production Mongo writes, git operations.

## 11. Limitations

- Fix version unknown → lab cannot validate patched behavior.
- WP core 6.8.3 is newer than the plugin's era; the vulnerable path is pure
  plugin PHP (compat-scanned + lint-clean), but full-era fidelity is not claimed.
- Lab is VM-local by design; it is not reachable from (nor visible to) any
  other host.

## 12. Final classification

**READY_FOR_LAB_VALIDATION**

The isolated environment exists, is reproducible, and is safe to test. This
authorizes NO exploitation, NO Nuclei execution, and NO Watch live validation.

---
Appendix — lab directory: `/opt/watch-lab/cve-2026-1557/`
(`docker-compose.yml`, `init.sh`, `healthcheck.sh`, `README.md`,
`VERSIONS.md`, `plugin/` + `SHA256SUMS`).
Live switches: `LIVE_NUCLEI=False`, `LIVE_LAUNCH_ENABLED=False`,
`WATCH_AI_LIVE_VALIDATION` unset (asserted). No external network target
contacted at any point (artifact acquisition used only wordpress.org SVN for
public source files and Docker Hub for pinned images; runtime has no egress).

Report generated:
`agent-reports/phase-5k-live-b10-lab-1-environment.md`
