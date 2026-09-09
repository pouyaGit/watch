# Phase B10-LAB.3 — Fixture-Scoped Nuclei Template Validation

**Date:** 2026-09-08
**Target (only):** `http://172.31.209.10:80` (isolated lab, VM-local)
**Scope:** LAB-ONLY Nuclei validation with a disposable fixture. No external
targets, no recon, pinned production template untouched
(`f5ba287d…b8d` re-verified), no `wp-config.php`/credentials used, no
OAST/interactsh/workflows, no live switches, no `lane.run(mode="live")`,
no production Mongo contact, old VPS untouched, no git operations.

## 1. Lab target

`172.31.209.10:80` — `cve1557-lab-wp` healthy on internal bridge
`watch-cve1557-lab`; zero host ports; no off-subnet gateway.

## 2. Lab template

- Path: `/opt/watch-lab/cve-2026-1557/CVE-2026-1557-lab.yaml` (outside the
  production pinned-template path; NOT the production template)
- SHA-256: `1b806a7cefc88b82fbf10848d70f02752f6aa75695ff66389e8802572f6c2de9`
  (recorded in `CVE-2026-1557-lab.yaml.sha256`; re-verified `OK` post-run)
- Content: id `cve-2026-1557-lab`, severity info, single GET to
  `image_handler.php?src=…/../../../../../../tmp/watch-cve1557-nuclei-fixture.txt`,
  matchers `status==200 AND body word WATCH_CVE1557_NUCLEI_LAB_MARKER_2883fc88`

## 3. Template safety review (pre-execution, all asserted in-process)

Absent: `http(s)://` URLs, interactsh, OAST, workflows, `wp-config`,
`DB_NAME`, `DB_PASSWORD`, credentials (`password/passwd/secret/apikey/token`),
sensitive paths (`/etc`, `/root`, `/home`, metadata, `.ssh`, shadow).
Present: exactly one request block, one request path, the exact lab fixture
path, the exact harmless marker. No callbacks of any kind.

## 4. Nuclei binary + exact execution constraints

- Binary `/usr/bin/nuclei` (→ `/usr/local/bin/nuclei`), v3.11.1, SHA-256
  `c4958814…70251` (matches B10.3 record)
- Manual invocation (Watch production launcher NOT used):
  one target (`-u http://172.31.209.10`), one template, `-retries 0`,
  `-concurrency 1`, `-bulk-size 1`, `-timeout 5`, `-no-interactsh`,
  `-disable-update-check`, `-disable-redirects`, `-silent -no-color -jsonl
  -nc`, wall-bounded via `timeout 120`, output to `/tmp` only
- First attempt WITH `-restrict-local-network-access` failed closed
  (`denied address found for host`, zero requests) — the production SSRF
  guard refuses RFC1918 lab addresses by design. Documented here as a
  positive boundary signal; the authorized lab run omitted only that flag.

## 5. MATCH result (2026-09-08T14:19:08Z)

- Exit 0, exactly one JSONL finding, `matcher-status: true`
- `host 172.31.209.10 / port 80 / scheme http` — lab target only
- `matched-at` is the fixture traversal URL; response body (69 bytes) is the
  fixture content including the unique marker — nothing else
- Response exhibits the researched dual behavior: HTTP `200 OK` status line
  with inner plugin header `Status: 403 Forbidden` (matches the production
  template's `200||403` expectation)
- Attributable to CVE-2026-1557 behavior: unauthenticated `src` traversal
  reading an file outside the web root (`/tmp/...`, statically unreachable)

## 6. NO MATCH negative control

Temp template copy retargeted to nonexistent
`watch-cve1557-absent-xyz` fixture → exit 0, **0 bytes output** (NO MATCH).
Temp copy deleted immediately after. Proves the MATCH depends on the real
fixture read, not on request shape.

## 7. Network isolation confirmation

All requests to IP-literal `172.31.209.10` on the internal bridge (no DNS);
container subnet has no default gateway; zero host port publications; no
external communication occurred or was possible.

## 8. No-sensitive-data confirmation

Only bytes ever retrieved: the disposable fixture (marker + `harmless` line).
No `wp-config.php`, no `DB_PASSWORD`/credentials, no host/cloud files touched.

## 9. Cleanup

Removed: container fixture, `/tmp` Nuclei JSONL/stderr, marker file, negative
template + output. Post-cleanup traversal probe: marker count 0. KEPT as
reproducible evidence: `CVE-2026-1557-lab.yaml` + `.sha256` (integrity
re-verified). Lab left running healthy. Production pinned template and
`gates.py` digest byte-unchanged.

## 10. Live safety

Production template unchanged; `LIVE_NUCLEI=False`,
`LIVE_LAUNCH_ENABLED=False`, `WATCH_AI_LIVE_VALIDATION` unset (asserted);
Watch live runner never invoked (`lane.run` untouched); no Nuclei process
remains.

## 11. Exact commands/checks

Fixture `printf` via `compose exec`; template authoring + static regex audit +
single-request structural assert + `sha256sum`; `-validate` run; verbose
diagnostic run (exposed the SSRF-guard refusal); bounded JSONL run; JSONL
field verification (`matcher-status`, host/port/scheme, matched-at, body);
negative-control variant run; `sha256sum -c`; fixture/output deletion +
marker-absence re-probe; switch assertions; `pgrep -x nuclei`.

## 12. Limitations

- Lab-only template/digest; production template still targets `wp-config.php`
  and remains unexecuted (per LAB.2 rule).
- Manual binary invocation, not the Watch gated launcher (separate activation).
- WP core newer than plugin era (vulnerable path is pure plugin PHP).

## 13. Final classification

**LAB_NUCLEI_MATCH_CONFIRMED**

The LAB-ONLY template detects the known vulnerability in the isolated lab.
Authorizes NO external-target testing and NO production live validation.

---
Lab: both containers running healthy. Switches: DISABLED. Nuclei: none.
Repo: untouched (lab outside git; `git status` shows only pre-existing entries).

Report generated:
`agent-reports/phase-5k-live-b10-lab-3-nuclei-template-validation.md`
