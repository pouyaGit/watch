# Spec — Vuln scanning + recon expansion for Watch

Audience: an implementer (e.g. Haiku) working in this repo (`/opt/watch`).
Scope: add the capabilities Watch is missing, grounded in what already exists.
Screenshots/gowitness are intentionally OUT of scope.

Keep the house style: FastAPI + mongoengine + server-rendered HTML
(`backend/routers/pages.py`, templates extend `web/templates/base.html`, CSS in
`web/static/css/app.css`), Telegram via `config()`, and — for anything heavy and
continuous — a **lane of the 24/7 heavy worker**, never a new always-on service.

---

## 0. What already exists (read first, do not rebuild)

- **Heavy worker** `watch_heavy_worker.py`: one always-on process that time-slices
  lanes round-robin, one at a time, `WATCH_HEAVY_LANE_MINUTES` (default 20) each.
  A lane = `(name, argv)` in `LANE_CMDS`; the worker runs
  `<script> --max-minutes N` and the script must be **resumable** (least-recently-
  processed first) and honour `--max-minutes`. Current lanes: `brute`, `crawl`,
  `param`. Resource caps come from `watch-heavy.slice`.
- **Models** `database/db.py`: `Programs` (scopes/ooscopes), `Subdomains`,
  `LiveSubdomains` (ips, cdn), `Http` (url, title, status_code, tech[], headers,
  final_url, favicon, created_date), `Urls`, `Endpoints` (x8 fields),
  `DnsBruteStatus`. Change tracking: `database/change_events.py`
  (`record_change`, `recent_events`) + `notify_*` helpers.
- **Tool runner** `utils/common.py` (`run_command_in_zsh_*`, `tool_env`),
  `ns/dns_brute_common.py` (`send_telegram`, `require_tools`).
- **Status pages** pattern: a handler in `backend/routers/pages.py` renders a
  `table.status` (responsive: cards on mobile) via `render_page(...)`; nav links
  live in `base.html`. Examples: `/ui/dns-bruteforce/status`, `/ui/crawl/status`,
  `/ui/x8/status`.
- **Installed tools**: nuclei, ffuf, dnsx, httpx, katana, subfinder, alterx,
  puredns, x8. **Missing** (install in setup + README): `gau`. (naabu NOT wanted.)
  Optional: `trufflehog` (or use a Python secret-regex pass).
- **`nuclei/watch_nuclei_all.py` already exists** but is **wired into nothing**.
  Review and reuse/replace it rather than starting from zero.

Hard lesson to encode everywhere (2026 recon consensus): **broad nuclei/fuzzing
against the whole surface = noise that buries real findings.** Prefer narrow,
tech-aware, severity-filtered scanning of *fresh/new* assets, and alert only on
`medium`+.

---

## 1. Findings data model (new) — `database/db.py`

One collection for all vuln-ish results (nuclei, takeover, secrets, content):

```
class Finding(Document):
    program_name = StringField(required=True)
    scope        = StringField()          # apex the asset belongs to
    target       = StringField(required=True)  # url / host the finding is on
    source       = StringField(required=True)  # nuclei | takeover | secret | content
    name         = StringField()          # template-id / rule name
    severity     = StringField()          # info|low|medium|high|critical|unknown
    matched      = StringField()          # matched-at / evidence (bounded)
    extra        = DictField()            # raw structured details (bounded)
    first_seen   = DateTimeField(default=datetime.now)
    last_seen    = DateTimeField(default=datetime.now)
    status       = StringField(default="open")   # open | triaged | false_positive | fixed
    meta = {"indexes": [
        {"fields": ["program_name", "severity"]},
        {"fields": ["source"]},
        {"fields": ["target", "name"], "unique": True},   # dedupe
    ]}
```

Add `upsert_finding(obj)` that dedupes on `(target, name)`: insert → set
first_seen; existing → bump `last_seen` only (do NOT re-alert). Alerting happens
only on first insert of a `medium`+ finding.

---

## 2. PRIORITY 1 — Nuclei smart lane (`nuclei`)

New resumable script `nuclei/watch_nuclei_run.py` (reuse logic from the existing
`watch_nuclei_all.py`), added as a 4th heavy-worker lane.

Target selection (the whole point — keep it narrow):
- Source of targets: `Http` (live HTTP services), **newest/fresh first**
  (`created_date` desc) and anything not scanned since `NUCLEI_RESCAN_DAYS`
  (track `last_nuclei_run` per target, e.g. a small `NucleiStatus` doc or a field
  on `Http`). Resumable: least-recently-scanned first, honour `--max-minutes`.
- Optional **tech-aware** template selection: use `Http.tech[]` to pass
  `-tags`/`-templates` narrowed to the detected stack when possible; otherwise a
  curated default template set (exclude `info` noise).

Invocation (argv list, never shell-interpolated input):
```
nuclei -l <targets_file> -jsonl -o <out> -severity low,medium,high,critical
       -rl <rate> -c <conc> -timeout 8 -retries 1 -silent
       [-tags <tech-derived>] -ni   # -ni = no interactsh unless you run a server
```
Env knobs (README them): `NUCLEI_RATE_LIMIT`, `NUCLEI_CONCURRENCY`,
`NUCLEI_SEVERITY` (default `medium,high,critical`), `NUCLEI_RESCAN_DAYS` (7),
`NUCLEI_TEMPLATES` (path; default the repo templates + projectdiscovery public).

Persist: parse JSONL → `upsert_finding(source="nuclei", severity=..., name=
template-id, target=url, matched=matched-at)`. On a NEW `medium`+ finding, send a
Telegram alert (one line: severity · template · url). Keep a per-run summary
telegram gated like the brute lane (`WATCH_BRUTE_VERBOSE`-style flag,
`WATCH_NUCLEI_VERBOSE`).

Lane wiring: add `nuclei` to `LANE_CMDS` and to `WATCH_HEAVY_LANES` default
(`brute,crawl,param,nuclei`). `require_tools(["nuclei"])` preflight.

Results page: `/ui/findings` (and nav link "Findings") — a `table.status`:
Severity · Source · Target · Name · First seen · Status, with filters by
program/severity/source and a severity color badge. Add a KPI tile on the
dashboard ("open findings by severity").

## 3. PRIORITY 2 — Subdomain takeover (`takeover`)

Cheap, low-noise, real findings. Two options (pick one, nuclei is simplest):
- **nuclei takeover templates**: run nuclei with the `takeover`/`dns` tags over
  `Subdomains` that have a dangling CNAME. Feed `upsert_finding(source=
  "takeover", severity="high")`.
- or a dedicated check: for each subdomain, `dnsx -cname` → if CNAME points to a
  known-takeoverable service (S3, GitHub Pages, Heroku, Azure, Fastly, etc.) and
  the base resolves NXDOMAIN/404-fingerprint → finding.

Run it as part of the `nuclei` lane (a cheap first pass) or a short dedicated
lane. Always alert on a takeover candidate (high value).

## 4. PRIORITY 3 — Secret / JS scanning (`secret`)

The crawl lane (`katana -jc`) already pulls JS URLs. Add a step/lane that:
- collects fresh JS/asset URLs from `Urls`/crawl output,
- downloads them (bounded size, `-mrs`-style cap) and scans for secrets with
  `trufflehog filesystem`/`--only-verified` if installed, else a Python
  regex pass (AWS keys, Google API, Slack, JWT, private keys, bearer tokens),
- `upsert_finding(source="secret", severity="high")` + alert.
Keep it polite + bounded (don't download huge bundles; cap count per run).

## 5. Data/coverage tools (install + integrate)

> **Port scanning (naabu) is OUT of scope — do not implement it.** The operator
> only wants `:443`. Remove the earlier naabu/port-scan item entirely.

- **`gau` merged INTO the crawl lane (katana)** — NOT a separate lane/enum step.
  gau (getallurls) aggregates historical URLs (wayback + commoncrawl + urlscan +
  OTX), which are then used as **extra katana seeds**, so the crawl goes deeper
  from known-historical paths instead of only from live `Http` URLs. In
  `crawl/watch_crawl_all.py`, per domain, BEFORE launching katana:
  1. run `gau` for the domain (include subdomains), bounded and killable:
     `timeout -k 10 N gau <domain> --subs --threads <n>` (verify flags with
     `gau -h`; some builds use `getallurls`/different flags).
  2. keep only in-scope hosts (host endswith an in-scope apex, drop `ooscopes`),
     drop junk/static extensions (reuse the crawl's `BAD_EXT`), de-duplicate, and
     **cap** at `GAU_MAX_SEEDS` (env, default e.g. 20000) so a huge history can't
     blow up the lane or katana.
  3. merge that capped set into the existing `seeds.txt` fed to katana (union
     with the live-HTTP seeds), then crawl as normal.
  4. persist the gau URLs via the **URL-only** writer (so they populate `Urls`
     but do NOT create `Endpoints` — raw historical URLs would feed x8 junk;
     this is exactly the url-only bulk writer added in §1).
  Gate with `GAU_ENABLED` (default on) and keep it inside the crawl lane's
  `--max-minutes` budget. One tool, one lane — no new heavy-worker lane for gau.
- **`ffuf` content discovery**: ffuf is installed but unused. Add a bounded
  dir/file fuzz over selected live hosts (small wordlist, per-host cap, polite
  rate), storing interesting responses as `Endpoints`/`Findings`. Opt-in lane
  (`WATCH_HEAVY_LANES` does not include it by default); active + noisy, keep it
  narrow.

Install `gau` in `setup-weekly-jobs.sh`/README (`go install
github.com/lc/gau/v2/cmd/gau@latest`). `require_tools(["gau"])` preflight the
crawl lane's gau step (skip gracefully if absent, don't fail the whole crawl).

## 6. Notifications — make Telegram useful, not spammy

- **Severity routing + dedupe**: only alert once per finding (handled by
  `upsert_finding`), and only `medium`+ immediately.
- **Daily digest** (new): a once-a-day summary (cron/systemd timer or a
  heavy-worker heartbeat) — new live hosts, new HTTP services, new findings by
  severity, per program. One message, not a stream.
- **Dedicated new-asset alerts**: on a genuinely NEW live host / new HTTP
  service / takeover-candidate, a concise high-priority ping (reuse
  `change_events`). Keep routine "unchanged" noise out.
- A `TELEGRAM_MIN_SEVERITY` env to tune the floor.

## 7. Operational / reliability

- **Health watchdog** (new small systemd timer `watch-health`, every ~10 min):
  check the key units (`watch.timer`, `watch-heavy`, `watch-ct-stream`,
  `watch-api`, the mongo container) are active; if one is down, Telegram-alert
  once (debounced). Optionally also probe an external URL list (e.g. the 9router
  dashboard) and alert if unreachable — the kind of outage that was missed before.
- **Mongo indexes + archiving**: dashboard/status queries were slow under load.
  Ensure indexes on the hot query fields (`program_name`, `scope`, `created_date`,
  `last_update`, `providers`). Add a maintenance job to prune/compact (e.g. drop
  `Urls` older than N months, cap `change_events`).
- **ASN/CIDR expansion** (`asnmap`, optional): from known resolved IPs, expand to
  the org's CIDRs → feed new candidate hosts into resolve/http. High-signal for
  orgs that own IP ranges.

## 8. Security / constraints (must hold)

- Tools come from a fixed allowlist; targets/scopes validated against `Programs`
  — never scan a host that isn't in scope (respect `ooscopes`).
- All external tool calls use argv lists (no `shell=True` with interpolated
  input). Wrap long-running tools in `timeout -k 10 N` (same pattern the crawl
  lane now uses) so nothing runs unbounded.
- Everything heavy goes through the heavy worker (one job at a time, slice caps),
  NOT new always-on services, so the 2-core/4GB VPS stays healthy.
- Respect program rate rules; keep rate limits conservative and env-tunable.
- New UI endpoints stay behind the existing auth middleware.

## 9. Acceptance criteria

1. The heavy worker rotates `brute → crawl → param → nuclei` and nuclei produces
   `Finding` rows; a NEW medium+ finding sends exactly one Telegram alert.
2. `/ui/findings` lists findings (responsive) filterable by program/severity/
   source; dashboard shows open-findings counts.
3. A takeover candidate is detected and alerted on a test domain with a dangling
   CNAME.
4. gau is merged into the crawl lane: historical URLs become extra katana seeds
   and land in `Urls` (url-only, no `Endpoints`); no separate gau lane exists.
   (No port scanning.)
5. A once-daily digest arrives; routine unchanged assets do NOT spam.
6. Killing `watch-ct-stream` (test) triggers one watchdog alert.
7. No out-of-scope host is ever scanned; no unbounded tool run; all behind auth.

## 10. Suggested order (impact first)

1. **Nuclei smart lane + Finding model + `/ui/findings` + medium+ alerts.**
2. **Subdomain takeover** (as a nuclei pass).
3. **Health watchdog** + **daily digest** (cheap reliability/ signal wins).
4. **gau merged into the crawl lane** (coverage). (No naabu/port scan.)
5. **Secret/JS scanning**.
6. **ffuf content discovery** + **asnmap** + **Mongo indexes/archiving**.

## 11. Files to touch / add

- `database/db.py` — `Finding` model + `upsert_finding`; indexes.
- `nuclei/watch_nuclei_run.py` (new, resumable) — reuse `watch_nuclei_all.py`.
- `crawl/watch_crawl_all.py` — add the gau step that feeds katana seeds (no
  separate gau file, no port-scan). `ffuf` content step (new, opt-in lane).
- `watch_heavy_worker.py` — add `nuclei` (and any new) lane to `LANE_CMDS`.
- `systemd/watch-heavy.service` — env knobs; new `systemd/watch-health.{service,timer}`.
- `backend/routers/pages.py` — `/ui/findings` (+ dashboard tile); nav link in
  `web/templates/base.html`; reuse `table.status`.
- Notifications: a digest sender + `change_events`-driven new-asset alerts.
- `setup-weekly-jobs.sh` + `README.md` — install gau(/trufflehog) — NOT naabu, document
  the nuclei/health/digest additions and all new env knobs.
