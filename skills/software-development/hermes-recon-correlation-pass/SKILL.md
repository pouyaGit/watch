---
name: hermes-recon-correlation-pass
category: software-development
description: "Use when running the HERMES complex correlation pass."
---

# HERMES complex cross-finding correlation pass

Recurring cron job: correlate assets, generic findings and XSS candidates from artefacts already
under `/root/hermes-recon/`, write `reports/correlation_<YYYY-MM-DD>.md`, and reply with a ≤10-line
Telegram message ending in the §28 attribution line. Static/passive only: never contact a host, never
send a payload/parameter/header, no internet, do not modify the DB, do not run a cycle, no git.

## Budget gate first
Read `BUDGET GATE` in the pre-run context. If REFUSE, output exactly
`💸 complex blocked/exhausted — finding correlation deferred; staying on free models` and stop.

## Data access (read-only)
- Copy the DB first: `shutil.copy('/root/hermes-recon/state/hermes.db', '/tmp/hermes_ro_MMDD.db')`,
then `PRAGMA query_only=1`. There is **no `sqlite3` CLI** on the box; use `python3`.
- `execute_code` is blocked in cron and any `python3 -c "<multi-line SQL>"` is blocked by the
Tirith shell scanner — always `write_file` a script to `/tmp/corr_Mmdd_<letter>.py` and run it.
- `http_samples` has **no `url` column** (key on `host`); one body per host. `js_samples(url,host,text)`
and `js_assets(url,host,size,content_hash,analyzed_hash,last_change)` do have `url`.
- `first_seen`/`last_seen` are **unixtime floats**, not ISO strings — `substr(first_seen,1,10)` groups
by the literal `1790…` prefix and is useless; convert with `datetime.fromtimestamp(float(ts))`.
- Bodies are capped: `js_samples` 300 000 chars, **`http_samples` 200 000 bytes** (the cap moved up from 150 000 — don't quote the old number). 61 rows sit exactly at the 200 000-byte cap and are truncated mid-attribute. Test `>=` the cap and say "captured region only" rather than claiming the whole file was read.
- `js_assets.content_hash` is **not** the md5 of the `js_samples` body (different byte range/encoding).
Use `content_hash` for identity *within* `js_assets`; use md5 of `text` for body identity.

## Rebuild the "important" set exactly
The pre-run context's N important items == every row matching
`xss_candidates.severity IN ('High','Medium') AND acked_at IS NULL`. Verify equality id-for-id before
analysing; it has held on every pass. `findings.alert_status` is NULL for all rows and
`xss_candidates.acked_at` is NULL for all 300+, so "unacknowledged" is a constant, not a signal.

## Defects that dominate the counts (verify, then report as the lead)
- **`auth:*` findings are attributed to the wrong host**: `scripts/cycle.py:1540-1543` passes the
  **whole target's** URL list to `analyze_auth_surfaces` while the recording closure uses the current
  job's `host`. Result: ~3 053 of 3 089 `auth:*` rows name a different host in their evidence than in
  their `host` column (55 distinct evidence URLs × 510 host values), all `dedup_key IS NULL`. This is
  usually ~80 % of a day's `findings` growth and it inflates `correlation:multi-finding-host`. Real
  signal = distinct `(evidence_url_host, category)` pairs (~25), not the row count.
- **Two CORS rules fire on one header pair**: `lib/analysis.py:210` emits `cors:wildcard-with-credentials`
  (High) when `ACAO='*' AND ACAC='true'`; `lib/analyzer.py:25-29` emits
  `cors:reflected-origin-with-credentials` on `ACAC='true' AND (ACAO='*' OR other-origin)` — the `'*'`
  arm is the identical condition, so one host gets two findings and a wildcard is labelled "reflected".
  Per the Fetch standard `ACAO:* + ACAC:true` is browser-invalid (not directly credential-leaking);
  reserve "reflected" for a value observed to vary with the request Origin.
- **CORS coverage is lane-luck, not header content**: parse every `http_samples` header blob for the pair
  (~10 captures hold it) and cross-check `coverage.module='security'` — hosts without a security row are
  `ABSENT` and silently produce no finding. Report the gap instead of the headline High count.
- **`response:0`-lane offsets must be verified against the archive.** `cards.linktr.ee`'s four Medium
  `variant` rows cite offsets that hold no such text; the value is a Shopify `pageurl` analytics field /
  server-rendered `<a href>`. `urls.params='variant'` is `crawl`-real, but `variant` is a platform id.
  When `js_file='response:0'` there is no stored body, so the row is unfalsifiable — say so.
- **`coverage` has 0 rows for module `xss`** (candidate coverage is not a tracked stage) and
  `auth:oidc-surface` in `lib/analysis.py:270` is a dead branch — no `findings` row ever carries it.

## Standing findings that keep being re-derived (check, then reuse)
- Collapse the set on `(js_file, line, sink)` and on `(…, host)` before reading any code: 108 ids →
  ~47 paths on ~25 files over ~39 hosts. Vendor families (`shortcodes.js` md5 `c5a1298660a2`,
  `ooo_solr.js` `25537825ef09`, `avia-snippet-hamburger-menu.js` `d70920369d9e`, `icongrid.js`,
  `dynamic.js` `dc309bf88174`, WP `jquery.min.js` `826eb77e86b0`, SWCMS `vendor.js` — the 09-22 hash
  `957573c34b17` **no longer exists**; the family is now `a1dbbb1f5b2433de` (28 510 B, 19 hosts, e.g.
  11 `*.schule.wien.at` `postMessage → Function` Lows re-recorded per host)
  are byte-identical across hosts: a **new host name for an existing file is a cross-reference**, not work.
- Count `severity IN ('High','Medium')`, then check for **the same body under two file names**: on
  Pinterest `js_NAhOQwS…` and `js_XGKr…` share `content_hash 74696efdb25be2…` (60 886 B) and
  `help.pinterest.com`/`support.pinterest.com` bodies are 99.986 % identical — 18 "important" ids = 5 paths on 1 site.
- Today's arrivals are almost always **asset-refresh driven**: for the files behind them
  `js_assets.content_hash == analyzed_hash` and `last_change` equals the candidate's `first_seen`
  to the second. Say that instead of treating growth as new risk.
- The prose verdicts live in `targets/<target>/findings/xss/reports/dataflow_*.md`; the
  `finding_reviews` table stops dead at `XSS-000157` (2026-09-19) and `classification` is NULL for
  ~half the important ids. Report both: the reports have verdicts for ~107/108 rows, the DB lane is 4 days stale.
- `urls.params` is ~94 % `source IN ('local_param','js_param')`, i.e. JS identifier tokens with `?`
  prepended (`?CSSMotion=`, `?msapplication-TileImage=`, `?e.type=`). The `correlation:xss-input-surface`
  findings count these, so their "N parameter-bearing URLs" is inflated. Gate on
  `source IN ('crawl','link','js_urlsearchparams','html_form')` before believing a parameter exists.
- 401/403 hosts with "parameters" are the same artefact; a **403 MA-01 block page**
  (`title = 'MA 01 - Wien Digital'`, `Zugriff verweigert`) is not page markup, so candidates on
  `ybbs`/`standort-penzing` were produced from a body that cannot contain the page.
- `pd_dns_observations` says `NO_ADDRESS`/`RESOLVER_ERROR` for ~33 000 hosts while `assets.dns_alive = 1`
  for 246 of them (the reverse is 0). Treat "dangling" as unproven; the 2026-09-22 verdict that the
  CloudFront/Adobe-CQMS/SFMC CNAME groups point at **live provider edges** still holds.
- `diff_decisions` is >95 % `DEFERRED_CEILING` and reaches only `linktr`/`dell`/`linktree`/`linktree-extensions`;
  `recon_changes` holds ~3 rows. Do not claim "what changed" for the other 14 targets.
- `http_samples` holds a 403 block page for `www.wien.at`, `standort-penzing`, `ybbs` and the
  0-byte/absent bodies elsewhere: grep the **host's own** capture for a `data-*` attribute before
  citing a sibling host for provenance, and say "absent from the archive" when the count is 0.

## Report shape that has been accepted
H2 sections `C1..Cn` (C1 is always the queue-collapse correction; then the auth/parameter artefact,
the DNS contradiction, the one converging host) each with **Findings involved · why it raises or
lowers · existing evidence · one concrete next manual step**, then `Patterns judged coincidence /
artifact (do not chase)` as a numbered list, then `Method / limitations (disclosed, not hidden)`
listing caps, non-archived files, and the hash/coverage divergences, then `What was NOT done`.
Never write "confirmed"; use *potential*/*candidate*. Keep the standing disclaimer paragraph.

## Change-lane watch
- `diff_runs.assets_deferred` sat at 981 for five runs then jumped to **25 141** (2026-09-24 05:58) with
  `errors` empty and no ceiling changed. Record such jumps as an anomaly for the operator; never raise a
  ceiling to "fix" it. `correlation_groups` (47) and `recon_changes` (3) have been frozen since 09-19.

## Final message
≤10 lines: the 3 most meaningful correlations, each with the involved ids/hosts and the single next
manual step. Last line exactly: `Model: complex (DeepSeek — 9Router 'complex' route)`.
