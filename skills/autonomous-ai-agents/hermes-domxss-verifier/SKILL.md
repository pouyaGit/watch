---
name: hermes-domxss-verifier
category: autonomous-ai-agents
description: Use when working on the HERMES DOM XSS verifier.
---
# HERMES DOM XSS verifier

`lib/dom_xss_verifier.py`: headless-Chromium probe for DOM XSS candidates that
`poc_verifier` marked NOT_VERIFIABLE. Writes `poc_verifications`
(`check_kind='DOM_XSS'`), `poc_verify_runs` (`mode='dom_xss'`), a ledger at
`state/dom_xss/ledger.jsonl`, and PoC notes under `state/poc/dom_xss/`.
Armed only with BOTH `HERMES_ACTIVE_DISCOVERY_ENABLED=1` and
`HERMES_DOM_XSS_ENABLED=1`; dry-run otherwise.

## Field traps that silently produce zero output

Each of these caused a whole stage to look "clean" while doing nothing.

1. **`xss_candidates.confidence` is TEXT** (`HIGH`/`MEDIUM`/`LOW`), so
   `ORDER BY confidence DESC` is ALPHABETICAL (`MEDIUM` > `LOW` > `HIGH`): the 15
   HIGH rows sank to depth 937/951 and were never probed. Order with an explicit
   ordinal (`CASE UPPER(COALESCE(confidence,'')) WHEN 'HIGH' THEN 0 ...`).
2. **`source`/`sink` are rich shapes, not canonical names.** Exact equality
   against `DOM_SOURCES`/`DOM_SINKS` rejects `element.innerHTML` (117 rows),
   `jQuery.append()` (72), `postMessage event.data`. Match by case-insensitive
   substring but STORE the canonical name, and pin the pick with `sorted()` —
   `next()` over a set is order-dependent because str hashing is randomized.
3. **The payload chooser is a separate hardcoded list.** Adding a sink to
   `DOM_SINKS` without adding it to the HTML-vs-JS decision probes it with the
   wrong payload in the wrong context (unfirable). Keep ONE `HTML_SINKS` set.
4. **`inject_fn` is a no-op for `postMessage`, `window.name`,
   `document.referrer`** — the URL cannot carry the payload, so those candidates
   navigate payload-free and can never fire. `postMessage` is already a
   `DOM_SOURCES` member and is HIGH tier, so it leads every run's selection.
5. **Playwright must be importable by the DAEMON interpreter** (`/usr/bin/python3`).
   If it is absent the module self-disables (`sync_playwright is None`) and returns
   before launching, indistinguishable from "no candidates". Install into the
   user site with `uv pip install --python /usr/bin/python3 --target
   /root/.local/lib/python3.12/site-packages playwright==<ver>` (PEP 668 blocks
   `--system`; pick the version whose bundled browser revision matches what is in
   `~/.cache/ms-playwright`).
6. **Never hard-code an `executable_path`.** A non-existent path makes
   `chromium.launch()` raise, which the old code swallowed. Prefer no path
   (Playwright resolves its own bundle), and only pass a path that `os.path.exists`.
7. **A `.js` candidate URL can NEVER fire — navigate its LOADING PAGE.** A script
   URL renders as plain text, so the bundle's sink never executes there; a fire is
   impossible by construction for every script-targeted probe. Resolve the page
   that loads the bundle and probe THAT, injecting the source into it.
   `PAGE_MODE=page` defers candidates with no resolvable page; `script` restores
   the old behaviour. Prefer the offline mapping: `http_samples.body` holds page
   HTML and its `Link: <...>; rel=shortlink` header names the page each body came
   from (`http_samples` has NO `url` column — one row per host), so the mapping
   needs no crawl change and no new traffic. A candidate matches only if the
   page's OWN stored HTML references its script, and any explicit version token
   agrees: `dt.min.<hashA>` and `dt-core.min.<hashB>` have hashes that contain one
   another, so a bare substring test collapses two different files onto one page.
   Same-host is not sufficient either. One page serves many scripts, so the ledger
   key for a page probe must be host+page_url_hash+candidate_id, not host+url_hash.
8. **The payload is injected into the page, so a source with no `inject_fn` case
   is seeded with NOTHING.** `location.pathname`/`location.hostname` matched
   `DOM_SOURCES` but had no branch, so they fell through to the no-op injector and
   were navigated payload-free. Add the branch or exclude the source from the lane.
9. **A reader/writer key mismatch produces a VACUOUS zero, and it looks exactly
   like a clean sweep.** One phase wrote the bundle URL under `bundle`; the next
   read `url`, so every candidate evaluated to `stem("") == ""`, nothing could
   match, and the run reported "0 probe rows" — indistinguishable from "no page
   loads the bundle". Nothing failed, no exception, and the zero was an artifact
   of the reader. **Guard it: refuse to emit a verdict when no candidate produced
   a usable stem, and print the candidate stems beside the page's actual script
   stems so the two lists can be compared by eye.** The same shape recurs
   wherever one phase's artifact is consumed by the next: state the key the
   WRITER used, not the key that reads naturally.

## Running under the service cgroup

`hermes-recon.service` is `MemoryMax=4G` and sits at `memory.max` with
`oom_kill=0` — continuous reclaim kills Chromium renderers in bursts, so
`browser.new_page()` raises "Target crashed" while the identical code works in an
interactive shell. Reproduce faithfully with `systemd-run --user --wait --collect
--pipe --property=PrivateTmp=yes --property=ProtectSystem=full --property=
NoNewPrivileges=true --property=CPUQuota=200% --property=MemoryMax=4G
--property=MemoryHigh=3500M --property=TasksMax=64 --property=IOWeight=50
--property=Nice=10`. **`PrivateTmp=yes` gives the unit its OWN `/tmp`**, so a test
script left in `/tmp` fails with "No such file or directory" — keep scripts under
`/root`, and write results to a FILE as you go so a later crash cannot lose them.

Handle it inside the ceiling (never raise the operator's `MemoryMax` to make a
test pass): isolate each candidate, close page+context every time (an unclosed
context fails the NEXT candidate), one bounded whole-browser relaunch per RUN,
stop early after N consecutive page failures, and **never write a ledger entry
for a candidate that was not navigated** so the next run retries it.

## Verifying a probe change

- **The harness fails more often than the detector.** Three separate controls
  aborted a run in one session, and every one was a bug in the TEST:
  (a) seeding `location.hash` on a `page.set_content()` page does not produce a
  navigable fragment, so the hash case read a stale value and reported a false
  FAIL — run the control against a LOCAL HTTP SERVER, one path per case;
  (b) a URL fragment is percent-encoded by the browser before the page sees it
  (`#<b>x</b>` arrives as `#%3Cb%3Ex%3C/b%3E`), so a hash-based control that
  expects a parsed element never gets one — drive the control through a QUERY
  PARAMETER instead;
  (c) a sink hook that does NOT replace the `Function` constructor leaves the
  entire `Function` sink class invisible — the most common tier-1 sink in a
  minified bundle — so every such probe reports a false silent. Replace
  `window.Function` with a wrapper that records the body then calls the original,
  and restore `prototype` so `instanceof` still works.
  When a control disagrees with your fix, suspect the control before the code.

- **Non-vacuity FIRST.** Before trusting any 0-verified result, prove the detector
  can fire: `page.set_content` with an HTML sink (`innerHTML`, `document.write`,
  or an `.html`-parity proxy) and with a JS sink (`eval`/`Function`/`setTimeout`)
  using the REAL token, plus negatives that must stay silent (no sink; payload
  never inserted; source read but never sunk). A 0-fire run means nothing until
  this passes. `Element.append("string")` inserts TEXT, not HTML — only jQuery's
  `.append()` parses markup, so a native-append "failure" is correct behaviour,
  not a detector gap.

- **A MARKER REACHING A SINK IS NOT EXECUTION — take a stack trace.** The most
  expensive false positive in this lane: with `?p=<img src=x onerror=1>TOKEN` an
  `innerHTML` hook fires, the raw decoded payload is in the value, and the page's
  own code is provably reading the source. That still is not a finding, because
  the write can be the application's OWN sanitiser. The classic `stripTags` is
  `d=document.createElement('div'); d.innerHTML=s; return d.textContent` — it
  sets `innerHTML` on a DETACHED element and reads `textContent` back, so nothing
  is ever parsed into the document. So record `new Error().stack` on every sink
  hit and name the caller's file, and add two controls that decide it: a
  non-executing tag (`<b>TOKEN</b>`) written to the same setter must produce a
  real `<b>` ELEMENT in the document (if `querySelectorAll('b')` finds none, no
  markup was parsed), and the executing payload must set an observable flag.
  A WAF title on the payload case (`Blocked - <site>`) is a third signal.
  Without this, a sanitiser's scratch element is reported as a DOM XSS.
- **Known-positive control.** Serve two local pages — one with
  `location.hash -> innerHTML`, one with `textContent` — then drive the REAL
  `run(live=True)` on a throwaway DB copy with `D._get_candidates` and
  `scope_guard.check` monkeypatched. Expect the vuln page `VERIFIED` (signal
  `fired`) and the safe page `NOT_EXECUTED`. Include `url_hash` in the fake
  candidate dict or the ledger write raises.
- Canonical verdict strings are `VERIFIED` / `NOT_EXECUTED` (the payload builder's
  `REPRODUCED_DOM_XSS` vocabulary is NOT what this module writes) — a spec may
  assert the wrong one.
- **`HERMES_DB` does not isolate the ledger or PoC dir**: `LEDGER_DIR`/`POC_DIR`
  derive from `ST.BASE`. Snapshot and restore them, or a "throwaway copy" test
  still writes production state.
- **Read run stats from `poc_verify_runs.summary_json`, never from the tail of
  console output.** A truncated `tail` once made `probed=15 errors=0` look correct
  when the real run was `probed=14 errors=1` (`ERR_NAME_NOT_RESOLVED` on a dead
  candidate host).
- `errors=1` is usually a single nav timeout or a non-resolving candidate host,
  not a crash; `probed=0 stopped_early=True` is a memory burst that was contained
  (candidates unledgered, so retried).
- The ledger suppresses re-probe of the same `(host, url_hash)`, so after fixing
  selection you must either wait for new candidates or run against a reset ledger
  to see the newly-reachable set.

## Commit/deploy

`lib/dom_xss_verifier.py` IS classified `HIGH_RISK` by `ci_gate` (it shows as
`HIGH (1): lib/dom_xss_verifier.py`) — it is simply not in the named high-risk
list, so it still deploys without `--allow-manual` as long as `HARD RULES: 0`.
Check `logs/ci_gate.log` for `DEPLOYED:` vs `BLOCKED:` and confirm `git log` top is
not a `Revert`.

**The `EXEC_ADD` hard rule scans ADDED lines for those execution words, so naming
a dynamic-execution SINK in a data set can block you.** Spelling the `eval`-class
sink name inside an added set trips "adds execution capability"; the same word
already present on an untouched line does not. DERIVE the set from the existing
constant instead of re-typing the literal, then verify before committing: regex
the `git diff <base> -- <file>` added lines against `EXEC_ADD` and require 0 hits.
Do NOT use `--allow-manual` and do NOT weaken the regex for this — the hit is a
false positive on a NAME, and removing the duplication is the real fix.
