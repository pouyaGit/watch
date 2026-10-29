---
name: hermes-battery-and-milestone-verification
description: Use when running the HERMES battery or milestone claims.
---

# HERMES battery + milestone claim verification

## The battery cannot run concurrently with itself

`state/day6/day6_battery.sh` writes to FIXED paths:

- `state/day6/snapA.json`, `snapB.json`, `integrity.json`
- a shared results/log file

Two overlapping runs interleave: one run's `snapA` gets compared against the
other's `snapB`, suite lines get double-logged, and `INTEGRITY_RC` flips to 1
with phantom `findings` deltas. The battery also STOPS the daemon for its
duration, so a daemon-produced row cannot explain an integrity delta — if you
see one, suspect your own overlapping run before blaming the system.

Rule: before starting the battery, confirm no other battery is in flight
(`pgrep -f day6_battery`). Run it once, alone, and wait for the real exit.

**Lesson earned 2026-09-29:** two concurrent runs produced `INTEGRITY_RC: 1`,
58 suite lines, and `findings +2`. The first attribution ("live daemon recon")
was wrong — the daemon was stopped. A single clean run gave `INTEGRITY_RC: 0`,
53/53, and byte-identical DB state.

## Suite count: 53, not 58

53 PASS lines = 51 unique suites; `day4_observability` and
`day5_observability` each run in two modes. Count PASS *lines*, and if the
number looks wrong, compare unique suite names between logs to detect
double-logging.

## Never write a claim before the process that verifies it exits

A report must not state "53/53" or "INTEGRITY_RC: 0" until the battery has
actually exited and the log has been read. Writing the expected value first and
then finding it contradicted is how wrong numbers reach a final report.

## Verify each number independently before reporting

Run the real thing, then re-derive each headline number with a separate command.
Parsing mistakes are common: PASS lines are `PASS<TAB>name` so
`grep -c '^PASS'` misses them (use `grep -cE '^PASS[[:space:]]'`); and
`integrity.json` has a `row_delta` key that is a dict, so
`all(v is True ...)` over `checks` reports False even on a clean run.

## Reading M10 (`lib/evidence.py`) correctly

- `ACTION_CLASS` keys have NO `AT_` prefix (`HTTP_HEAD`), while the `AT_*`
  constants do. `plan_actions` stores `action_type` unprefixed too.
- `AUTO_EXECUTABLE` holds SAFETY CLASS names (`SAFE_HEAD`, `SAFE_LOCAL`), not
  action-type keys. Comparing action types against it silently reports every
  action as non-executable.
- `execute_action` dispatches on SAFETY CLASS, not per action type, so a
  per-action regex finds nothing.
- All `SAFE_LOCAL` actions return `acquired: False, evidence: [], requests: 0` —
  they acquire NOTHING. A mapping that plans one yields no evidence.
- Only `HTTP_HEAD` / `HTTP_GET_FINGERPRINT` fetch, and only
  `fetcher(host, target_dir=target, method=...)`: no path, query, params, or
  custom headers exist to abuse.
- `plan_actions` needs a real audit from `audit_correlation` with gap dicts
  shaped `{gap_type, why_missing, what_would_resolve, actionable}`.

## Read the CURRENT run's artifacts, not the append-only log

`battery.log` is opened with `tee -a` and never truncated, so it accumulates
every historical run. Grepping it for `INTEGRITY_RC` or `FAILED_SUITES` returns
one line per past run and you cannot tell which is yours. Authoritative
current-run sources:

- `state/day6/regression/results.tsv` — `: >"$RESULT"` truncates it at start and
  `run_suite` appends one row per suite, so its row count IS this run's count.
- `state/day6/integrity.json` — written exactly once, after snapshots B and the
  compare step.

Do not count `grep -cE '^PASS[[:space:]]' battery.log` — that sums all runs (it
returned 2032 against a 53-suite run). Use
`awk -F'\t' '$2==0' results.tsv | wc -l`, and read the exit from a wrapper
(`...; echo "BATTERY_EXIT=$?"`), since the script itself always `exit 0`.

**The `integrity.json` sha256 pair goes stale the moment you copy it.** The
daemon restarts after the battery and immediately writes, so a fresh `sha256sum`
disagrees. Quote `before`/`after` **from integrity.json** — that IS the A-vs-B
comparison. Writing the hash into a report before the battery exits guarantees a
stale number.

## Registering a new suite changes the total — that is not a regression

Adding `run_suite` lines for new suites moves the count (53 -> 55 here) while
`FAILED_SUITES` stays 0. Say so explicitly and report both the PASS-line count
and the unique-suite count, so the change is not read as double-logging.

## A CSS assertion is not a viewport measurement

For a UI/responsive claim, reading the stylesheet proves nothing about layout.
Measure it: render the real pages, then drive headless Chrome over CDP and read
back geometry.

- Render first: call the real route + shell (`server.route(path, {})` then
  `render.shell(...)`) and write the HTML to `/tmp/...`, so the measured document
  is the real one.
- Driver: `--headless=new --remote-debugging-port` at
  `/root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome`, then a stdlib
  WebSocket (raw socket + frame masking) to `Page.navigate`,
  `Emulation.setDeviceMetricsOverride` and `Runtime.evaluate`. No new pip
  dependency.
- Assert on `document.documentElement.scrollWidth - clientWidth`, on every
  element's `getBoundingClientRect().right` vs the viewport, and on
  `td.scrollWidth > td.clientWidth` per cell. Then check `getComputedStyle` for
  visibility of the nav you claim is reachable.
- **Use `/usr/bin/python3`, not Hermes' venv python.** The web UI imports
  `bcrypt` (for `web/auth.py`) and only the system interpreter has it; the venv
  fails with `ModuleNotFoundError`, which must not be misread as an app fault.
- **Exclude the skip-to-content link from the overflow probe.** It is parked at
  `left:-9999px` until focused by design, so it appears as "1 element past the
  viewport" on every page at every width. Exclude `position:fixed` and
  `.skip` explicitly rather than arguing the 24 "failures" away.
- Prove a nav is reachable by "visible in the renderer rounded to the pixel",
  not by the `href` being present in the HTML.
- For mobile stacked tables, `td::before` is the only thing carrying the column
  name once `thead{display:none}`. A fixed `flex:0 0 40%` label column CLIPS long
  values instead of wrapping, and an anonymous flex item cannot be given
  `min-width`. Use `flex-wrap:wrap` + `overflow-wrap:anywhere`.
- A CSS-only disclosure (`#id` + `:target`) keeps `default-src 'none'` viable and
  stays usable with scripting disabled; measure it by setting `location.hash` and
  re-reading visibility.

## "Click" means click, not set-the-state-you-expected

Three Hermes UI milestones in a row passed an interaction they never performed. Each
failure had the same shape: a test **set the postcondition directly** instead of
**driving the mechanism**, so it could not distinguish working code from broken code.

| Milestone | What the test did | What it should have done |
|---|---|---|
| v1 More menu | asserted `href="#moredest"` + `id="moredest"` present | dispatch a real mouse event |
| v2 Activity | `location.hash='#moredest'` then asserted panel open | dispatch a real mouse event |
| v3 (root cause) | all of the above | dispatch a real mouse event |

v3's actual defect: two `<nav class="mobilebar">` elements were both
`position:fixed;bottom:0;left:0;right:0;z-index:9` — **the identical rect**. The More bar's
single `flex:1` link spanned the full 360px and painted over all four 90px primary cells.
Worse, the cell widths still *looked* right in the DOM (`/t` `/targets` `/i` `/security`
each 90px), so every geometry and overflow assertion passed. Hit-testing
(`document.elementFromPoint` at each cell's centre) was the only probe that saw it — it
returned the More bar's `☰` for all four cells.

Rules:
- **`element.click()` is not a click either.** It bypasses hit-testing, so it cannot
  prove a control is *reachable* — only that it has a handler. Use CDP
  `Input.dispatchMouseEvent` at the element's coordinates, then assert
  `document.elementFromPoint(x,y)` is the element or its descendant. That is the only
  probe that distinguishes "painted" from "tappable", and "painted over" from "visible".
- **Assert the pre-click state.** A suite that only checks the postcondition passes
  against a panel that was already open. Probe closed → click → probe open.
- **Two sibling elements with identical fixed geometry will collide.** When adding a
  second bar/overlay, assert the count (`querySelectorAll(...).length === 1`) and
  hit-test *every* cell of the survivor. `getBoundingClientRect` equality is a cheap
  smoke test for the whole class.

## A suite that passes standalone can still fail in the battery

`test_more_interaction` passed 3/3 standalone and failed `A4 Shamsi date still Persian`
in the battery, because `goto()` polled only `document.readyState === "complete"` — already
true on the page being *left*, so the next probe could read the **previous** page
(`/settings`, which has no `DATE` cell → empty string). It is a real race, not a flake, and
"it passed three times in a row" is what a race looks like before it loses.

Fix: plant `window.__navSentinel` on the current document, navigate, and wait until the
sentinel is **absent** *and* `location.pathname` matches *and* `readyState === "complete"`.
Never gate navigation on a condition that is already true pre-click.

Two follow-ups that matter:
- **Run a new suite in the real battery immediately.** A focused run that passes does not
  establish anything about ordering.
- **Always check the log for a traceback when a suite exits non-zero with `fails=0`.**
  `grep '  FAIL'` returning nothing is *not* evidence of success — it may mean the suite
  never ran (e.g. `OSError: Address already in use` on a fixed port). Print the tail.

## Retargeting a test is not weakening it

When a fix legitimately changes structure, an old assertion will encode the **buggy**
layout. v2 asserted `len(hrefs) == 4 and "#moredest" not in hrefs` — that literal encoded
the two-bar bug. Replacing it with the *invariant* (`PRIMARY_CELLS <= hrefs` and
`"#moredest" in hrefs` and `barCount == 1`) is stronger, not weaker. State that plainly in
the report; a retarget that drops an assertion without a reason is a regression.

## A geometry assertion is not a semantics assertion

The failure mode that produced a wrong PASS on a visibly broken mobile page:
the viewport audit measured **overflow**, **elements past the edge**,
**`td.scrollWidth > td.clientWidth`** and **link reachability** — all clean —
while every field label was absent. A label that was never painted does not
overflow (no box), does not clip (nothing to clip) and does not break the route.
The test proved the container was healthy while the content was empty.

Check the thing the user reads, not the box around it:

- **Read the painted value, not the markup.** `getComputedStyle(td,'::before').content`
  compared against `td.getAttribute('data-label')` catches this in one line.
  Asserting `"data-label=" in html` is inert — the attribute can be present in
  markup and dead in the cascade.
- **The classic signature is a CSS `attr()` naming a different attribute than
  the renderer emits.** `content:attr(data-l)` with `<td data-label=…>` resolves
  to the **empty string** (no error, no console warning, zero-width box). Match
  the names with `[\w-]+`, not `\w+` — `\w` stops at the hyphen, so a test
  written as `\w+` silently matches only `data` and can fail for the wrong
  reason.
- **A visually-hidden `<caption>` is body text until you hide it.** A table
  caption carrying the column names, not clipped at mobile widths, paints as a
  detached list of labels above every card. Assert its rendered box
  (`getBoundingClientRect()` plus display/visibility/opacity) — but assert
  **painted geometry**, never `innerText`, because the correctly-hidden caption
  is still in `innerText` and would then report a false failure.
- **`flex` + `space-between` detaches a label from its value** once the value is
  long, and an anonymous flex `::before` cannot be given a stable min-width. A
  two-column `display:grid` with `minmax(…,…)` keeps label and value on one row
  as a structural fact rather than an alignment accident.
- **Keep the field's own label even when you promote it to a card header.** If
  `WHEN` becomes the title row and you drop its label, a test that requires
  "every field has a visible label/value pair" fails — style it instead.
- **Prove the suite non-vacuous by re-injecting the defect**, then restore from
  a saved copy and re-verify the restore. A responsive-layout suite that cannot
  fail when the labels are removed is a suite that certifies a broken page.

## A flaky integrity check is worse than none

Comparing the production file's sha256 across a standalone suite run is
invalid whenever the live daemon is writing — it reports a false `FAIL` on a
perfectly read-only suite, and a check that cries wolf trains the reader to
ignore it. It also blames the suite for the daemon's activity.

- Pass silently when the hash is unchanged.
- When it changed **and the daemon is live**, attribute it to the daemon, say so
  in the output, and name the stopped-daemon battery as the authoritative A/B.
- **Fail hard if the hash changed with the daemon stopped** — that one case IS
  the suite's own write and must never be excused.
- Prove non-write **structurally**, since that cannot be fooled by a busy daemon:
  assert `db.execute_write(...)` is refused (`mode=ro` + `PRAGMA query_only=ON`).
  This is the assertion that actually survives concurrency.
- Never compare a value to itself to get a green row-count check; snapshot
  before the run and compare at the end.

## Guard against vacuous proofs

An empty planned-action list trivially "contains no forbidden action". Assert a
non-empty plan before claiming a security boundary holds. Likewise a mapper
that rejects everything passes every rejection test — prove productivity on
valid input, and prove every vocabulary id is reachable.
