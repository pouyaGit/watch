# Verifying a bounded active-probe lane

A lane that sends crafted requests and writes evidence rows. Verifying it means four
separate verdicts, and they are routinely confused with each other:

| verdict | question | evidence |
|---|---|---|
| GATE | does the guarded property actually get exercised? | the dependency patched at source, not injected |
| INERT | does it send nothing while unarmed? | arming flag absent from the unit AND the live process env; 0 rows; no ledger file |
| WIRED | can it ever run? | job type in `scheduler.JOB_CLASS`, in `RESERVED_JOB_TYPES`, a budget entry, a planner cadence trio, an executor, validator classifier entries |
| RAN | did it run, and what did it do? | the job row's status/error + `poc_verify_runs.summary_json` reconciled against the lane ledger |

A lane can be INERT and unwired and still "implemented". Report which of the four you
actually established, and never let one stand in for another.

## Exercise the real request path

The lane wraps `crawler.fetch_one` in its own closure that builds the rate limiter and
health objects, and passes it into `run()`. A test that calls `run(fetch=fake)` replaces
that closure and never executes it — a suite can pass while every sweep dies on the
first request.

```python
calls = []
def fake_fetch_one(url, target, limiter=None, health=None, robots=None,
                   extra_headers=None):
    calls.append({"limiter": limiter, "health": health})
    return {"url": url, "status": 200, "headers": {}, "body": "...",
            "ctype": "text/html", "binary": False, "error": "",
            "out_of_scope_redirect": ""}

orig = crawler.fetch_one
crawler.fetch_one = fake_fetch_one
```

Match the real signature exactly, including keyword names — a mismatch raises
`TypeError` inside the closure and reads as a lane bug. Then assert the collaborator was
constructed (`limiter is not None and health is not None`), because that is the line
the injected-dependency test could never reach.

## Traffic-free by construction

Selection is usually built from STORED data (`http_samples`, `pd_dns_observations`), so
building the worklist sends nothing. Keep it that way: feed every probe from a fixture
and assert the per-run accounting invariant instead of a network effect —

    probed == written == ledger lines == rows for this run

A run killed at the job timeout must keep what it already wrote, which is exactly what
that invariant catches (a lane that persists only after its loop fails it).

## Measure an acceptance criterion against real data

When a criterion is a count over production ("resolvable > 0", "N hosts covered"):

- Prefer the pipeline's OWN populated field over recomputing it. A selector that
already returns `resolved`, `page_url` or `probe_url` is the authority; rebuilding the
fact from raw tables is how a measurement drifts from what the lane will really do.
- Print the row keys first (`sorted(row.keys())`) and read the real signatures before
  calling (`build_page_index(c, rows)` vs `_get_candidates(c)`). A swallowed `TypeError`
  inside a guard clause turns a call-shape mistake into a confident zero.
- Reconcile against a second source: a module-level counter, a stored `summary_json`, a
  row field. Disagreement means one of them measures something else.

Counter shape: `_LANE_STATS` (per-outcome counters) and `_PAGE_*` caches are the cheap,
already-populated signals for "did the lane get anywhere".

## Confirming a lane is armed and running

```bash
# unit carries the flag?
grep -cE "HERMES_AD_<LANE>" /root/.config/systemd/user/hermes-recon.service
tr '\0' '\n' < /proc/$(systemctl --user show hermes-recon -p MainPID --value)/environ \
  | grep -E "HERMES_AD_|HERMES_ACTIVE_DISCOVERY_ENABLED" | sort
```

Grep the live environ by FULL variable names. A pattern like `HERMES_AD_` silently omits
`HERMES_DOM_XSS_ENABLED`, and the resulting "the flag vanished" is a grep artifact, not a
finding.

A process env is fixed at exec time: adding a line to the unit does nothing until
`systemctl --user daemon-reload && systemctl --user restart`. Confirm both sides — the
file and the running process — and re-read the module from the daemon's own interpreter.

## Arming is the operator's action

The module must REFUSE a live run while unarmed, and `live` without `apply` must be
refused so no request is ever sent that is not recorded. Implement the flag; add it to
the unit only when the operator says so. When you do arm it, back the unit up first, add
the flag with a comment naming what it probes and how to disarm, and verify the diff
against the backup is exactly the added lines.

A lane that runs an external binary additionally trips the added-execution hard rule by
design. That block IS the operator's authorization gate for sending requests — but it is
theirs to CLEAR, not merely to hand over. When they clear it, follow the manual-pass
protocol: review the bounds yourself, commit a written review record (the flag records
nothing about a human reading the code), then run the pass and require
`HARD RULES: 0` + `DEPLOYED`. Gate pass and arming are two separate decisions — see
`references/hard-rule-manual-pass.md`.

## A lane can be armed and still never run

Before reporting a lane as armed, establish WHICH path it runs on. A daemon lane needs a
job type the planner enqueues; a scanner-style lane often has NO job type at all and runs
from its own `hermes-active-discovery-<tool>.service` + `.timer` pair, imported by no
service — there, a flag in the unit changes nothing. Find the sibling service as the
template, copy its shape, and enable the timer. `OnBootSec` is relative to boot, so
enabling on a long-running host fires immediately: expect a real run at once and watch it
to completion rather than assuming it will happen later.
