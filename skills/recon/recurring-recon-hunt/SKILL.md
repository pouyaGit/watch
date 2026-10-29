---
name: recurring-recon-hunt
description: Use when hunting fresh recon data on a schedule.
---

# Recurring hunt over fresh recon data

A scheduled job - or an operator asking "run today's hunt" - that reads a recon data store for
records collected since the last run, tests a bounded shortlist in scope, and reports only what it
proved. The store is the producer; this is the consumer side.

**It is ACTIVE where a recon daemon is passive.** This loop sends probes to in-scope hosts, so the
scope gate and the rate ceiling apply to every request it makes. Contrast: `autonomous-recon-agent`
builds a 24/7 *producer* whose rule is to send no detection payloads at all. Do not carry the
producer's passive-only rule here, and do not carry this skill's active probes into a
passive-only deployment.

## Standing rules: put them on disk and read them first

The operator's rules must exist as files the run reads at the start of every invocation and as
files the job prompt only POINTS at. One file per concern, in a directory that is NOT the project
tree:

```
/opt/<project>-agent-rules.md      where code may be written; what is read-only
/opt/<project>-capabilities.md     what the agent may use, and what is banned outright
/opt/<project>-reporting-rule.md   what becomes a report, and how it is delivered
/opt/<project>-scope.json          in-scope domains plus an explicit out-of-scope list
```

Why files: they survive prompt edits, the operator can correct one concern without touching the
schedule, and a later session can diff declared behaviour against actual behaviour.

### Never write inside a project you do not own

Default: the project tree is READ-ONLY. Code, scratch, fixtures, baselines, state and logs go one
level back, in `/opt`. The only thing permitted inside the project is the report:

```
/opt/<project>/reports/<name>.md      permitted
/opt/<project>/<anything else>        violation
```

Mechanism: keep a baseline of the tree and diff against it, recording paths, sizes and mtimes only -
never contents - and exit non-zero when a path outside `reports/` appeared. Two behaviours make the
check usable instead of noise:

- **Track dotfiles.** Skipping `.`-prefixed names hides `.env`, which is exactly the file an agent
  adds by accident.
- **Classify the running system's own output separately.** A live pipeline legitimately writes logs,
  crawl output and a database under the project every minute; counting those as violations makes the
  check red always, and an always-red check gets ignored. Report three buckets - *permitted*
  (reports), *runtime* (the pipeline's own writes), *violations* (the agent's writes). Only the
  third is a failure.

## The loop

1. **Read the rule files and the scope list.** If any is missing, say so and stop.
2. **Collect.** Run the collector: it reads the store, writes a shortlist, and prints a compact
   brief. If it errors, report the error and stop - never synthesise records to fill a thin window.
3. **Select a bounded shortlist.** Cap it (order of 30 per run). Few and deep beats many and
   shallow: a run that touches thousands of endpoints proves nothing about any of them. **Enforce
   the cap where the list is produced, not in the prompt** - a bound that exists only as prose is a
   suggestion: a run told "max 30" examined 65 and disclosed the breach itself. The collector
   truncates; the prompt only explains why.

   **Measure the final run against its declared cap.** A convincing report with a "two times the
   brief" footnote is a run whose endpoint count was never bounded, and the next run repeats it.
4. **Probe, in scope, under the ceiling.** One shared token bucket for the whole run. No port
   scanning, no accounts, no scope widening.
5. **Judge each candidate against the honesty gates below.**
6. **Write**: proven + in-scope + reportable to a report; everything else to an evidence note
   labelled "not a report".
7. **Deliver the report as a FILE** (see below).

Store schema, how to define the window, and the collector design:
`references/fresh-data-window.md`.

## Honesty gates before any verdict

- **A positive verdict needs a 2xx, a non-empty body, and not an edge challenge.** A marker present
  in a deny/WAF page is not a reflection; a zero-byte `200` is not an exposure.
- **A negative verdict must name scheme, port and vantage.** "No response", "status 0" and timeouts
  are statements about the probe. Write `UNREACHABLE-FROM-<vantage>` or `NAMES-DO-NOT-RESOLVE`,
  never "no exposure".
- **An edge challenge is not the application.** Cloudflare / Imperva / Akamai pages mean
  `EDGE-BLOCKED-APPLICATION-NOT-REACHED`.
- **Prove the comparator is stable before comparing.** One sample per side reports transitions that
  never happened, and a per-response token makes a hash comparison pure noise.
- **A reachable host is not a changed host.** A change-log row is a lead; re-measure the host before
  turning it into a verdict.
- **"Nothing found" is not a report.** It is an evidence note carrying the measured negatives.

## Report or evidence note

```
proven + in-scope + reportable      reports/<date>-<host>-<class>.md
Informational / primitive           evidence/NOTE-<topic>.md   ("not a report")
public-by-design                    evidence/NOTE-<topic>.md
uncertain / session-gated           evidence/NOTE-<topic>.md
measured negative                   evidence/NOTE-<topic>.md
```

A report carries: a summary, the real commands with their output, evidence (status, size, hash,
response excerpt), impact **including its ceiling** ("zero write access - every scope grants only
pull, tested"), the scope justification, and what was NOT tested. A section stating only the lower
bound of the impact overstates the finding.

## Delivery is part of the contract

Every report is sent to the operator as an attachment in the same run that wrote it -
`MEDIA:<absolute path>` in the final response. Not a summary instead of the file, not a path, not
"it is in `reports/`". A report the operator has to go looking for was not delivered.

End every run with the fixed shape: window, candidates examined, reports written, non-reportable
findings with one-line verdicts, and a one-line conclusion.

## Wiring it to a schedule

- **Continuity on**, so each run sees its own previous output: that is what lets the window be
  "since the last run" instead of a fixed lookback, and what keeps the run from re-reporting the
  same candidates.
- **Deliver to the operator's chat**, with the final response carrying the `MEDIA:` lines.
- **Validate every enum-shaped field against the code's own validator before trusting it** - a
  create call echoing your input confirms storage, not validity, and a toolset name one character
  from the real one stores fine and then runs without those tools.
- **Restrict the enabled toolsets** to what the run uses; it also cuts prompt cost.
- **Fire it once before its first natural schedule**, with a transient prompt that forbids side
  effects (no requests to targets, no writes). A valid schedule and working plumbing are different
  claims.
- Keep the durable rules in the files above and the prompt to the procedure plus a pointer to them.

## Pitfalls

- **A crawler's store is not a vetted target list.** Fresh records include internal-only names, CDN
  defaults and wildcard noise. Filtering them silently hides a real member; filter if you must, but
  count and report the filtered class.
- **A "new record" flag can be nearly the whole table.** Before using a change collection as the
  freshness signal, measure its distribution - an event type present for essentially every row
  carries no change information.
- **Rank on structured fields, not on free text.** Ranking by substrings of a URL path ranks junk:
  percent-encoded multilingual paths and CDN asset URLs contain the letters of the keywords being
  matched. Rank on parameter NAMES.
- **Match parameter names by set membership, not substring.** Short names match inside longer ones,
  so nearly every candidate scores and the ordering stops discriminating.
- **Re-read the ranking output after every change to it** - print the top N with full path and
  params. A ranker that reads correctly in source can still put a junk row first.
- **A stale count in a note is a wrong number.** Corpus counts drift; quote them with the time they
  were taken, or not at all.
- **Never widen scope to make a category hold.** A finding out of scope is not a finding, whatever
  its impact.
- **A dry run that shares the live state file consumes the window the real run was waiting for.** A
  manual invocation persisted its completion time to the same pointer the schedule reads, so the
  next natural run saw a two-minute window and reported a clean zero in every class. Give manual and
  scheduled runs separate state (or have the manual path not persist at all), and when a run reports
  a suspiciously thin window, read the recorded last-run time before believing the store is quiet.
- **Follow a resolution chain past its first hop before calling it first-party.** A host's CNAME
  pointed at the organisation's own domain, so a third-party-vendor classifier scored it clean - the
  next hop resolved into a public cloud provider's traffic manager. Judge a takeover candidate on the
  whole chain and on who ANSWERS, never on the first label alone.
