# Observing a natural production cycle and measuring effectiveness

Use when a brief is observation-only: observe the running daemon, do not force a
cycle, and report whether an enabled capability actually changed the work
product. Capability-enablement milestones end this way — a subsystem was made
reachable, and the next question is whether being reachable mattered.

## 1. Reachability is not effectiveness

Three claims are separate and each needs its own evidence. Collapsing them is the
default failure mode of an effectiveness report:

| Claim | Evidence required |
|---|---|
| reachable | every branch selectable; a distribution over the FULL real population |
| consumed | a persisted lineage record naming the exact id + version + status |
| effective | the work product measurably improved because of it |

Retrieval, a routed case, a provider decision, and a created case are all
*reachability* evidence. None of them is effectiveness. A registry with N
approved entries, all retrievable, with a case created and a decision returned,
has still proved nothing about value.

**The metric that matters is the supporting-outcome counter, not the route
counter.** Ask what fraction of outcomes the capability is bound to landed on
`SUPPORTS` rather than weakening or staying inconclusive. A rising route count
with a flat zero in supporting outcomes is not progress.

**A rising specialist/branch share can be a regression in disguise.** If the new
routes are drawing work onto units whose governing premise is already
contradicted in persisted data, more specialist activity means more wasted
work. Check the outcome classification of the work the new routes actually
attracted, and say so if the increase is not buying evidence.

## 2. Do not force the window, and prove you did not

The brief will forbid injecting signals, resetting timers, manufacturing jobs, or
editing scheduler timestamps. Honouring that is half the job; the other half is
producing evidence that the event was natural:

- Anchor the baseline to a wall-clock cutoff, and use that cutoff as the query
  boundary for every "in the cycle" number.
- Show the daemon's own progress counter advanced across the window, and that
  the cycle's event timestamps fall inside it without your involvement.
- The unit's uptime/start timestamp must predate your observation, i.e. the
  process that produced the cycle was already running when you started. A cycle
  you triggered yourself by restarting the daemon is not natural.
- If no cycle arrives in the bounded window, `NOT_OBSERVED` is the deliverable.
  Do not stretch the window indefinitely and do not let the absence of a new row
  read as an implied success.

## 3. Capture lineage from the real event stream, ordered

Reconstruct the chain by walking the case's events in `sequence` order, not by
`created_at` alone — rows sharing a second interleave arbitrarily, and an
investigation that spans days has a long history of earlier attempts that will
otherwise be mistaken for the current cycle.

For each hop record the id, the timestamp, and the fields that carry the claim:
routing family, mission/required-evidence contract, execution-authority flag,
skill id + version + status + eligibility, decision source + provider status +
decision + next action + constraints, and the outcome classification with its
summary text.

A case that has been investigated across several days is itself evidence: the
same unit carrying the same family, then a different family after new recon, is
a genuine natural reroute. Quote the earlier hop and the current hop side by side.

## 4. Classify outcomes honestly and do not upgrade them

Sort every observed outcome into `SUPPORTS` / `WEAKENS` / `INCONCLUSIVE` /
`DUPLICATE` / `WAITING_HUMAN` and report the raw counts, including the zeros. A
run where all counts are zero in the category you hoped for is a finding, not a
reporting gap.

- Do not convert a weakening or inconclusive result into a failure of the system
  — the system behaving conservatively on thin evidence is correct.
- Do not convert one into a success either. "A case was created and a decision
  returned" is not a supporting outcome.
- When the consumer persists its own learning records, read the real status and
  sample band it wrote. `LOW_SAMPLE` / `INSUFFICIENT_EVIDENCE` on every record is
  the consumer correctly refusing to generalise from one observation — quote it
  as the system working, and do not treat it as a defect to fix.
- Do not modify any definition, threshold, or policy on the basis of one noisy
  observation, even when the observation is unflattering.

## 4a. Answer "did it change anything?" with a with/without A-B probe, not by reading code

Observing outcomes tells you the capability *coexisted* with the work. It cannot
tell you the capability *caused* it. When the question is whether an enabled
capability actually shaped the product, build the same artifact twice and diff:

- Build it once with the capability active, once with the capability suppressed
  (monkeypatch the retrieval/lookup to return `[]`, pass the dependency as
  `None` — do not edit production code to get the "off" arm).
- Diff the full work product: for a knowledge/skill/knowledge-base capability
  that means the hypothesis text, the plan objective, the allowed action list,
  the evidence requirements — every field the capability could plausibly shape.
- Report the ratio: `byte-identical N of N` is a positive finding about
  inertness. A probe that reports `compared 25, identical 0, differing 0`
  compared **nothing** — every build was skipped; print the skip reason and the
  count of comparable builds, and treat "zero comparable" as a broken probe,
  not as a result.

Three independent confirmations make an inertness finding trustworthy: the A-B
diff, a source scan for the capability's content fields at the construction
site, and reading what the production caller actually forwards. The wiring scan
is the one that names the mechanism: `skill_ctx = {"skill_id", "skill_version",
"status"}` forwarded to the decision layer means only attribution travels,
regardless of how rich the stored content is.

### A plan that differs is not a decision that differs

`BASE != GUIDED` proves the capability reaches the ARTIFACT it targets. It does
not prove the artifact reaches the DECISION. Before reporting a capability
"integrated" and stopping, read the consumer's decision function and ask which
fields it actually reads.

- **Count token references inside the consumer to the fields your bridge
  populates.** A classifier containing `plan` eight times but `evidence_needed`
  zero times cannot be influenced by changing `evidence_needed` — it inspects
  the plan's own metadata, never the guidance inside it. A source scan of the
  CONSTRUCTION site proves the producer; a source scan of the CONSUMER proves
  reachability, and that is the one that can come back zero.
- **Find the short-circuit rule.** A rule-ordered policy (`P1`..`Pn`) evaluated
  top-down means a rule firing on almost every row makes every later rule
  unreachable. Count which rule decided every persisted outcome (read
  `provenance`/`rule` on the records, not the outcome label). "One rule decided
  100% of all N outcomes ever recorded" is the finding — the outcome label makes
  it look like a property of the work rather than of the policy ORDER.
- **Quantify the short-circuit's population** (rows with the triggering condition
  / total rows). A rule firing on 56% of rows and sitting above the
  corroboration rule is the mechanism behind a flat outcome distribution.
- Then report the split. The counterfactual is the proof: same signal, same
  target, same evidence state, same constraints, only the capability differs —
  `plans that DIFFER 12/12` beside `outcomes IDENTICAL 12/12` is a structural
  null, and no further sampling moves it while the consumer is unchanged.
- **Read the rule's own condition before calling it a defect.** A rule firing on
  every row may be CORRECT (those premises really are contradicted) rather than
  masking the capability. Present the two readings — "the policy is right and
  the capability is irrelevant here" vs "the policy masks the capability" — as
  an architectural question for a human, and do NOT wire the capability into the
  decision path to produce a better number. That is tuning production behaviour
  to improve a measured metric.
- **A downstream record's own counts can be pre-capability.** A learning row that
  cites the capability's id but predates the era it was enabled in measures
  nothing about it. Slice every count by the capability's live-at timestamp and
  report the pre/post split; "NOT ENOUGH DATA" is the honest cell when the only
  rows are historical.

**Name the null precisely.** Three verdicts are not interchangeable, and a
structural null is not a small sample:

| Verdict | When |
|---|---|
| `INSUFFICIENT_SAMPLE` | too few observations to separate anything |
| `NO_MEASURED_EFFECT` | the consumer provably does not read the field; equal regardless of sample size |
| `NEGATIVE_SIGNAL` | repeated observations show the capability producing harmful work |

Reporting `INSUFFICIENT_SAMPLE` for a structural null understates the result and
invites another observation window that will reach the same answer. Reporting
`NEGATIVE_SIGNAL` overstates it — nothing showed harm. Check the wiring first;
the wiring decides which of the three applies.

**Split performance attribution.** When a milestone adds a bridge, report the
new component's isolated cost AND the end-to-end delta, and label which part is
pre-existing. An end-to-end delta that is mostly the consumer's own DB work is
not the milestone's cost. Time the isolated component over many iterations (mean
of N calls) and never attribute pre-existing retrieval or query cost to the
change under measurement.

**Inertness and breakage are different findings.** "The capability is attached
and correctly gated, but its content never reaches the work product" is a
design gap to report to a human. "The capability is unreachable" is a defect to
fix. Check the attachment/gating path before concluding anything, and when both
are true say both.

### Isolate the probe from production without losing real signal

An A-B arm that needs the authority boundary to verify *real* persisted rows
will reject synthetic fixtures ("signal reference does not exist"). Snapshot
with SQLite's own backup API and point the store at the copy, using the
project's own convention for redirecting it — set the env var and the module
attributes the store module actually reads, *before* importing consumers:

```python
TMP = tempfile.TemporaryDirectory(prefix='probe_')
DB = Path(TMP.name) / 'hermes.db'
os.environ['HERMES_DB'] = str(DB)
import store
store.BASE = TMP.name
store.DB = str(DB)
src = sqlite3.connect('file:%s/state/hermes.db?mode=ro' % BASE, uri=True)
dst = sqlite3.connect(str(DB)); src.backup(dst); dst.close()
```

Open production `mode=ro` for reading real registry rows and real signals. Copy
the fixture convention out of an existing test in the repo rather than inventing
one — a module may re-derive its DB path from env at import.

### Freeze a negative finding as a test

When the measurement is "this is how the system behaves", freeze it so a later
change is a visible, intentional diff instead of silent drift. The test asserts
the observed behaviour and says in a comment that the observation is a finding,
not an endorsement. A future agent wiring the capability in then gets a red
suite and a conversation, rather than a silent improvement nobody notices.

## 4b. Sample count is not independent-condition count

Eight samples drawn from three underlying conditions are three observations
wearing eight hats. Report both numbers, and dedupe by the condition the
investigation actually evaluates (host, product premise, resolved decision) when
reporting "N samples".

Before committing to an observation window, **measure the natural cadence from
the job table** (`SELECT created_at FROM jobs WHERE job_type='investigation_run'
ORDER BY created_at DESC`) and compute how long the target sample actually
needs. A ~3h03m cadence means a 10-sample target needs hours, not one sitting.
Reporting the arithmetic up front is better than reporting a window that was
never going to reach the count.

Distinguish a cycle that produced new samples from one that re-decided old
ones. Re-decisions write `decision` events for cases that already carry lineage
and mint **no** new capability-consumption records, so a cycle firing on schedule
can still deliver zero samples. Check for the new lineage records, not the
decision count.

## 5. Small samples get a small-sample verdict

A sample that cannot separate "helped" from "did nothing" must be reported as
`INSUFFICIENT_SAMPLE`, with the required count spelled out. This is a valid,
expected outcome of an observation milestone — say it in the first screen of the
report, not in a limitations appendix, because it is the headline finding.

Distinguish the two verdicts the operator needs, which can legitimately disagree:
whether the system is healthy enough to keep running (`READY FOR PRODUCTION`)
and whether there is enough evidence to advance the program's claims
(`READY FOR NEXT STAGE`). A healthy system with unproven effectiveness is the
common and legitimate end state, and pairing `YES` with `NO` is more informative
than a single blended verdict.

## 6. Observation must not change what it observes

- Freeze the semantic fingerprint at the baseline and diff it at the end. Assert
  on invariants, schema hash, and protected per-table counts; raw file hashes of a
  live WAL database are not stable (§4 of the parent skill).
- Attribute every delta. A table that grew is either the natural consequence of
  the cycle (name it) or churn you caused (say so). A registry the milestone is
  supposed to leave alone must be byte-stable: same count, same status
  distribution, same distinct content hashes, same version count.
- Enumerate unsafe job/action classes created in the window by name, and report
  the empty list as the safety result. A positive finding there outranks every
  other section of the report.
- Confirm the human gate held: queue size before vs after, zero new
  auto-resolutions, zero `HUMAN_CONFIRMED` written by anything other than a
  recorded human action. A decision whose `next_action` is human review is a
  correct terminal state, not an unfinished one.

## 7. Pitfalls specific to this work

- **Guessed schema names in throwaway analysis scripts.** The rule in §4 of the
  parent skill is about test fixtures; the same trap hits every ad-hoc capture
  script. Take one `PRAGMA table_info` pass over every table the script touches
  before writing queries. Event/lineage tables commonly use
  `event_id`/`sequence`/`object_type` and store the payload in a JSON
  `metadata` column; provider-request tables commonly use `request_id`,
  `state`, `provider_status`, and a payload column. Queue/config/target tables
  frequently do not exist under the obvious name at all — look the name up
  instead of assuming, and prefer listing candidate tables by `LIKE` when you
  are unsure.
- **The regression battery stops the service.** It does so deliberately, to get a
  clean window, and restarts it at the end. So a start timestamp that moved
  during your milestone, or a unit found `inactive (dead)` between phases, may be
  the harness rather than a crash. Check the battery script for `systemctl stop`
  before attributing either to a regression, and confirm the unit is `active`
  with `NRestarts=0` before the final report.
- **A stale log line explains nothing.** A scary traceback in a long-lived log
  file may predate the milestone by days; check the file mtime and the entry's
  own timestamp.
- **Do not invoke the fallback provider to prove the fallback works.** If the
  primary resolved every decision, record `NOT_USED` with the reason and report
  the fallback's availability from the earlier bounded validation. Invoking a
  paid or metered path to produce a nicer report is manufacturing evidence.
- **Each suite prints a different summary line.** A loop that greps one fixed
  `RESULT x y` shape silently records `NO_SUMMARY` for a suite that actually
  passed. When a focused run reports no summary, read that suite's own tail and
  exit code before recording a result for it.
