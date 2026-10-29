# Diagnosing a pipeline that reports zero output

For the class of question "X is enabled / configured / scheduled, but the
downstream artifact count is 0". The trap is that every obvious knob looks
correct, so the investigation wanders into config instead of the queue.

## Read the counter's own table, not the counter

A stage counter reading 0 is a symptom. The rows it counts usually exist in a
neighbouring state. Enumerate the state distribution of the target table before
concluding the stage never ran:

```sql
SELECT state, COUNT(*) FROM <target> GROUP BY state;
```

A non-empty neighbouring state (`*_REVIEW_REQUIRED`, `*_QUARANTINED`) is the
finding, and its `reason` column names the exact gate. Then check whether that
state has a **drain**: no verdict column and no queued alert means a row parked
there is permanent. Unreachability, not the counter, is the defect.

## The retry pool is where a healthy feed starves

Signature: upstream rows are all `OK`, ingest counters are non-zero or the feed
is fine, yet the newest run produced 0 new items and ended in a degraded state.

A selector that takes "the oldest item not yet exhausted" drains one item per
run when every selected item fails at the same downstream step. After N runs the
pool is empty and every later run is a no-op that still reports an attempt:

```
run N   -> oldest non-exhausted -> downstream failure -> mark exhausted
run N+1 -> next oldest          -> downstream failure -> mark exhausted
...
run N+k -> pool empty           -> "consecutive transport failures - ending PARTIAL"
```

**Diagnostic tells:**
- Failure timestamps in the pool land **exactly one per run period**, evenly
  spaced. Natural upstream decay is irregular; one-per-cadence is a self-inflicted
  loop.
- The run's aggregate error is a *summary* ("N consecutive transport failures"),
  while the per-item error carries the real class. Read the per-item table.
- Check the exhausted flag explicitly. A pool where every row is exhausted is a
  pool with no input, which looks identical to "nothing to do".

**The fix is not a bigger pool or more sources.** It is either restoring the
downstream step the pool is failing on, or giving the selector a floor so an
exhausted pool produces a visible no-op instead of a silent zero. Say which.

## Error text in a long-lived table is a claim about the past

A `last_error` / `errors` row persists. Two rows in the same table can disagree
because one was written when the defect was different.

- Date the error before adopting it: compare the row's timestamp against the
  most recent run. A cached `KeyError` that stopped being raised days ago will
  happily reappear in every search and send you after a fixed bug.
- Prove the live path separately: if the in-code registry/table is complete
  (`10/10 entries, 0 missing keys`), the cached error is not the current cause.
- Prefer the run-scoped error table for "what failed this time" and the
  health/registry table for "what is configured".

## Check the schema before you write the query

Literal SQL from a brief or a memory is usually right in shape and wrong in
column names. One `PRAGMA table_info(<t>)` per table is cheaper than a failed
run, and both failures look the same in the output:

```sql
SELECT * FROM t LIMIT 0;  -- or PRAGMA table_info(t)
```

Small-key tables are routinely `k`/`v`, not `key`/`value`, and an `enabled` or
`cooldown_s` column frequently does not exist at all — the value may live only
in the in-code registry. When a query filters on a column that is not there, the
honest report says the column is absent, not that the value is empty.

## A keyword gate over prose is a false-negative machine

A downstream stage can be parked by a matcher that reads free text written by a
model. Read the gate's pattern, then run it against the real persisted rows
before theorising — the blocking reason column usually names which condition
failed, and the loser is often the one you would not have guessed.

The tell that the gate is inverted:

- The pattern is a **positive** test for a property ("limitations contain this
  disclaimer phrase") and the failure mode is a parked row.
- The rows that fail say something **more** hedged than the pattern looks for.
  A list of synonyms cannot enumerate how a model expresses caution, so a
  reasonable phrasing is silently treated as non-compliant.
- The gate has **no drain**: no verdict column, no alert, no re-queue. A row that
  lands there is permanent and invisible, and the upstream counter stays 0
  forever with nothing in the logs to explain it.

Verify before changing anything: take the persisted field, run the production
regex over it directly, and print the match or the explicit no-match. That one
call distinguishes "the gate rejected these" from "the gate never ran" and turns
a counter mystery into a single named condition.

When reversing such a gate, prefer **inverting the default** — accept unless an
explicit overclaim is present — over growing the synonym list, because an
enumeration is the mechanism that produced the miss and will produce the next
one. Whichever way it goes, add the drain: a verdict column plus an enqueued
alert, so a row that genuinely should stay parked is a decision someone can see
and clear rather than a permanent silent loss.

## Sequence a fix chain against its verification

When a brief asks for several fixes whose final step must be demonstrated
end-to-end, check that the final step is reachable **before** starting. If the
upstream that produces the input is broken, the honest move is:

1. Deliver the diagnosis for the upstream blocker with measurements.
2. State which of the requested fixes you can prove offline right now, and which
   you cannot prove at all until the blocker clears.
3. Offer the sequencing options and let the operator choose.

Doing the reachable half and reporting it as done converts one honest blocker
into a half-verified fix plus a hidden failure. Fixing the blocker first is
usually the shorter path, and it is the one that ends with the requested
artifact actually existing.
