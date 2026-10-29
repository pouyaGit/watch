# Human disposition of the HERMES pending-review backlog

Project root `/root/hermes-recon`; state DB `state/hermes.db` (no `sqlite3` CLI —
use `python3` + `lib/store.py:conn()`).

## The three queues that a "review everything" banner blurs together

| Queue | Table / predicate | Clears by |
|---|---|---|
| Unacknowledged findings | `findings` + `xss_candidates`, high/medium, `acked_at IS NULL` | `findings_state.ack_finding(id)` |
| Waiting cases | `hunt_cases.status = 'WAITING_HUMAN'` | a separate decision; **not** drained by ack |
| Judgement closures | `decision_closures.decision_state = 'HUMAN_REVIEW_REQUIRED'` | a separate decision; **not** drained by ack |

The status line renders the last two as `REVIEW — N case(s) await your decision`
(`lib/status.py:human_review_count()`), and the alert-recovery banner renders the
first as `N unacknowledged` (`lib/notify.py:alert_recovery()`). Both re-emit on
every daemon start, so the request repeats.

## Read before writing

`scripts/human_review_digest.py` (in-repo, read-only) prints both review queues with
reason, host, severity/confidence, evidence basis and age. Group before presenting:
waiting rows are routinely a handful of distinct fingerprints — 11 rows on one host
resolved to 3 distinct exposure ids.

Distinguish infrastructure-shaped entries from real judgement calls by reading the
reason text: a `case_reason` naming a provider outage (`JEV=..., LLM=...`) is a
downstream symptom of the outage, not a decision the queue is waiting on. Report the
split; it changes what the operator should do.

## The safe ordering: snapshot -> ack -> deterministic reclassify

1. Snapshot each row's prior `status`/`alert_status` to JSON before writing. Restoring
   from that file plus `acked_at = NULL` reverses the ack exactly.
2. Back up the DB with SQLite's own backup API. A plain `cp` of a live WAL database
   does not capture the WAL — see SKILL.md §4.
3. `ack_finding()` per id, then re-count. Quote the before count, the after count and
   the elapsed time: live producers add rows during the work.
4. Only then run the deterministic classifier, so its writes land on rows whose
   notification state is already settled and its outcome is unambiguous.

## Acknowledgement is NOT a verdict

`store.apply_classification()` guards only the `status` column: it leaves an existing
`ACKNOWLEDGED`/`VERIFYING`/`CONFIRMED`/`RESOLVED`/`DISMISSED` status alone, but writes
`confidence`, `severity`, `source_class`, `sink_class`, `classification` and
`classification_reason` unconditionally. Acking does not freeze the deterministic
verdict, and reclassify can move an acknowledged row LOW -> HIGH.

Always post-run check the cross-tab, and quote split states as evidence rather than
reading them as noise:

```sql
SELECT status, classification, COUNT(*) FROM xss_candidates
 GROUP BY status, classification ORDER BY 3 DESC;
```

## Run the classifier in dry-run JSON, and read the `fresh` counter

`reclassify_xss.py --dry-run --json` emits one object per row including `fresh`, which
is true only when `fresh_candidate()` found an archived `js_samples` body and re-ran
the real analyzer on it. All-false across every row means no JS was re-analyzed and
every verdict was recomputed from the stored columns.

The usual cause is a target-key shape mismatch between the two tables —
`xss_candidates.target` stores a glob scope (`*.wien.gv.at`) while `js_samples.target`
stores the bare slug (`wien`) — which degrades silently because the lookup is a
`LIKE` on `url` keyed by `target` equality. Confirm with a direct probe before
reporting the run as a clean re-analysis:

```python
c.execute("SELECT target,url FROM js_samples WHERE target=? AND url LIKE ?",
          (row["target"], f"%{row['js_file']}%")).fetchone()
```

Report a column-recompute honestly: "verdicts recomputed from stored columns, no
archived JS re-analyzed" is a different claim from "re-analyzed and unchanged", and
the join-key mismatch is a real defect worth naming in the report.

## Never bulk-confirm

Confirming asserts a human judged an artefact real. A bulk instruction over rows that
carry no verdict fabricates human attestation and violates the project's hard rule.
For a negative-version claim with `EVIDENCE_INSUFFICIENT`, the honest dispositions
are per-row judgement or leaving it queued — not an automated sweep, especially when
`unresolved_json` shows the basis hit `MAX_SUPPORTING_EVENTS` (the recorded basis is
truncated, so approving it approves an unread basis).
