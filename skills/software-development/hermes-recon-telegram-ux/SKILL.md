---
name: hermes-recon-telegram-ux
description: "Use when changing HERMES Telegram/notification rendering."
---

# Changing the HERMES Telegram layer

Telegram is the operator's only window into a system that runs unattended. It is
**read-only observability**: it may render, count, order and suppress. It may not
execute a job, mutate a decision/claim/verdict, promote a finding to confirmed,
override Jev, change scope or a rate limit, or add state. When a brief asks for a
UX improvement, the deliverable is *rendered text and its gates* — the predicates
behind those gates are the security surface and are not yours to widen.

Reference: `references/renderer-map.md` — which module owns which message class,
which tables are load-bearing, and which gate functions must stay byte-identical.

## Procedure

1. **Read the spec, then read the renderers.** Treat the approved spec as the
   contract; do not redesign it mid-implementation. Read the real renderer source
   before assuming a helper exists — helper names differ from their meaning
   (`window_label` returns a Tehran clock range, not a date).

2. **Enumerate the blast radius with grep before your first edit.** Existing
   suites assert on the *literal* strings of the renderer you are about to
   redesign:
   ```bash
   grep -rn "build_status\|build_pulse_text\|build_digest" scripts/ | grep -v day7
   grep -rln "🤖 HERMES STATUS\|📋 Queue\|🔎 Findings\|🖥 Resources" scripts/
   ```
   A suite that breaks purely because a message got shorter is a **baseline
   conflict, not a regression** — but you must have the pre-change result to say
   so. Capture the baseline before editing, and make sure the baseline harness
   is real: a suite that passes against an empty or wrong-schema fixture is a
   harness that cannot fail, and it turns a pre-existing break into a fabricated
   `NEW_REGRESSION` in your final gate.

3. **Back up the primary files** (`cp lib/status.py /tmp/bak_status.py`, same for
   `notify.py`, `activity_pulse.py`, `pdreport.py`) and record sha256 sums. The
   daemon runs the old code while you work; this is your rollback.

4. **Add constants, not new state.** Action levels, stage labels and mandatory
   disclaimer strings go in `lib/notify.py` at module scope. Mirror them in
   `lib/status.py` and `lib/activity_pulse.py` rather than importing across
   modules — `status` imports store/safety and `notify` imports `activity_pulse`,
   so a cross-import closes a cycle.

5. **One message, one formatting gate.** Route every new renderer through a
   single helper that appends timestamp + exactly one `ACTION:` line, so the
   visual contract cannot drift per class. Any function that can raise before
   defining a variable it later uses must initialise that variable in the
   `except` branch — an `import` inside `try` leaves the name unbound on failure.

6. **Enforce numeric budgets in code, not by eye.** If the spec says ≤20 lines,
   assert it immediately after building a sample and trim filler programmatically
   (blank separators first). A one-off `lines.append("")` between every section
   is what pushed a compliant design to 24 lines.

7. **Suppress without losing idempotency.** Suppression and exactly-once
   delivery are separate concerns: when a window renders to nothing, mark the
   window DELIVERED in the existing idempotency table and send nothing. Never
   leave a claimed window unconsumed — it will be re-claimed forever.

8. **Byte-identical periodic suppression** goes in the sender, keyed by message
   class, and must return success (cadence recorded) without sending. Event-driven
   messages keep their own dedup keys and must not be filtered here.

9. **Write patch scripts to a file, then run the file.** `write_file` to
   `/tmp/<name>.py` + `python3 /tmp/<name>.py`. Do not nest a heredoc containing
   quotes inside a tool-call string — the inner string literal breaks the outer
   one and you lose the run to a `SyntaxError`.

10. **Focused test, then existing Telegram/status suites, then the regression
    battery.** Compare every failing suite against the baseline from step 2 before
    labelling it NEW_REGRESSION.

11. **Integrity before and after:** `quick_check`, `integrity_check`,
    `foreign_key_check`, and a row-count audit on the renderer's tables
    (`alert_queue`, `activity_pulse_deliveries`, `pd_telegram_reports`). A
    renderer must produce zero write attempts — if a test hooks the connection to
    detect them, that check is the authoritative one, not row counts (live
    workers use their own connections and move counts on their own).

## Rules that keep the safety boundary intact

- **Gates are frozen; only text changes.** `register_*_alert()` predicates,
  `EVIDENCE_ALERT_REASONS`, exposure priorities, dedup keys and the
  `alert_queue` schema stay as they are. If a brief and a gate disagree, the gate
  wins and the conflict is reported.
- **A security signal needs a real gate.** Never derive one from a new finding, a
  High detection, a candidate, a hypothesis, a score, a CVE match, or "the
  Intelligence stage ran". An `EVIDENCE_SUPPORTS` outcome is a real signal and is
  still **not** a confirmation: a PENDING / NOT-HUMAN-CONFIRMED block is
  mandatory unless a human-verdict row genuinely exists.
- **A gate is only as good as the call that reaches it.** A pure
  `signal_allowed(...)` predicate is not the gate — the enqueueing wrapper is.
  When the wrapper's signature omits the rejection inputs, a caller bypasses the
  gate by simply not passing a reason, and the predicate's careful rejections
  never run. Mirror every rejection input onto the wrapper and forward it.
- **A bare `except Exception: return None` around an enqueue hides a dead gate.**
  A typo in a constant name (`SECURITY_KIND` where the module defines
  `EVIDENCE_KIND`) raised `NameError`, the except swallowed it, and the
  function returned `None` — which reads exactly like "the gate correctly
  rejected this". Every approved signal was silently dropped and the suite still
  showed green on the rejection checks. Prove the accept path reaches a real
  enqueue (assert an alert row with the disclaimer in its message), and narrow
  the except so a missing name fails loudly.
- **Rewriting a legacy assertion is a licence that needs its own proof.** When a
  suite fails purely because the layout changed, retargeting it is legitimate —
  but a rewritten assertion is weaker evidence than an untouched one. Assert the
  *invariant the check was protecting*, not a token from the new layout, and say
  in the report which suites you rewrote and how many checks that covered. Where
  the retired field still has a real source, assert it there instead
  (observability helper, digest, or the producing query).
- **Derive expected counts from the fixture; never leave them hardcoded.** Once
  the set of emitted messages becomes conditional, a literal expected total
  ("sent = 19") fails everywhere. Compute the expected set from the same
  predicate the renderer uses, then assert delivery accounting, idempotency and
  retry against *that* number — the invariants survive, the constant does not.
- **Counts are read, never inferred.** Confirmations come from the existing
  human-verdict fields; when zero, print zero. Detection volume and security
  value never share a sentence.
- **A correct matcher is not news.** A stage with zero matches/proposals/priority
  influence is suppressed from periodic messages and appears as one digest line.
- **Keeps a second copy as a fallback, not as compat.** Renaming the old
  renderer to `_<name>_verbose()` preserves *callers*; it does not preserve
  substring assertions in tests. Say so in the report rather than implying the
  old tests still pass.

## Reporting

The chat reply is a fixed block of counts only — never the report body. State
the final gate (`PASS` / `INCOMPLETE` / `FAILED`) and the zero-count architecture
limits honestly. If verification was refused or blocked mid-run, report the code as
unverified; an unverified implementation is not a pass, and saying so is cheaper
than a wrong PASS.
