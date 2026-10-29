# Clearing a hard-rule block: the manual-pass protocol

`ci_gate` hard rules read TEXT, so they fire on legitimate code as well as on real
risk. Two categories exist and they get different treatment.

## Diff-SHAPE artifacts — fix the code, never the gate

A guard that appears as a REMOVED line (pure re-indentation, wrapping a loop that
contains a scope check in `try/finally`) and a dynamic-execution word re-typed as a
data literal (`eval` inside a sink-name set) are both false positives. Fix the SHAPE:
keep the block at its original indentation and move the new work into a helper; derive
the set from the existing constant instead of spelling the word. Verify mechanically
before committing (regex the added lines, assert no removed line names a guard
keyword). Never reach for `--allow-manual` here, and never edit the rule.

## Genuine added-execution hits — the block IS the authorization gate

A new module that spawns an external binary (a scanner executor) trips
`adds execution capability (os.system/subprocess/eval)` by design. The gate is the
operator's conscious authorization for active requests against a live target. When the
operator authorizes it, the protocol is three steps, and the first two are not optional:

1. **Review the code yourself, line by line, and be able to state the bounds.** Write
   down what you verified: request method, one target per invocation, the fixed list,
   absence of the fan-out flags, rate/concurrency/timeout flags, scope validation
   ordering, whether bodies are read, how the tool's share of the global rate lease is
   taken, and that no user-controlled string reaches a shell.
2. **Author and COMMIT the review record.** This is the step that is easy to skip and
   it matters: `--allow-manual` only downgrades the hit to a warning — the flag records
   NOTHING about a human having read the file. Without a committed record, the next
   reader sees a passed gate and no evidence. Put the record under `reports/dev/`,
   commit it as its own docs commit, and point the new unit's `Documentation=` at it so
   the unit and the review are linked.
3. **Run the pass and read the outcome** —
   `python3 scripts/ci_gate.py --sha HEAD --allow-manual`; require
   `HARD RULES: 0 hit(s)` and `DEPLOYED` and the suites green.

Then arm separately. The gate pass authorizes the code; `HERMES_AD_<TOOL>=1` authorizes
sending requests, and it is its own operator decision. Keep the two decisions distinct
in the record and in the unit comment.

Do NOT weaken the rule, do NOT edit the regex, and do NOT treat the pass as a
formality: if you cannot state the bounds of what the new code will send, the answer is
not "pass it" but "this needs the operator's review".
