# Verification anti-patterns: comparators, labels, and false greens

Depth for the rules referenced from SKILL.md. Load this when a verification
result depends on a COMPARISON (two arms, two runs, two numbers), when a
verdict label was assigned to a host/file/run, or when a green suite is the only
thing standing between a guess and a report.

## Comparators: prove stability before the verdict

Three verdicts were issued and withdrawn in one round, all by one mechanism: a
comparator was trusted before it was shown to be stable.

* An arm compared body hashes on a page that renders a per-request nonce, so
every arm "differed" and 8 hosts were reported as parameter-sensitive. The
group returned 298/298/298/298 bytes with four different hashes — pure jitter.
* A comparison held the parameter NAME and the VALUE both different, so a
difference could not be attributed to either.
* A label named an event ("backend switch") that had not happened on 7 of 8
  hosts, because the condition was tested on the arm of interest only.

Order, non-negotiable:

1. send the identical request N times and require an identical response, PER ARM;
2. isolate ONE variable between arms (`?goto=<url>` vs `?zqrandom=<url>` — same
   value, only the name differs);
3. compare arms by set disjointness, not by one sample;
4. read the BODY, not its length — two lengths can mean two servers, and a stock
   default page (nginx welcome / "It works!" / IIS / "Test Page for the") means
   the application was never reached.

An arm that is not internally stable leaves the host **unjudged**, not clean.
When a later measurement contradicts an earlier verdict, withdraw the verdict in
writing. The withdrawal is the evidence that the method was checked.

## Labels: assert what the name implies, across ALL arms

A class name is a claim. Before accepting it, assert the condition the name
implies over every arm, not just the interesting one:

```python
# WRONG - names a switch that may never have happened
probe_is_default
# RIGHT - "switched" requires a baseline that was NOT default
not base_is_default and probe_is_default
# and "always served a stock page" is a DIFFERENT observation
all(arm_is_default for arm in base + control + probe)
```

That single change separated 7 hosts that had always served a default page from
the 1 host that genuinely switched — a label that would otherwise have described
an event that never occurred.

## Absent keys are not zeros

A `Counter` omits classes with no members, so `tally.get("X") == 0` fails for a
bookkeeping reason, and `.get("X", 0)` turns that failure into a fabricated
pass. Assert against the population that is always present — the record list:

```python
check("no case carries verdict X",
      sum(1 for c in cases if c["verdict"] == "X") == 0)
```

## Phrase-presence assertions certify sentences, not truth

`has("the reason we withdrew this verdict")` proves the sentence EXISTS. In one
round a note explained a withdrawal with a fact the artifacts contradicted — the
two runs it claimed disagreed had returned byte-identical responses — and the
suite stayed green because substring presence was the only assertion on that
paragraph.

When a note states a REASON, CAUSE, or COMPARISON, derive the assertion from the
artifacts and assert the RELATIONSHIP, plus a negative guard so the retracted
wording cannot return:

```python
s2 = {(c["status"], c["len"]) for c in art2 if c["label"] == "no-param"}
s3 = {(r["status"], r["len"]) for r in art3 if r["label"] == "no-query"}
check("the two runs agree on the bare url", s2 == s3 and s2 == {(200, 52)})
check("note does not make the retracted claim", not has("<retracted wording>"))
```

A green suite over a false rationale is worse than a red one: it converts a guess
into evidence, and the note is what the client reads.

## Aborts must not exit 0

A run that tested nothing returned `EXIT=0`. The listener had issued zero
payloads (a TLD regex matched nothing), the script printed the reason and
returned from `main()`, so to the process supervisor it looked exactly like a
clean run with a clean result. The only trace was one line of log output.

```
payloads not issued   -> sys.exit(2)
listener not proven   -> sys.exit(3)
EXIT=0                -> the phase produced a verdict it stands behind
```

Pair the code with a verifier assertion that the artifact carries no `aborted`
key, so a silent abort cannot be mistaken for a result even if someone re-reads
only the JSON. A non-result that reports success is worse than a failure,
because it gets filed as evidence.

## Superseded harness scripts need a refusal, not a comment

When a phase is replaced because its METHOD was defective, the old script stays
on disk with the defect intact and nothing stops a later session from re-running
it and reproducing the exact failure it was replaced for:

```python
if __name__ == "__main__" and not os.environ.get("ALLOW_SUPERSEDED"):
    sys.stderr.write("SUPERSEDED - refusing to run. Use <replacement>. "
                     "Set ALLOW_SUPERSEDED=1 only to reproduce the original fault.\n")
    sys.exit(3)
```

Leave the original body untouched as the record of what went wrong. Before adding
the guard, grep the verifier tree for the old path — a verifier that imports a
guarded script turns a green suite red for a reason unrelated to the target.

## An installable blocker is not a blocker

Do not close a phase by telling the user which tool to install so the measurement
can be finished. If the missing piece is a binary, a package, or a listener you
can install yourself (`go install ...@latest`, `pip install`, a venv), install it
and finish the measurement in the same turn, then report the result together with
that instrument's own non-vacuity control.

Handing back a prerequisite moves the work onto the user and leaves the phase
reported as "could not be verified" — a weaker outcome than a real negative, and
one the user reads as an excuse. Reserve "blocked" for what genuinely needs a
decision, a credential, or a scope change only the owner can grant.

## Verdict scaffolding: early-write, and write the verdict before printing

Two ordering rules, both learned by losing a finished phase's output:

* Write the artifact (population, plan) BEFORE the slow loop, and flush after
each item — a killed phase that has written nothing has the evidentiary value of
one never run.
* Write the VERDICT to disk as soon as it is computed, before the closing print
statements — a `%`-format crash in a cosmetic `say()` after the verdict erased a
forty-minute measurement.

Both belong in the harness, not in a note explaining what went wrong.
