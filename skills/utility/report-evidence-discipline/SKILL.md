---
name: report-evidence-discipline
description: Use when a report cites saved evidence tables.
---

# Report Evidence Discipline

Companion to `xss-reflection-verification` (which covers the reflection
finding itself) and `offensive-reporting` (which covers the prose). This
covers the layer in between: keeping the evidence artifacts honest while
the report is written, and re-verifying the report before it ships.

Load it whenever a report cites a table of measured values, a count of
affected hosts/pages, a frequency, or a "not demonstrated" list.

## A CAPTURE FILE IS EVIDENCE, SO A RE-RUN MUST MERGE

The most common way evidence silently disappears: a script writes its
measurements to a JSON capture with `open(path, "w")`. Hours later the
script is re-run, the endpoint is rate limited, and the new file has
fewer rows than the old one. The report still cites the bigger table.

Rules that hold:

- **Merge by case key, never truncate.** Load the previous capture, index
  it by the case key, and write the union.
- **429 means "NOT MEASURED".** It must not replace a previously measured
  result. Same for a WAF 302/403 that never reached the application. A
  measurement replaces an old one only when it actually measured
  something.
- **A superseded script must not write the live capture at all.** Mark it
  `SUPERSEDED`, point it at its own file, and say in a comment WHY it
  was superseded (the bug that made it wrong). A re-run of an old buggy
  harness can destroy good evidence.
- **Test the merge logic offline.** A re-run that measured nothing, a
  partial re-run, a brand new case, and a fresh measurement with a
  different result - four cases, no network. Do not trust merge logic
  that has only been exercised by a real run.
- **Check the artifact, not just the verifier.** The verifier may merge
  several captures to get a complete picture, and the individual capture
  can still be full of 429s. A reader who opens that file sees the
  incomplete data.
- **Use `scripts/capture_merge.py` instead of writing the merge by
  hand.** It provides `write_capture(path, rows, key=...)` (load, merge,
  write the union) plus an offline self-test:

  ```bash
  python3 scripts/capture_merge.py --self-test
  ```

  A writer that opens the capture with `"w"` and dumps its own rows is
  the bug this script exists to prevent - reach for it before writing
  any capture.

## A SAMPLE SIZE MUST MATCH THE BEHAVIOUR YOU ARE MEASURED

If a disclosure appears in roughly half the responses, a 6-request sample
fails 12.5% of the time even when the finding is solid.

- Sample an intermittent behaviour 10-12 times.
- Break out of the loop only on a POSITIVE observation. Breaking on the
  first "looks right" response is how a run reports a false failure.
- Report the FRACTION, not one number - and quote every batch, because
  the fraction moves between runs.
- Identify the stable column and lead with it. In one real case the
  internal hostname appeared in 12/12 responses while the private address
  appeared in about half, so the finding is the hostname disclosure and
  the address is supporting evidence. The report must survive a reader
  who samples once and sees no address.

## "BLOCKED" IS NOT ONE THING

A WAF 403 with an `X-Iinfo` header and a vendor interstitial body is a
different defender from an application 200 that returns
`Error: ... is not a fully qualified public domain name`. Record which
layer answered, because the remediation differs - an application check
can be fixed in the application, a WAF rule is a mitigation that can be
reordered later.

Live re-testing is worth the time: a report written a day earlier can be
wrong in a way that looks like a new bug. In one real case the report
claimed a URL-form parameter was stopped by the WAF with a 403, and
live testing showed the APPLICATION strips the scheme and rejects the
result itself, while only the metadata address was stopped by the WAF.

## A HARNESS YOU CONTROL CAN LIE TO YOU

When the test stands up its own server and measures what the target
reflects back, two traps both produce a FALSE POSITIVE:

1. **A default header can shadow yours.** Python's `http.server`
   `send_response()` emits `Server: BaseHTTP/0.6 Python/3.x` BEFORE the
   header you set, so a client reading the FIRST `Server` header never
   sees your payload. Use `send_response_only()`, and always assert that
   YOUR marker is present in the reflected value before concluding
   anything from that value.
2. **A greedy regex picks up the page's own markup.** `r"Header:(.{0,80})"`
   runs past the closing tag into the following HTML. Extract up to the
   closing tag: `r"Header:(.*?)</p>"`.

A payload with no special character is a CONTROL, not a test case - it
has nothing to encode, so it appears verbatim and carries no entity.
Asserting "must not appear verbatim" on it is a bug in the test.

## EVERY REPORT GETS AN INDEPENDENT VERIFIER

One script per report that re-derives the claims from the live target
and from the saved artifacts, printing `N/N checks passed` and exiting
non-zero on any failure. Requirements:

- The verifier must not be the script that produced the finding.
- A check may not be a bare negation of another check's condition: a
  429 or an error body satisfies "marker not in body" and turns an
  untested case into a reported negative. Assert on the status class AND
  the verdict string together.
- Re-run the verifier after every edit to the report. A report that
  changed but whose verifier did not re-run is unverified.
- Keep the check count visible in the final report, so a reader can see
  the work instead of taking the claim on trust.
- **A verifier check must not be a bare negation.** `"marker" not in
  body` is satisfied by a rate-limit body, an error page and a WAF
  interstitial, so it silently converts an untested case into a
  reported negative. Assert the status class AND the verdict string
  together, or assert on a verdict the script itself assigned.
- **A check that counts cases must assert the count it expects.** If a
  run measured 4 of the 6 cases it was supposed to measure, a verifier
  that only checks "the combined payload is present" stays green while
  the evidence table is half empty. Assert the full expected set.
- **The verifier's own expected numbers drift when the skill grows.**
  When a check asserts a literal like `"39/39 merge checks passed"`,
  update it in the same edit that changes the count. Otherwise the
  verifier fails on a stale literal and nobody trusts it again.

## A PREFIX IS NOT A SAMPLE

Sorting a corpus and taking the first N names is a prefix, and a finding can be
missing from the sweep that is supposed to support it. `alpha.<domain>` sorts
after `01dl2.<domain>`, so a 1,500-of-12,000 prefix resolved zero of the name the
report was about - the evidence and the report described different populations.

- **Resolve the whole list, in chunks, and say which subset you measured.** In one
  estate the third-party CNAME count was 59 for the prefix and 691 for the full
  list; both numbers were true, only one was a measurement.
- **State the selection rule next to the number** ("all 11,945 names", not "names").
  If a sample really is a sample, say how it was drawn.
- **Any name a previous phase identified must be asserted present** in the sweep
  that follows, or re-measured alone and labelled as such.

## A NON-DETERMINISTIC MEASUREMENT CANNOT CARRY A VERDICT

A header that reflects the request `Origin` in 3 of 6 identical requests is not a
CORS misconfiguration, and a body status that appears and disappears across
repeats is not a consumed parameter. Both are the absence of an invariant.

- **Repeat the identical request before believing a differential.** Require an
  identical `(status, hash)` from N=6 repeats per arm. An arm that is not
  internally stable leaves the case **unjudged** - never clean, never vulnerable.
- **A strategy with 11,000 random ids is a signal, not a finding.** `acac=true`
  with `acao=None` is not a valid CORS response, so an observation like that says
  the front end fans out to several backends - investigate the realm before
  writing anything.
- **Then strip the variable instead of averaging.** Probe the REALM: the same
  request to the platform IP with an explicit `Host` header, or the platform's own
  apex. Apply the condition to the realm, not to the instance.
- **Never record "absent" when the check returned a gather error.** A resolver
  failure, a timeout, or a `gaierror` is not evidence that the property is
  missing - re-probe by IP with a `Host` header, and disclose the flake as a
  property of the vantage point rather than of the target.

## A RUN THAT CAN BE KILLED MUST PERSIST PER ITEM

A sweep that wrote its results once, at the end, lost 20 minutes of measurement
to a `pkill` - and a re-run cost the whole sweep again. The same shape applies to
any long enumeration.

- **Append each item to `jsonl` as it completes**, plus a done-marker file, so a
  kill keeps everything already measured and the next run resumes instead of
  restarting.
- **A completion runner must reuse the original classifier module** (`import base`)
  rather than copying its logic, or the two halves of one sweep are judged by two
different rules.
- **Read the exit code before theorising about the cause.** `124` means the
  `timeout` wrapper fired; `143` means something sent SIGTERM; a run with no exit
  marker and no output file is unverified, not "probably finished". Diagnosing a
  `124` as a resolver hang sends the next hour at the wrong problem.
- **Bound DNS resolution separately from the socket.** `urlopen(timeout=N)` does
  not cover the `getaddrinfo` inside it: set `socket.setdefaulttimeout`, and put
  `signal.alarm` around each request so a stuck resolver cannot consume the run.

## A VERIFIER THAT TALLIES A LIVE COLLECTION WILL GO RED FOR THE RIGHT REASON

A verifier asserting `total == 82` against a database a pipeline is still writing
failed at 88 findings - the check was correct about its own expectation and wrong
about the world. The fix is not to relax the check.

- **Pin to a timestamp, not to a total.** Assert the collection grew since the
  snapshot and that the growth is attributable, and keep the counts the snapshot
  actually measured.
- **Replace the constant with an invariant that must not move.** Findings sourced
  from *retired* templates are counts that must stay fixed even as new rows
  arrive - assert those, and the check becomes stronger than the total it
  replaced.
- **No `or True` may survive in any verifier.** It makes the check unfalsifiable
  and is indistinguishable from a passing test. When inheriting a verifier, grep
  it for `or True` before trusting a green run.

## WHEN RE-DOING A FINDING, RECHECK THE SCOPE OF THE CLAIM

The count is the claim. A first pass found 5 affected pages; re-running
the same sweep with the correct criterion found 21. The first sweep had
covered the same 282 pages - it had simply asked the wrong question
(server-side reflection) and reported them as clean.

Re-run the scan with the corrected criterion before publishing any
count, and state the corrected number in the report rather than the
number the first pass produced.

## REPORTING DISCIPLINE

- Verify every factual claim by re-fetching it, not from memory.
- If the finding is NOT the class you expected, say so in the report
  body. A report that overclaims gets closed as informative.
- Do not write a report for a finding you could not verify.
- Report only actual limitations. Never claim readiness when a required
  test or live verification did not pass.
