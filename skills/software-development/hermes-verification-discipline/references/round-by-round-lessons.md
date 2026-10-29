# Round-by-round lessons (topics 41+)

Extracted from SKILL.md when it exceeded the 100k size limit. The rules in
SKILL.md are the index; these are the detailed cases behind them.

## 41. Code pasted into a conversation is a SPEC, not a file

An operator who cannot write a file themselves (a classifier refuses them, and they are
deliberately not going around it) pastes the full source for you to apply. The paste is
close to correct and wrong in exactly the places a chat transport damages: identifiers
with an eaten underscore, a module path that does not exist, and lost indentation.

- **Read every referenced module's REAL API before writing the file.** Check each
  constant, function and method exists under that name, and import each module the paste
  imports. A nonexistent module is a transcription gap, not an instruction to create it;
  the correct module is usually named in the paste's own docstring or by the surrounding
  code. Report which you corrected.
- **A truncated identifier is the signature of this failure.** `type(exc).name` sitting
  beside that same module's other uses of `.__name__` is a lost underscore. Check against
  the recipient module's own conventions instead of propagating the typo.
- **Prefer targeted edits for an existing file; a new file for a new one.** Apply the
  paste in the order it specifies (often bottom-up) so anchors and line numbers do not
  move under you. Never rewrite a module wholesale to land a handful of functions (§35).
- **A pasted test failing on an undefined symbol is not a defect in the paste.** It is
  the half you have not applied yet. Land the whole change set, then run it.
- **Record the transcription fixes in the file's own docstring** ("applied as given; the
  only changes were transcription fixes …") so the edit is auditable and a later reader
  does not think the author wrote it that way.
- **The paste's premise paragraph is a claim to verify, not context.** A paste asserting
  "flags X, Y, Z are already set, so this exposes A, B and C" is asserting CURRENT unit
  state. Check it — and check the opposite direction too, because flags set by EARLIER
  work are usually still present and the real exposed set is often LARGER than the paste
  says. Report the gap before the code goes live; it is the entire safety story of the
  change.

## 42. Widening a shared constant means finding every place it is asserted

Adding an item to a shared constant (a tool allowlist, a job-type set, a policy tuple)
breaks every site that asserts its exact contents, and those sites are NOT co-located.

- **Grep the whole tree for the SYMBOL, not the suspected file.** A capability audit
  helper asserted the same set SEPARATELY from the main safety suite, so the first fix
  left a red suite behind that only surfaced when its own check ran. Update every site in
  one edit, then add a positive guard (assert the widened set does not intersect the
  banned set).
- **An arm flag with no executor is INERT, not armed.** A capability needs an executor
  module and a runner script; a name registered in the arm map alone creates no path.
  List the executors and runners to decide whether a flag is live before describing it as
  enabled.
- **A capability may already be live under a DIFFERENT subsystem's flag.** Before saying
  "tool X is now enabled", grep the unit for other flags naming X and read what the job
  table has already produced (`SELECT status, COUNT(*) FROM jobs WHERE
  job_type='<x>'`). Hundreds of COMPLETED jobs means it was already on: re-arming it
  changes nothing and must be reported as such, never as an activation.
- **Read the armed set from the LIVE process, not the unit file.** Derive it exactly as
  the code does — allowlist × `is_armed()` — from `/proc/<MainPID>/environ`. The
  requestable set is that intersection and it routinely contains more than the brief
  assumed, because earlier work's flags are still set.
- **A grep filter that reads the live env is itself a query, and a lossy one silently
  hides the thing you are checking.** `grep -E "^HERMES_[A-Z_]*="` drops every variable
  with a DIGIT in its name (`HERMES_AD_X8`), so a tool looked unarmed when it was armed.
  Print the full `tr '\0' '\n' < /proc/<pid>/environ | grep <prefix>` list, or match with
  `[A-Z_0-9]`; never narrow with a character class that excludes a character the name
  legitimately contains.
- **A subprocess that must see the daemon's env needs it passed explicitly.** Env
  exports in your shell do not reach it, and an import in a fresh interpreter starts
  with YOUR environment: build an env dict from `/proc/<MainPID>/environ` and pass
  `env=` to the subprocess, then read the variables inside it. Never conclude "unarmed"
  from a probe that ran without the service's environment.
- **Changing flags by editing a unit is an additive edit you must diff.** Back the unit
  up first and diff against it afterwards, showing only added lines, so a reordering or
  dropped line cannot hide in the change.
- **A flag that only widens a request surface needs its load time stated.** If the
  daemon's start time predates your edit, the new code is not loaded: say so and leave
  the restart to the operator rather than describing the change as live (§36).
- **An allowlisted capability is not an executed one.** After the allowlist widens, the
  honest verdict needs two more facts: whether anything can CALL it (an executor module
  plus a runner, wired into the planner), and whether it is armed. Name all three states
  separately instead of collapsing them into "enabled".
- **Announce the semantic change, and any conflict with the system's stated posture.**
  Allowlisting a scanner that injects payloads is an operator decision, and it can
  contradict what the system's own banners claim (`exploitation OFF`). Report the conflict
  rather than resolving it silently on your own authority.

## 43. A missing character has three causes — attribute it before concluding

"The payload came back absent" is a statement about your request, not about the filter.
Something that vanishes can be sanitised, blocked, or never delivered, and those are
three different findings with three different fixes.

- **Send the neutral control in the SAME request shape as the payload.** If a benign
  value echoes verbatim while the payload does not, the difference is inside the request
  path — sanitisation. If the control also vanishes, the shape is the problem and nothing
  about the payload was measured. A control that differs in method, host, or parameter
  position shares a cause with the payload and cannot separate the two.
- **A block looks different from a strip, and the status/body says which.** A WAF block
  changes the status or serves a challenge/interstitial; a strip returns the normal page
  minus the characters. Record the status beside the absence, and check for block-page
  signatures (`cType:'managed'`, `cRay:`, `__cf_chl_tk`, `X-Iinfo`, `visid_incap_*`)
  before writing "filtered".
- **Distinguish "the filter removed it" from "the request never arrived".** A rate limit
  that engages mid-run turns later probes into 403s; those requests are UNTESTED, not
  evidence of a filter. Re-run paced, one data point per request, and write the raw
  bodies to disk so the escaping is inspectable instead of summarised.
- **Test one character at a time.** A combined breakout payload attributes nothing: if it
  fails you cannot tell which character a filter caught. Per-character probes are what
  let you say `<` passes raw while `"` becomes `\"` — a correct escaper rather than a
  block.

## 44. One bucket named by one mechanism is a claim — split the classes

A single counter labelled with a single mechanism is an assertion, and it is usually
wrong in the direction that flatters the work. A scanner's `encoded` bucket of 519 rows
was described as "all Cloudflare challenge pages" and an assertion was written for it;
the bucket actually held two disjoint populations — 65% WAF challenge pages, 28% the
application quoting the whole request URL into its own JSON (`requestURL`,
`passportAccountURL`, `continue=`), 0 overlap — and fewer than a third were 200 responses
at all.

- **Enumerate each class and its share, and check the overlap explicitly.** Classes are
  frequently disjoint (0 shared), which means a claim about the union is a claim about
  neither class.
- **Read the status mix before naming a mechanism.** If most rows are not 200s they are
  infrastructure, not the application, and the remediation differs.
- **Never pool provider/infrastructure classes with application classes.** This is the
  same rule as reporting vendor CNAME families separately rather than as one pool: the
  pooled number is unfalsifiable and hides which side the work actually touched.
- **When a verifier assertion above a pooled claim fails, the assertion is right and the
  claim is the defect.** Replace the single assertion with one per class, each carrying
  its measured share, so the split itself is what is gated.

### A marker reaching a sink is not execution

When the measurement is a browser probe, the equivalent trap one layer down: a marker
arriving at an `innerHTML` setter can be the application's own sanitiser's scratch
element. Take `new Error().stack` on every sink hit and name the caller, and require a
non-executing tag payload to produce a real element in the document before claiming
markup was parsed. Full procedure in `hermes-domxss-verifier`.

## 45. A stale notification replays old state — reconcile it, never act on it

Background-process notifications arrive long after their result was consumed, and they
carry the state at the moment THAT process stopped. Acting on the headline turns a
finished phase back into an open question.

- Compare the notification against live state (artifact mtime, current verdict artifact,
  process table) and report the reconciliation, not the alarm. A `DALFOX_EXIT=143`
  (SIGTERM) arriving after you stopped the tool yourself is a confirmation, not a
  failure.
- A notification that VALIDATES a claim you already published is still worth the one
  call: quote the artifact field it matches rather than saying "as expected".
- Verify "nothing is running" by matching your own patterns, not by counting
  interpreter processes — a shared host legitimately runs unrelated services, and
  `pgrep -f <pattern>` will also match the shell running the `pgrep`.

## 46. `a = b = c = []` binds ONE list to three names

`refused = redir = other = []` does not create three lists. It creates one list and
three references, so every `other.append(x)` also mutates `refused` and `redir`. A
classification check then reports values that look like corrupt data
(`refused=7 redir=7 other=[all seven hosts]`) when the data is fine and the test is not.

```python
refused, redir, other = [], [], []     # correct
```

Tell-tale: a check reporting the SAME contents under two labels, or counts exceeding
the population. Suspect aliasing before you suspect the data — then re-read the
artifact to confirm.

## 47. An assertion that cannot fail is worse than no assertion

These pass forever, and the tally counts them as coverage:

```python
check("the claim holds", some_condition or True)   # always passes
check("the claim holds", True, "info: %s" % x)     # always passes
```

Grep for `or True` and for `check(\(.*, True` before trusting a verifier's count. When
the fact is not yet checkable, write the small phase that dumps it to an artifact
instead of softening the assertion.

## 48. Numbers in a LOG are not numbers in an ARTIFACT

A phase that `print()`s its findings writes them to a log. A verifier reading the JSON
artifact cannot see them — and the author then "verifies" them by asserting against the
NOTE's own text, which passes whether or not the underlying numbers are true.

**If a NOTE quotes a number, that number must exist in a JSON artifact and the
verifier must read it from there** — never from prose, never from a log, never from the
author's recall. When the artifact lacks it, add a phase that writes it out (and make
that phase print the inventory so the log and the JSON agree).

## 49. Read the artifact's real keys before asserting against it

The artifact is a file; its shape is whatever the writer actually wrote.
`z1["population"]` and `z1["verdict"]` are different claims, and `len(z1["rows"])` on an
int raises `TypeError`, which reads as a crash rather than as a wrong assertion. Print
`list(d.keys())` and the type of each value first, then write the checks.

## 50. Run the SUITE, not the verifiers you remember

A hand-maintained list of 9 was being run each round on a project that had grown to 19
verifiers. The other 10 were green and nobody knew; one had already been dropped from
the routine.

Glob `*_note_verify.py`, run each, parse the summary, print a uniform tally plus
`healthy: N/M`. Expect a suite that grew over months to print **several** summary
formats — `NN PASS / NN FAIL`, `NN passed, NN failed`, `NN checks passed, NN failed`,
and a counts-free `all checks passed`. Parsing one convention silently reports the rest
as having no summary, which reads as "these verifiers are broken" when they are fine.

Report an unparsed summary as `NO RECOGNISED SUMMARY`, never as 0 passed, so "I cannot
read this" is never confused with "this checks nothing".

## 51. A LIVE corpus means absolute counts drift — assert the RELATIONSHIP

When a background daemon keeps writing the same collection a script counts, any absolute
total is a snapshot, not a fact. Two runs of the same phase an hour apart gave
`live 19,203 -> 19,226`, `gap 16,099 -> 16,110`, `probed 3,104 -> 3,116`. A verifier
asserting `== 16099` goes red for a reason that is nobody's mistake, and it trains you to
ignore red.

Assert what the phase CONTROLS:

```python
check("the gap is the difference of its own two counts", gap == live - probed)
check("the gap is ~84% of the live set", 0.80 < gap / live < 0.87)
check("the classes sum to the in-scope gap",
      env + interesting + regional + other == gap_in_scope)
check("env scaffolding is the 2.3k class", 2200 <= env <= 2500)
```

The STABLE classes (2,315 env / 1,108 interesting) are the ones a note may quote; moving
totals are quoted with `~`, and the note must say the corpus is live and the numbers
drift. A `==` against a number a daemon can change is a test that fails for the wrong
reason.

## 52. A name that RESOLVES is not a host that SERVES

A corpus of "live subdomains" is a snapshot of when each name last resolved. Re-probing
it later yields `URLError` for almost everything, and "83.8% of hosts are unprobed" then
reads like an untested attack surface when it is actually a measure of how stale the
snapshot is. Push past the error class before writing the verdict — split it, because the
parts mean different things:

```bash
getent hosts <h>                        # does it resolve NOW
timeout 6 bash -c '</dev/tcp/<h>/443'   # does anything listen on 443
timeout 6 bash -c '</dev/tcp/<h>/80'    # and on 80
```

Result on an 8-host sample of a supposedly-live gap: **7 resolve but refuse both ports**
(the names are real, the services are gone or unreachable from this vantage), **1 did
answer on :443** (and the corpus already knew it), and **1 did not resolve at all** (a
stale entry). None answered with a body.

The honest conclusion is that the gap is a **corpus-age** measure and the fix is a
refresh/re-resolve, not a bigger probe budget. Say that instead of reporting "16,099
untested hosts".

## 53. Wildcard-permutation names are enumeration noise, not hosts

A name shaped like `acc-acc-access-dashboard.wildcard.aggtest.indeed.net` is generated by
an enumeration tool permuting prefixes against suffixes. An unfiltered sample drawn from
a large corpus was **46 of 47 such names**, every one answering no connection — the phase
measured nothing and then ran long enough to be killed by its own wall-clock timeout
before writing its artifact.

Two guards, both cheap: filter `wildcard|aggtest|acc-acc|\.backup\.|\.info\.` before
sampling, and **write the artifact BEFORE the slow probe loop** so a timeout can never
lose a characterisation that was already computed.

## 54. A verifier glob is a coverage decision — `*_note_verify.py` hides the report verifiers

A suite grew a second family of verifiers and the collector kept globbing only the first:

```python
files = sorted(f for f in os.listdir(ART) if f.endswith("_note_verify.py"))
```

That is a *correct* expression and a *complete* one — for notes. Five report verifiers
existed (a report is the highest-stakes artifact this project produces, the one that
leaves the building) and **not one of them had ever run**. When the glob was widened,
three were red: one had a genuine false-positive assertion, one printed a summary format
the parser did not know, and one timed out because it makes ~24 LIVE requests.

Widen the glob to every verifier family, and treat a summary you cannot parse as
`NO RECOGNISED SUMMARY` rather than 0-passed, or a silent verifier is indistinguishable
from a passing one.

### The summary-format zoo

A suite that grows over months accumulates formats. Five so far, and each one missed
reads as "this verifier checks nothing":

```
NN PASS / NN FAIL              NN passed, NN failed
NN checks passed, NN failed    NN/NN checks passed
PASSED: NN   FAILED: NN
```

Note `NN/NN checks passed` is passed-of-TOTAL, so failed = total - passed; whereas
`NN PASS / NN FAIL` gives both numbers directly. Parse them differently.

## 55. A live-network verifier needs pacing, or it rate-limits itself into a false failure

A report verifier re-fetched its evidence from a production host — **24 requests** with
**zero** delay, so the whole run cost minutes and risked the host rate-limiting it. A
deprecated claim that fails because the verifier tripped a rate limiter is the worst
outcome available: it looks like a finding.

Route every live fetch through one pacing helper, and print the request count so the
cost is visible rather than silent:

```python
PACE_S = 1.1
_REQ = [0]

def _pace():
    if _REQ[0]:
        time.sleep(PACE_S)
    _REQ[0] += 1

# in EVERY function that opens a socket:
def raw_get(...):
    _pace()
...
print("  live requests issued: %d (paced at %.1fs)" % (_REQ[0], PACE_S))
```

Also raise the collector's per-verifier timeout above the slowest legitimate run, and
print each verifier's elapsed seconds: a 450s all-green verifier is legible, whereas a
500s timeout with no timing data looks like a hang.

## 56. A secret-scanner that matches a KEYWORD names a negative table as a leak

A scan for `password=`, `api_key=`, `secret=` flags the report that *documents what it
searched for and did not find*:

```
| Credential (`password=`, `secret=`, `token=`, `api_key=`) | **No** |
```

One hit in 255 files, and it was the report naming the string it looked for. Do not
weaken the pattern — require a VALUE by demanding something other than a negative after
the separator:

```python
if re.fullmatch(r"(?i)(password|api[_-]?key|aws_secret)\s*[:=]", whole):
    after = txt[m.end():m.end() + 40]
    if re.match(r"\s*[`\"']?\s*(No|None|n/a|\||`)", after):
        continue          # the keyword is being NAMED, not assigned
```

Guard the filter with a **positive self-test** that plants a real secret and asserts the
regex still catches it, so tightening the rule cannot quietly turn it into a no-op.

## 57. Write the artifact BEFORE the slow loop, or a kill erases the phase

A phase that computes its population first and probes second has a vulnerable
ordering: the population is known immediately, but nothing reaches disk until
the probes finish, so a timeout kill leaves NO artifact at all. This happened
twice on the same project (ZH28, then ZH31 by the same mechanism) before the
fix was applied in both places:

```python
# WRONG: one write at the end
for host in hosts:
    probe(host)
write(json.dump(res))

# RIGHT: land what you know, then append as you go
res["verdict"] = {"status": "in_progress"}
write(json.dump(res))
for host in hosts:
    res["hosts"].append(probe(host))
    write(json.dump(res))          # survives a kill mid-probe
```

A phase killed before its write has the same evidentiary value as a phase never
run, and it looks like a crash rather than a result. Cost of the fix: one extra
write per item.

### The two causes of the kills, both worth fixing at the same time

*Unresolvable names burn the FULL timeout on every path.* A serial sweep of
candidates spends nearly all its wall clock waiting on NXDOMAIN, and the fix is
either a cheap resolver pre-check or a batch resolver (`dnsx -l names.txt -a`,
one pass). Separate "does not exist" from "exists but does not answer" - the two
are different facts and only the second is a statement about the target.

*Serial requests cannot hide a timeout.* A bounded worker pool (5-6) behind a
SHARED token-bucket limiter finishes the same work in a fraction of the time
without raising the rate. "Shared" is the operative word: threads with a
per-thread throttle multiply the request rate by the worker count, which turns a
polite sweep into a flood.

## 58. Fold BOTH sides of a phrase assertion, once

Asserting that a document contains a multi-word phrase has two independent
failure modes, and both look like a content failure when they are test bugs:

1. **markdown hard-wraps.** A phrase spanning a line break fails a plain
   substring test. Fix: normalise whitespace (`" ".join(text.split())`).
2. **casing.** `"ZH30" in note.lower()` is False because the HAYSTACK was folded
   and the NEEDLE was not. Fix: fold the needle too.

Both cost multiple cycles because the failure reads as "the NOTE does not say
this". Build one helper and route every phrase claim through it:

```python
flat = " ".join(note.split()).lower()

def ph(fragment):
    return " ".join(fragment.split()).lower()

check("NOTE records X", ph("X as written in the note") in flat)
```

Structural assertions that care about the document's real formatting still use
the raw text.

## 59. A request count you quote from memory is a claim; read it from the run

A live verifier was reported to issue "24 requests to a production host" when it
actually issues **65**. The number came from a quick impression of the code
(a handful of call sites) rather than from the run's own output - and it was
then used to make a point about rate discipline, which made it load-bearing.

The script already printed the truth; the fix is procedural:

```python
print("  live requests issued: %d (paced at %.1fs, no concurrent fetches)"
      % (COUNT[0], PACE_S))
```

Two rules follow:

* Any script that touches a target prints its own request count, so the figure
  can never be recalled wrong.
* When a count is quoted in a report, NOTE, or summary, quote what the script
  printed - never an estimate of it. Counting call sites undercounts loops, and
  loops are where the requests are.

The same discipline as topic 48 (assert from the artifact, not from prose) -
applied to numbers that appear in conversation rather than in tests.

## 60. Never build a URL with `%`-formatting — percent-escapes are read as conversions

```python
# BROKEN: ValueError: unsupported format character 'A' (0x41) at index 56
"https://x/login?next=https%3A%2F%2F%s%2F" % canary
```

`%2F` is parsed as a conversion specifier, so any URL containing percent-escapes
cannot be `%`-formatted. This stopped a classifier self-test on two separate
phases of the same project, which is good news only because the self-test ran
BEFORE the sweep - the failure was cheap precisely because the check was first.

Use concatenation or `.format()`/f-strings for URLs:

```python
enc = urllib.parse.quote("https://" + canary + "/", safe="")
url = "https://x/login?next=" + enc
```

Corollary for self-tests: a self-test that runs first converts a would-be
mid-sweep crash into a startup refusal. Prefer aborting on a failed self-test
over raising partway through a run that has already written half an artifact.

## 61. A new assertion must be EXECUTED, not merely written

Adding checks to a verifier and then trusting them is how a suite grows
assertions that cannot run. Two consecutive additions needed a second pass:

```python
# NameError: name 'res' is not defined          -> verifier crashed, reported
#                                                 as NO RECOGNISED SUMMARY
check(..., urllib.parse.unquote(x))             # NameError: no module named
```

The first looked like a content failure (`NO RECOGNISED SUMMARY`); the second
looked like a failed assertion. Both were the verifier not being runnable. Run
the verifier immediately after editing it - the collector will report a crash
as an unhealthy count rather than as a test result, and a crash is not a pass.

## 62. A prefix table is ORDER-SENSITIVE — specific ranges before general ones

Classifying IPs by a list of (regex, owner) pairs is a first-match-wins lookup, so
a broad range listed before a narrower range inside it silently swallows the
narrow one:

```python
OWNERS = [
    (r"^45\.(3[0-9]|...|9[0-9])\.", "Heroku", True),   # matches 45.60.x.x too
    (r"^45\.60\.", "Imperva", False),                  # NEVER REACHED
]
```

Consequence on a real engagement: seven DigiCert hostnames whose addresses are
`45.60.x.x` (Imperva) were reported as **"moved to a claimable Heroku provider"**
— a fabricated subdomain-takeover report against customer-facing hosts, which
would have been written up and sent. Every other detector error in that round
overstated a count; this one invented a vulnerability class.

Two cheap guards, both of which would have caught it:

* **Self-test the table.** Pin the specific-before-general cases by hand:
  `("45.60.150.51", "Imperva", False)`, `("45.33.12.9", "Heroku", True)`. Run it
  before the baseline and abort the run if it fails.
* **Cross-check against something already known about the host.** These same
  hosts carried `visid_incap_*` cookies and served Imperva challenge pages in
  earlier phases. A classification that contradicts established observations of
  the same host is a bug in the classification.

Ordering is invisible in a passing run. It only shows up as a wrong answer, so
it needs the explicit test.

## 63. A marker in a REFUSAL page is the WAF, not the application

A reflection detector that counts "marker in body" without requiring a 2xx will
read a WAF deny page as input reflection, because deny pages QUOTE THE URL THEY
REFUSED:

```
<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>
You don't have permission to access "...&47;marker&47;..." on this server.
```

That produced a false "ESCALATE: the response carries the marker, so the field is
input-dependent" on an endpoint whose ONLY 2xx was the control body. On the same
project this is the third instance of one shape: a round-10 balance where 145 of
519 apparent reflections were the application quoting the whole URL, then a
Cloudflare challenge page, then this.

Rules that close it:

```python
tracked  = [p for p in probes if p["contains_marker"] and 200 <= p["status"] < 300]
waf_echo = [p for p in probes if p["contains_marker"] and not (200 <= p["status"] < 300)]
```

* **Require 2xx for a reflection.** Everything else is a property of the
  intermediary, not of the target.
* **Report the non-2xx echoes on their own line**, labelled, so a reader cannot
  mistake them for hits.
* When a sweep's only 2xx is the control, the honest verdict is CLOSED - the
  other shapes never reached the application at all.

## 64. A static chain detector must follow the CALLBACK PARAMETER, not just names

Scanning for "source -> fetch -> sink" by matching identifiers misses how every
minified jQuery chain actually reads:

```js
a.get(i).done(function (a) { e.html(a) })
//    ^ fetch arg      ^ callback parameter, NOT the fetch arg
```

The fetch target is `i`; the sink receives `a`, the callback's parameter. An
identifier-equality test finds nothing, so a positive fixture built from a REAL
chain failed its own detector - which is exactly how it was caught (the
non-vacuity gate aborted the sweep on the fixture, twice, before any file was
scanned).

Also: `$` is not the only jQuery alias. Minified bundles use `a`, `n`, `t`, `e`
freely, so a pattern anchored on a literal `$` sees almost nothing. Match any
identifier:

```python
FETCH = re.compile(r"[\w$]+\.(get|post|ajax)\(|(?<![\w.])fetch\(|\.load\(")
```

Keep a NEGATIVE fixture beside the positive one: a fetch whose result goes to
`console.log` must not match, or the detector is really testing "this file
contains a fetch" rather than "this chain reaches a sink".

## 65. A comparator must be shown STABLE before its verdict counts

Three verdicts were issued and then withdrawn in one round, all by the same
mechanism: a comparator was trusted before it was shown to be stable.

* one arm compared body hashes on a page that renders a per-request nonce, so
  every arm "differed" and 8 hosts were reported as parameter-sensitive;
* one comparison held the parameter NAME and the VALUE both different, so a
  difference could not be attributed to either;
* one labelled 7 hosts a backend switch when all 7 had served the default page
  on every arm - the named event never happened.

Order, non-negotiable: (1) send the identical request N times and require an
identical response per arm; (2) isolate ONE variable between arms; (3) compare
arms by set disjointness, not by one sample; (4) read the BODY, not its length -
two lengths can mean two servers, and a stock default page means the app was
never reached.

When a later measurement contradicts an earlier verdict, withdraw the verdict in
writing. The withdrawal is the evidence that the method was checked.

## 66. A verdict LABEL can be true of the wrong thing

`BACKEND-SWITCH` was assigned to hosts where no switch occurred, because the
condition was tested on the arm of interest only (`probe.default_page`). Before
accepting a class name, assert what the name implies across ALL arms:
`all(default_page for arm in base + control + probe)` is a different observation
and it excluded 7 of the 8.

## 67. An ABSENT key is not a zero

A `Counter` omits classes with no members, so `tally.get("X") == 0` fails for a
bookkeeping reason, and `.get("X", 0)` would turn that into a fabricated pass.
Assert against the population that is always present - the record list:
`sum(1 for c in cases if c["verdict"] == "X") == 0`.

## 68. An ABORT must not exit 0

A run that tested nothing returned `EXIT=0`. The listener had issued zero
payloads (the TLD regex matched nothing), the script printed the reason and
`return`ed from `main()`, so to the process supervisor it looked exactly like a
clean run with a clean result. The only trace was one line of log output.

Every early-exit path needs a distinct non-zero code, and the caller needs to
treat it as "no result":

```
payloads not issued   -> sys.exit(2)
listener not proven   -> sys.exit(3)
```

`EXIT=0` must mean **the phase produced a verdict it stands behind**. Anything
else — aborted setup, unproven instrument, empty population — is a non-result,
and a non-result that reports success is worse than a failure, because it gets
filed as evidence. Pair the code with a verifier assertion that the artifact
carries no `aborted` key, so a silent abort cannot be mistaken for a result even
if someone re-reads only the JSON.

## 69. A NUL byte in a log makes `grep` SKIP matching lines silently

A verifier printed raw bytes, the shared sweep log acquired NUL, and `file`
reported it as `data`. Every `grep` against that log returned partial results with
no error at all: the header said **27 verifiers**, only **26 rows** matched, and
the missing verifier looked like it had simply not run. `grep -a` showed all 27
and the correct `27/27`.

Two fixes, both wanted:

* sanitise collected output in the runner (`out.replace("\x00", "\\x00")`) so one
  chatty tool cannot poison a shared log
* when a count in a log disagrees with a list, re-read with `grep -a` and check
  `file` before believing either number — "row missing" and "row filtered" are
  indistinguishable otherwise

## 70. `EXIT=0` from a batched inline interpreter is not per-item success

Running several verifiers through one `python3 -` script that times out yields a
single `TimeoutExpired` for the whole batch: items that already passed look
identical to items never reached, and the traceback names only the wrapper.
Prefer the project's own runner, which prints one row per verifier.

## 71. A count READ from a log must be re-derived at the moment of the claim

A number quoted from an earlier grep of the same file goes stale the moment a
newer run rewrites that file. Repeatedly this round a count was reported from a
read taken before the file changed. State the mtime with the number, or re-read
it as part of making the claim.

## 72. An abort path must not exit 0

A run that tested nothing returned `EXIT=0`: the setup aborted (zero payloads
issued), the script printed the reason and returned from `main()`, so to the
supervisor it looked exactly like a clean run. The only trace was one line of log
output, which gets filed as evidence.

```
payloads not issued   -> sys.exit(2)
instrument not proven -> sys.exit(3)
```

`EXIT=0` must mean **the phase produced a verdict it stands behind**. Anything
else — aborted setup, unproven instrument, empty population — is a non-result, and
a non-result that reports success is worse than a failure because it is archived.
Pair the code with a verifier assertion that the artifact carries no `aborted`
key, so a silent abort cannot be mistaken for a result even if someone re-reads
only the JSON.

## 73. An ABSENT key is not a zero

A `Counter` omits classes with no members, so `tally.get("X") == 0` fails for a
bookkeeping reason, and `.get("X", 0)` would turn that into a fabricated pass.
Assert against the population that is always present — the record list:
`sum(1 for c in cases if c["verdict"] == "X") == 0`.

## 74. A verdict LABEL can be true of the wrong thing

`BACKEND-SWITCH` was assigned to hosts where no switch occurred, because the
condition was tested on the arm of interest only (`probe.default_page`). Before
accepting a class name, assert what the name implies across ALL arms:
`all(default_page for arm in base + control + probe)` is a different observation
and it excluded 7 of the 8.

## 75. A parser that extracts nothing from a large input is BROKEN, not empty

`dnsx -resp` wraps the record type and the target in ANSI colour escapes:

```
'*.le.etm.digicert.com [\x1b[35mCNAME\x1b[0m] [\x1b[32metm.digicert.com\x1b[0m]'
```

A regex written against the plain shape `name [CNAME] target` matched **zero** of
6,971 lines. The run then printed `live requests: 0` and wrote a clean artifact —
a fully successful-looking empty result produced by a parser that never worked.

Guard every bulk parse: if input lines exist and zero records were extracted,
**abort with a distinct non-zero code** and print the first raw line. An empty
result and a broken parser are indistinguishable downstream, and only one of them
is a finding.

Check the raw shape before writing the regex — one `repr(line)` would have shown
the escapes immediately.

## 76. A field that has not been written yet is not a value

A sweep writes its artifact after each item, so mid-run the per-item `verdict` is
still absent. Inspecting the file at that moment and treating a missing verdict as
"not the good case" produced a report of **81 takeover-ready subdomains** while
the live-state phase had not yet run. The finished numbers were 389 chains and 20
candidates, zero of them claimable.

Two rules: do not read an artifact that a running phase owns, and treat an absent
key as unknown rather than as false (see also the zero-vs-absent rule). State the
mtime of any artifact you quote, and re-read at the moment of the claim.

## 77. A "NO-RESPONSE" verdict must name the scheme and port tried

A host was recorded NO-RESPONSE because HTTPS reset the connection. The service
was live on port 80 the whole time, which is the port the recon corpus had used.
The verdict was true of the probe and false of the host.

Say which scheme and port the negative applies to; a per-scheme, per-port verdict
is the only kind that cannot mislead. The same applies to the certificate
mismatch found on a second host: "unreachable" was really "reachable but the name
cannot match the certificate it presents".
