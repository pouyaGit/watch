---
name: bug-bounty-triage
description: "Use when triaging a bug-bounty target: scope and payout."
---

# Bug bounty triage — scope and payout-worthiness

Complements `web-finding-verification`: that skill decides whether a candidate is real;
this one decides whether it is worth submitting and to whom.

## Scope comes from the program, not from the hostname

- Take the in-scope asset list from the program's own record. A host that resolves
  under the target's domain is not automatically in scope — subsidiaries, acquisitions,
  and third-party SaaS are routinely excluded.
- Never send traffic to an out-of-scope host, including a single "is it up?" request.
  A scope violation can void every finding in the report.
- Record the scope decision per host in the report so the triager can see the reasoning.

## Severity discipline for payout

- Low-severity findings with no demonstrable impact are triaged as informational and
  pay nothing. Before writing one up, name the concrete consequence: what data, whose
  account, what action.
- Do not inflate a finding to reach a payout band. An over-claimed Medium that gets
  downgraded costs more trust than an honest Low that gets accepted.
- Separate a *configuration inconsistency* (a sibling endpoint missing the auth its
  peers enforce) from *data exposure*. Only the second escalates.

## Write-ups that get accepted

- Lead with the exact request and the exact response, both redacted.
- State the reproduction in a form a triager can run in under five minutes.
- Include the negative controls you ran (the differential test, the sibling endpoint
  comparison) — showing what you ruled out is what distinguishes a real finding from a
  scanner hit.
- Say plainly what you did NOT prove. A report that states its own limits is trusted;
  one that implies impact it never demonstrated is closed as not reproducible.
