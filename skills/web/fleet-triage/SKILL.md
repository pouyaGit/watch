---
name: fleet-triage
description: 'Cluster-first triage for large same-class hit lists.'
---

# Fleet Triage — cluster a candidate fleet before working it host-by-host

When an automated pass returns dozens or hundreds of same-class hits (CORS
reflection, reflection sweeps, header probes), do not work the list top-down.
Cluster first, then spend requests only on representatives and outliers.

## Procedure

1. **Sweep cheap, one request per host.** A single canary request (marker
   Origin, marker query value) plus a negative control (no Origin, benign
   value) per host is enough for the first pass. Run it concurrent (10+ workers)
   and persist (host, status, body length, body hash, title, key headers).
2. **Cluster the control responses by shape.** Group by (status, body length,
   body hash/title). A large fleet usually collapses to 2-4 shapes: empty
   redirects, one SPA shell served on every path, one JSON refusal. Record the
   cluster sizes.
3. **Run the behaviour test on one representative per cluster.** The question
   is whether server behaviour changes when attacker-controlled input is
   present — e.g. a bogus credential for CORS, a canary value for reflection.
   Identical refusal with and without the input means the host sits behind an
   edge/WAF and impact is unproven; mark the whole cluster as such.
4. **Spend per-host effort only on outliers.** Non-shell status/length, real
   API paths from the crawl, bodies that differ from the cluster shape. These
   earn sub-path sweeps and manual follow-up.
5. **State the ceiling honestly.** "N hosts reflect, but every response is a
   WAF refusal / empty shell with no behaviour change" is a note, not a
   report. Record what was measured and what would change the verdict.

## Pitfalls

- **Do not chase the scariest-looking cluster first** — a wildcard header or a
  reflecting echo on an empty body is inert by construction; the explicit-value
  hosts that could actually echo attacker input are the real candidates,
  because only they can carry a live reflection.
- **Measure the body before the header, never after** — a header over an empty
  or identical-shell body is worth nothing even when the header looks
  misconfigured.
- **Test the negative control before believing any reflection** — if the
  header/value is present with no attacker input, it is static, not reflected.
- **One shape per cluster is enough for the verdict** — re-proving the same
  shell on all 40 members burns budget and re-triggers rate limits; prove the
  representative, spot-check one sibling, move on.
