---
name: recon-scope-triage
description: Triage ASM/recon output for ownership before testing — separate the target's real assets from namespace-collision noise. Automated recon keyword-matches on the brand name, so for any target whose name is a common/dictionary word, the output is dominated by assets belonging to UNRELATED same-named companies (repos, cloud buckets, mobile apps, breach corpora, typosquats). Built from an authorized engagement where an ASM report's "Criticals" were overwhelmingly false positives and the combo/repos/mobile/bucket lists were polluted with unrelated same-named orgs. Use at the START of any engagement, immediately on receiving any ASM/recon/OSINT dataset, BEFORE testing anything.
---
---

## When to use this skill

Trigger when:
- The target brand is a common/dictionary word or shared term (e.g. `apex`, `summit`, `vertex`, `nova`, `core`, `orbit`, `pulse`, `unity`…)
- You receive an ASM report, recon export, breach combo, repo list, bucket list, or mobile-app list to act on
- A "Critical" count looks implausibly high (hundreds) for the org's size
- Any asset's ownership is asserted by the tool but not *proven*

The two failure modes this skill prevents:
1. **Wasting the engagement** testing/triaging assets that aren't the target's.
2. **Attacking an innocent third party** that merely shares the name — out of scope, and real harm.

**Rule: ownership is guilty-until-proven. An asset is the target's only when a concrete ownership signal ties it to the target — never because a scanner's keyword matched.**

---

## The collision sources (where keyword-matching lies)

| Recon source | How it collides | Verify ownership by |
|---|---|---|
| **GitHub repos** | Search matched the brand word in repo name / topic / a string | Repo owner is the org's GH org; commits from org emails; code references the org's real domains/infra. A repo named `<word>-backend` by a random user = noise. |
| **Cloud buckets** (S3/GCS) | Bucket names are a **global namespace**; `<word>-static`, `<word>-data`, `<word>-public` exist for *someone* | Bucket content references the target; bucket name correlates with a *confirmed* target subdomain (`x.target.com` ↔ `x-public`) AND content matches; ACL/owner metadata. Generic content (other-language, other-industry) = not theirs. |
| **Mobile apps** | Store search matched the brand word in app name / package | Publisher account = the org; package reverse-DNS = an owned domain (`com.<owneddomain>.app`); dev cert; app calls owned API hosts. Mature ASM tools emit an "apps_accepted=0" / ownership-confidence field — read it. |
| **Breach corpora / combos** | Email local-or-domain contains the brand word | **Exact** owned-domain match only (`@target.com`), not `@<word>group.com` / `@something<word>.com`. A different domain that contains the word is a different org. |
| **Typosquats** | Generated permutations of the name | These are *defensive*/brand-protection findings, not offensive scope — note and move on. |
| **Stack/forum/paste hits** | Brand word in body | Body references the target's real domain/subdomain/employee/secret. Ownership-confidence < threshold = drop. |

---

## Web "Critical" triage — the soft-404 control

Automated `.env` / `.git` / `actuator` / admin-panel "Criticals" are overwhelmingly **soft-404s**: SPA/framework catch-alls returning HTTP 200 (or 403) for *every* path. Verify EACH before believing it:
```bash
# the "finding"
curl -s -o /tmp/a -w "%{http_code} %{size_download}\n" https://host.target.com/.env
# a junk control on the same host
curl -s -o /tmp/b -w "%{http_code} %{size_download}\n" https://host.target.com/zzz-nonsense-$RANDOM
# identical byte length / body  →  FALSE POSITIVE (catch-all), discard
cmp -s /tmp/a /tmp/b && echo "SOFT-404 false positive" || echo "differs — investigate"
```
Real exposures have a content-type + signature that differs from the catch-all (`.git/config` starts `[core]`; `.env` has `KEY=value`; phpinfo has the XHTML-transitional doctype + `PHP Version`). A physical `.php`/`phpinfo.php` that returns a *bigger/different* body than the junk control is the real-vs-soft-404 tell.

---

## The triage workflow

1. **Confirm the canonical owned-domain set first** (the SOW/program domain + its verified subdomains + the verified Entra/Okta/Google tenant brand name). This is your ownership anchor.
2. **For each asset class, apply the verify-by column above.** No signal → quarantine, don't test.
3. **Re-baseline the severity counts** against only-owned assets. Report the *delta* — "N Criticals → M after ownership + soft-404 triage" is itself a finding about the ASM program.
4. **Quarantine collisions explicitly** (a `loot/quarantined_<source>.txt`) so it's auditable that you saw them and chose not to target them.
5. **Surface the meta-finding:** if the supplied ASM/recon feed is mostly false-positive, that misallocates the owner's remediation budget and buries real risk — write it up (Medium/Strategic).

---

## Anti-patterns

- **Trusting the tool's "owned" label.** Tools keyword-match; they don't prove ownership. Verify.
- **Targeting a same-named third party** because it was "in the report." Out of scope + real harm. A combo line `user@<word>company.com` is a different company's employee.
- **Reporting soft-404s as exposures.** Always run the junk-path control.
- **Counting typosquats / missing-headers / brand-collision repos as offensive findings.** They're defensive/hygiene/noise — they pad the report and erode credibility.
- **Skipping triage "to save time."** Untriaged, you spend the whole engagement on other people's assets and find nothing real.

---

## Why this matters (calibration)

For a target whose brand is a common word, expect the bulk of automated "owned" assets to be collisions:
- **Repos** that are unrelated open-source projects (ad-block lists, scrapers, student projects, a different company's SDK) merely containing the word.
- **Mobile apps** published by entirely different companies that share the name — banks, credit unions, dating apps, dispensaries, home-care services are all real-world collision categories. (Good ASM tooling will tell you it accepted *zero* as owned.)
- **Cloud buckets** in the global namespace holding some unrelated org's content (other-language documents, demo/sample data, another industry's files).
- **Breach combos** full of emails from sibling-named-but-different companies (`<word>group.com`, `<region><word>.com`).

On a real engagement against a dictionary-word brand, after clearing this noise the only genuinely-owned high-severity finding was discoverable solely by manual tradecraft (a JS-bundle → API discovery, see `hunt-spa-api`) — it was nowhere in the hundreds of scanner "Criticals." Triage-first is what made the engagement productive instead of a goose chase.

---

## Related Skills & Chains

- **`triage-validation`** — asset-ownership triage (this skill) precedes finding-validity triage (the 7-Question Gate). Ownership first, then validity.
- **`redteam-mindset`** — "aggressive default" means probe every *owned* live surface; this skill defines which surfaces are owned so persistence isn't wasted on collisions.
- **`hunt-spa-api`** — once an API host passes ownership triage, this is how you test it.
- **`offensive-osint` / `osint-methodology`** — feed ownership anchors (verified domains, tenant brand, dev accounts) from OSINT into this triage.

## READ THE PROGRAM SCOPE FROM THE DATABASE, NEVER FROM A HAND-TYPED LIST

Thirteen scripts carried a hand-typed out-of-scope list. Reading the authoritative scope
from the corpus DB's `programs` collection showed the Dell list is

```
educate.dell.com, console.dell.com,
console-test.dell.com, salesproductivity.dell.com
```

and **`console.dell.com` was missing from every one of my lists** — I had
`console.delltechnologies.com`, which is a *different host*. A one-character-shifted
neighbour in a hand-typed list is invisible until a count comes out wrong.

```python
for d in db.programs.find({}):
    for s in (d.get("scopes") or []):   inc.add(s.lower())
    for s in (d.get("ooscopes") or []): oos.add(s.lower())
```

### Two facts bound the severity — state both, gloss neither

When the leak is found, separate these, because they are different claims:

* **Was an out-of-scope host REQUESTED?** Walk every artifact and collect the hosts
  sitting under a request/URL key, then check each against the DB scope. In this case:
  **0 out-of-scope hosts requested across 14 artifacts** — the phases that leaked read an
  archive and send no HTTP at all. The defect was a **count**, not traffic.
* **Was it still wrong?** Yes. A population that counts an out-of-scope host is incorrect
  regardless of how it was obtained, and the same list fed the *deciding* phases where a
  request **would** have gone out.

### Fix the gate, not the edit — and then MEASURE the gate

Editing the list leaves the next typo free to do the same thing. Make scope come from the
DB in every script, and add a phase that re-derives it and **fails loudly if any artifact
requests an out-of-scope host**. Then re-generate the affected artifacts and update the
counts in the note — stating the delta (`framable 1,548 -> 1,547`), not applying it
silently.

The verifier must then assert the NEW value AND require the note to disclose why it
changed. A verifier that keeps asserting the old number will fail the moment you fix the
bug, and "the verifier is red because I corrected the scope" is exactly the kind of noise
that gets a real failure waved through.

### "Has an OOS check" is not "rejects the OOS host"

After patching every request-making script, an inspection says "all guarded". The
inspection was wrong in **11 of 50** scripts, and nothing in the code made it visible:
those 11 *did* call an out-of-scope check, but their own `OOS` tuple was missing
`console.dell.com` — the same hand-typed gap one layer down. True and false at the same
time.

Measure it by **importing each script's real `in_scope()`** and feeding it the cases:

```python
# MUST BE REJECTED
console.dell.com, console-test.dell.com, educate.dell.com,
salesproductivity.dell.com, partner.digicert.com, partners.digicert.com,
x.console.dell.com,                 # a SUBDOMAIN of an OOS host
console.dell.com.evil.example       # a crafted suffix
# MUST BE ACCEPTED
www.dell.com, dell.com, www.delltechnologies.com, www.indeed.com,
id.indeed.tech, one.digicert.com
# PARSE
CONSOLE.DELL.COM -> reject;  console.dell.com:443 -> reject;
console.dell.com. -> reject;  WWW.DELL.COM -> accept
```

Report an import that raises as **NOT-TESTABLE**, never as passing. This is not
theoretical: the fix for those 11 tuples was applied with a regex that captured the
closing paren of the tuple and deleted it, leaving `'(' was never closed` in 11 files.
A suite that counted them as passing would have shipped 11 broken scripts and called it
green. After repair: 50/50 pass, 0 not-testable.

### Fixing the guard can invalidate numbers in EARLIER notes

The corrected guard changes what an old script returns, so an old note's figure can
become wrong the moment you fix the gate — and a verifier that re-derives from the live
script will go red. Do not "fix" that by restoring the old number. Re-derive, state the
delta, and require the note to disclose it.

Real case: `zd8`'s shape count was **8,448** and became **8,590**. The direction is the
point — the old guard tested only the allow-list, so it *accepted* the out-of-scope
`partners.digicert.com`; the corrected one refuses it, and the new guard also stops
dropping hosts the old suffix test mishandled. **8,448 was a number that counted an
out-of-scope host**, and the only reason it surfaced was a verifier asserting against
live code instead of a frozen artifact.
