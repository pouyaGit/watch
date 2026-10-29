# Verifying Skill provenance before trusting it

Run when seeding from public writeups, or reviewing an existing seed whose sources
were never HTTP-checked.

## The check that matters

Content validation does not test a citation. A seed can pass every schema gate
while its sources are dead links.

```sh
# collect every locator, then status-check each
for u in <locators>; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 12 "$u")
  echo "$code  $u"
done
```

- Verify with the status code, not with a content-extraction tool. A keyless
  extractor reports "Not found" for pages that are live, so a tool error is not
  evidence of a bad URL — confirm with `curl` before recording a defect.
- A doubled path segment (`/web-security/web-security/<topic>`) is the signature
  of a reorganised doc site, not a typo. Replacements are the SAME topic at the
  new path, each re-checked to 200.
- CWE ids are cheap to validate: the reference is well-formed and, separately,
  present in the local knowledge table. An id absent from local CVE knowledge
  cannot be corroborated locally, which is a finding to report, not a reason to
  delete the artifact.

## What "source supports the concept" means

A PortSwigger or CWE citation on a record proves nothing about whether the record
is correct. Check that the source's subject matches the Skill's family, and treat
a URL as evidence of provenance only — never as evidence of correctness. Domain
truth needs a human; the gate verifies form.

## Recording the outcome

Apply corrections as new versions. Report separately: locators that were dead,
what each was replaced with, how many skills were affected, and the post-fix
count of live links. Preserve the prior version as the record of the earlier
belief.
