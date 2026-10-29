---
name: hunt-verbose-error-pages
description: "Triage verbose framework error pages and their ceiling."
---

# VERBOSE ERROR PAGES — FINDING THE CEILING BEFORE WRITING THE REPORT

A stack trace on an unauthenticated path is one of the most commonly over-claimed findings
in bug bounty. The same condition is **Low** in one deployment and **Critical** in the
next. The difference is entirely in the framework's behaviour, and it is **measurable**.

---

## STEP 1 — CONFIRM IT IS UNAUTHENTICATED AND UNIVERSAL

Two separate questions, and both must be answered:

* **Unauthenticated**: fetch the error path with no cookie jar, no `Authorization` header,
  no session. The error page must render with none of that.
* **Universal**: the error page must appear on paths that were never meant to exist, not
  only on one broken link. Sample 10 distinct unmapped paths; 10 of 10 means the
  condition is reachable by anyone at any path, with no need to trigger a specific error.

A single broken path is a bug in one feature. Every path is a deployment posture.

## STEP 2 — THE FRAMEWORK IS WHAT DECIDES THE SEVERITY

| Framework | dev flag | What the page shows | Exploitability question |
|---|---|---|---|
| **Struts 2** | `struts.devMode=true` | full Java stack trace + the fix instruction | **is OGNL evaluated?** |
| Django | `DEBUG=True` | settings, full traceback, local vars | is there a usable injection point? |
| Rails | `config.consider_all_requests_local` | full traceback + env | are the env vars dumped? |
| Spring Boot | — | stack trace, sometimes the config | actuator exposed? |
| ASP.NET | `customErrors` off | yellow screen, full traceback | is the source path disclosed? |

**Struts is the one to be most careful with**, because `devMode` is the visible half of
the OGNL-injection bug class. Read the stack trace for `AjpProcessor` — if AJP is
reachable, the deployment is a Ghostcat away from RCE, and the devMode page is a
symptom of a much bigger problem.

## STEP 3 — THE OGNL PROBE (Struts; this is the decision)

The question is binary: **does this deployment evaluate OGNL?** If yes, the devMode page
is the reader that makes the exploit *observable* and the finding is RCE. If no, the
finding is disclosure and nothing more.

Run the probe with **arithmetic only** (`1+1` against a `1` baseline). No shell, no file
read, no file write, no system call. A non-destructive expression is enough to answer
the question and cannot cause harm if it fires.

**The probe must be differential and must read the SERVER's response only.** Fetch the
same URL twice — once with a benign literal, once with the expression — and diff. A
result is only real if the payload's value appears in the *server-rendered* response and
not in the baseline. Parse the rendered message, not the raw body, and never read your
own client's error strings: a local `urllib` error like *"URL can't contain control
characters"* contains the payload and will make a naive detector report a reflection that
does not exist.

Probe shapes, in the order they are worth testing:

```
1  mapped action, expression in a query parameter
2  namespace manipulation in the path          (S2-057 shape)
3  the action: prefix                          (S2-061 shape)
4  expression in the bang method               (S2-062 shape)
5  expression in a plain unmapped action name
6  expression as the whole namespace
7  double namespace
8  a known-mapped action with an expression parameter
9  a second known-mapped action
```

Record, for each shape: baseline status/bytes/text-length, payload status/bytes/
text-length, whether the arithmetic result appeared, whether an OGNL error signature
appeared (`ognl`, `expression`, `NumberFormat`, `xwork2.injector`), and whether the error
page grew.

```
probe shapes run            : 9
arithmetic expressions evaluated : 0
OGNL error signatures       : 0
-> this deployment does NOT evaluate OGNL. Disclosure only. Low.
```

**A POST-only variant (S2-045's multipart trick) needs a POST body.** If there is no
blanket POST authorization, do not attempt it — record it as an untested variant in the
note, not as a failed test.

## STEP 4 — THE CEILING TESTS (six negative checks)

Run these against the rendered page and record every one. A report that states its
ceiling survives triage; a report that claims a stack trace is "sensitive information"
without testing what is in it does not.

1. **filesystem path** — `/usr/`, `/opt/`, `/etc/`, `/home/`, `/var/`, `WEB-INF`
2. **internal hostname** — `*.internal`, `*.corp`, `*.k8s`, `*.dev`, `*.stg`, `*.qa`, `*.prod`
3. **private IP** — `10/8`, `172.16/12`, `192.168/16`
4. **DSN** — `jdbc:`, `mongodb://`, `mysql://`, `postgres://`
5. **email address**
6. **credential** — `password=`, `secret=`, `token=`, `api_key=` with a value

All six coming back empty is what makes a Low-severity claim honest. If even one hits,
the severity goes up and the report has to say what it exposes.

Then the two structural negatives:

* **AJP is not exposed** — probe 8009, 8443, 8005, 8080, 8180 directly. Do not infer
  from the stack trace that the connector is closed.
* **the path/action name is not reflected** — send percent-encoded payloads and look for
  the token in the server-rendered message, raw AND HTML-escaped. If the action name is
  not reflected at all, there is no XSS here; say so in the report, because a triager
  will look for it.

## STEP 5 — IS THE APP ACTUALLY EXPOSED, OR JUST ITS FRONT DOOR?

A devMode error page proves the *error handler* is exposed. It does not prove the
*application* is exposed. Check the application's own pages:

```
/app/pages/SomeAction.action  -> 200 with title "page.missingAccount.window.title"
```

That title is the app saying it needs an account. If every application page answers
that way, then **no authenticated data is reachable** and the impact is disclosure of
the application's existence and version, nothing more. Report it that way.

Also check the **context path**: the application often lives one path down, behind a
default page at the root.

## STEP 6 — WHAT THE REPORT IS ACTUALLY WORTH

A defensible Low report contains:

* the product name, the **exact version** and the context path (the asset inventory);
* the frame count and the frame list;
* the vendor's own remediation text, quoted (it proves the state is not accepted);
* the **six negative ceiling checks**, stated as a table;
* AJP closed, the action name not reflected, OGNL not evaluated;
* the application's pages answer "missing account" — no data reachable;
* the explicit statement of what an attacker **cannot** do.

A report that says "this leaks sensitive information" without the negative checks will
be marked N/A for over-claiming. A report that says "33 frames, product version 1.2.8,
context path, framework internals, no credential, no path, no host, no data" is a
finding a triager can verify in a minute.

## THE NEVER-SUBMIT NEIGHBOUR

"**Banner / version disclosure without working CVE exploit**" is on the never-submit
list. A devMode page is *adjacent* to that, not the same thing — but the distinction
must be argued, not assumed:

* it is a rendered **exception stack trace on every unmapped path**, not a version
  string in a header;
* it names the vendor's own remediation instruction, which proves the state is a
  misconfiguration rather than a design decision;
* the report is filed at **Low** and claims no exploit.

If the OGNL probe had fired, this argument would collapse — the finding would be OGNL
injection, not information disclosure, and it would be Critical.

## REPORTABLE / NOT REPORTABLE

| Situation | Verdict |
|---|---|
| devMode on an unauthenticated path, no path/host/credential leaked, no exploit | **Low, reportable** |
| devMode + the page leaks a JDBC URL, an internal hostname or a private IP | Medium — the disclosure is now actionable |
| devMode + OGNL evaluates | **Critical/High — that is the finding, not the page** |
| devMode + AJP reachable | High — Ghostcat, RCE |
| devMode + the action name reflects raw | the XSS is a separate report; the devMode page is not the vector |
| the app's pages return real data to an anonymous visitor | the missing-auth is a separate report |
| the stack trace is on a path that needs a login | not reachable, not reportable |
| a stack trace on a stock demo page with no version and no context | Informational |
