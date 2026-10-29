---
name: hunt-container-registry
description: "Hunt exposed container registries and their image secrets."
---

# HUNTING AN EXPOSED CONTAINER REGISTRY

A registry is a **content store**, not an app. Finding one is easy; deciding whether it is
a *bug* is where the work is. The whole question is answered by reading the content and
asking "what did the owner intend to publish?"

---

## STAGE 0 — IDENTIFY THE REGISTRY AND ITS API

| Vendor | Management API | Pull API | Signature |
|---|---|---|---|
| Harbor | `/api/v2.0/...` | `/v2/...` | UI title "Harbor", `X-Request-Id` |
| Artifactory | `/artifactory/api/...` | `/artifactory/<repo>/...` | `X-JFrog-Art-Api` header |
| Nexus | `/service/rest/v1/...` | `/repository/<name>/...` | `X-Nexus-UI` |
| GitLab | `/api/v4/projects?...` | `/v2/<project>...` | `X-Gitlab-Token` hints |
| ECR / GCR | AWS / GCP auth | `*.dkr.ecr.*/v2/...` | 401 + `WWW-Authenticate` |

Read the **health** endpoint first — it names the exact version:

```bash
curl -sk https://REG/api/v2.0/health | jq .        # Harbor
curl -sk https://REG/api/v2.0/systeminfo | jq .   # Harbor: version + storage config
```

## STAGE 1 — THE AUTH MATRIX (do this FIRST, it decides everything)

Measure which endpoints need a credential and which do not. The pattern that matters:

```
/api/v2.0/projects     200   <- public project list
/api/v2.0/users        401   <- auth required
/api/v2.0/registries   401   <- auth required
```

A registry where **user and registry listings require auth but the project list does not**
is behaving normally. A registry where `/users` returns 200 is a different, much stronger
finding (user enumeration / account takeover surface) — check it explicitly, do not assume.

## STAGE 2 — READ THE PROJECT METADATA, AND BELIEVE IT

```bash
curl -sk https://REG/api/v2.0/projects | jq '.[] | {name, metadata}'
```

**`metadata.public: "true"` is the owner telling you the project is meant to be public.**
That single field is usually the whole verdict. A public project on a public registry is
a *configuration*, not a *misconfiguration* — there is no control that should have applied
and did not. Do not write this up as "unauthenticated access to a private registry".

Watch for the inverse case, which IS a finding: `metadata.public: "false"` (or absent)
on a project whose contents are readable anyway. That means the project is marked private
but the pull path does not enforce it. **Check the flag before you check the content** —
it is the difference between a report and a note.

## STAGE 3 — THE PULL API IS A DIFFERENT PATH SPACE

Harbor's management API and the Docker Registry v2 API do not share paths:

```
/api/v2.0/projects/dcone/repositories/<repo>/artifacts   <- management
/v2/<repo>/tags/list                                     <- Docker Registry v2
/v2/<repo>/manifests/<tag>                                <- Docker Registry v2
/v2/<repo>/blobs/<digest>                                 <- Docker Registry v2
```

A request to a `/v2/` path with the wrong `Accept` header falls back to the **SPA
index.html** — a ~850-byte HTML page, not JSON, and not a 404. That is a common
false-negative source. Send the right header:

```bash
curl -sk -H 'Accept: application/vnd.oci.image.index.v1+json' \
     https://REG/v2/<repo>/manifests/<tag>
```

Registry responses are **content-negotiated**. Without the right `Accept` you get
`"OCI index found, but accept header does not support OCI indexes"`, or the SPA page.
Always set the Accept header explicitly and assert the response is JSON.

## STAGE 4 — THE IMAGE CONFIG IS WHERE THE SECRETS ARE

The manifest gives you the config digest. The config blob holds the ENV, the labels, the
build history, and the entrypoint. **Read it for every image, not a sample** — a secret
is in one image out of forty.

```bash
CFG=sha256:<config digest from the manifest>
curl -sk https://REG/v2/<repo>/blobs/$CFG | jq '.config.Env, .config.Labels, .history'
```

Classify every ENV value into three buckets, not two:

| Bucket | Meaning | Verdict |
|---|---|---|
| populated and secret-shaped | a real credential | **reportable** |
| present but EMPTY (`API_KEY=""`) | injected at runtime | not a credential |
| populated and non-secret (e.g. `ENCRYPTION_TEXT=DigiCertContentSigningService`) | config/label | not a credential |

The middle bucket is the one that fools people. A config template with
`MySQLPassword=""`, `MasterSecret=""`, `APIKey=""` is a **template**, and a template in
a public image is documentation, not a leak. Report the *empty* template as nothing.

**A SECRET-SHAPED LINE IS NOT A SECRET, AND UI TRANSLATION FILES ARE THE WORST
OFFENDER.** A CA image that ships twelve translation files will produce hundreds of
hits that look exactly like leaked credentials:

```
"password": "密码"
"the password is incorrect"
"remember your password!"
```

Every one of those matches a password-shaped pattern. Classify every hit into four
buckets and report the first one alone:

| Bucket | Meaning |
|---|---|
| a real credential | an assignment whose value is a NON-EMPTY secret-shaped string |
| an empty slot | `Key=""` — a runtime injection point |
| a documentation line | a `#` comment that describes a secret |
| a false positive | a UI translation string, or a line that mentions a secret word without being an assignment |

A 587-line sweep that produced **552 translation strings** and **zero** real
credentials is a different result from "587 credential-shaped lines" — and only the
first one is a claim a reader can check. Run an INDEPENDENT sweep as well: every
assignment in every extracted file, not just the regex-matched ones. If the
independent sweep also finds zero non-empty values, the verdict is solid.

**A TEMPLATE LISTS EVERY OPTION, INCLUDING THE DANGEROUS ONES.** Read the comment
next to each interesting setting, and do not confuse "the template mentions `demo`"
with "the template IS `demo`":

```
# The type of authorization resolver to use for authentication. The
# types allowed are:
#   demo - Ignore authentication and use a demo user will all permissions.
#   ijwt - Use the Internal JWT (default).
AuthorizationResolver=""
```

A blank value means the **default** (`ijwt` — real authentication), not `demo`. A
template that lists `demo` as an option is not running as `demo`. Similarly a setting
called `Mode = "dev"` may be the *analytics* mode ("if analytics are enabled, what
mode? Only dev, stage, or prod are allowed"), not an application dev mode. Read the
comment; do not infer from the key name.

A populated secret-shaped ENV is reportable **only if it is a working credential** — a
live key, a real password, a valid token. Prove it works against the service it belongs
to before you write the report.

## STAGE 5 — THE BUILD HISTORY IS THE REAL FINDING SOURCE

`config.history` records every `RUN`/`COPY`/`ENV` instruction of the build. It is where
these live:

* `wget`/`curl` to an **internal registry or artifact host** — discloses internal
  hostnames that do not resolve publicly. A hostname that resolves nowhere is a naming
  detail, not an access path.
* `COPY` of a **config file** — read it from the layer blob. A copied `.toml`/`.yaml`
  is usually a template; a copied `.env`/`.properties` may not be.
* `ADD` of a **binary bundle** — a client app, a proxy agent, an SDK. It tells you what
  the service talks to.

## STAGE 6 — READ THE LAYERS FOR THE FILES THE HISTORY PROMISES

```bash
# the manifest lists layers; each layer is a tar.gz with a diff
curl -sk https://REG/v2/<repo>/blobs/<layer digest> | tar tzf - | head -50
```

Pull only the layers that contain the file the history names, and only the specific
member — a CA image layer can be hundreds of MB.

**The highest-value file in a container image is usually the API specification.** A
`swagger.yaml`/`openapi.json` copied into an image is the complete endpoint inventory of
a service that may not be publicly reachable. Read it, and then **test whether the
service is reachable**: probe the documented base path on every candidate public host.

```
swagger.yaml documents basePath /certificate-authority/api/v1 with 23 endpoints
6 hosts x 4 CA paths = 24 requests -> 0 reachable
-> the SPEC is public, the SERVER is not. Nothing to report.
```

A public spec with a private server is a note. A public spec **with** a reachable server
and unauthenticated endpoints is a real finding, and the spec hands you the exact paths.

## STAGE 7 — READ THE ACCOUNT FILES (the layer member list is not a read)

A member listing that shows `etc/passwd` and `etc/shadow` is a **promise**, not a
reading. A member filter that pulls only `/etc/*.conf` and config-shaped files will
list them and never open them — and `/etc/shadow` in a public image is exactly the file
worth opening.

Pull the layer that holds them and extract the specific members:

```bash
curl -sk https://REG/v2/<repo>/blobs/<layer digest> | tar xzO etc/shadow
curl -sk https://REG/v2/<repo>/blobs/<layer digest> | tar xzO etc/passwd
```

Then read them correctly. **The second field of `/etc/passwd` is a PASSWORD REFERENCE,
not a password.** On a normal system it is the literal `x`, meaning "look in
`/etc/shadow`". A line-level check that treats any non-empty second field as a
password reports all 19 stock accounts as 19 fake credentials.

```
/etc/shadow : every entry is '*' (no password) or '!' (locked)  ->  0 hashes
/etc/passwd : every second field is 'x'                          ->  0 passwords
```

The one thing worth keeping is the **non-stock service account** — the account the
container actually runs as:

```
caadmin   uid=1000   gid=1000   home=/home/caadmin   shell=/bin/bash
```

A dedicated account with a login shell confirms what the image is for. A name and a
uid are not a credential: no password, no home contents, no key.

## STAGE 8 — THE REPORTABILITY BAR

Ask all four, in order:

1. **Is the project flagged public by the registry itself?** If yes → not a finding.
2. **Is there a populated, working credential?** If no → the content is templates and
   build metadata.
3. **Is the service that the content describes reachable publicly?** If no → the content
   is documentation of a private system.
4. **Is there a control that SHOULD have applied and did not?** (a project marked private
   but publicly readable, an API that should require a token and does not)

**All four must be answered before a report is written.** If the honest answer to 1, 2
and 3 is "no", the finding is a NOTE.

## WHAT IS ACTUALLY REPORTABLE HERE

| Situation | Verdict |
|---|---|
| project marked public, only templates and empty configs | note |
| project marked public, image contains a WORKING credential | **reportable — credential exposure** |
| project marked PRIVATE but its images are pullable | **reportable — access control bypass** |
| `/users` or `/registries` listable without auth | **reportable — user/registry enumeration** |
| a public image contains a private key, a token, or a live password | **reportable** |
| an internal registry hostname in the build history, host does not resolve | note |
| a public swagger.yaml for a service no public host serves | note |
| a public swagger.yaml for a service that IS publicly reachable and unauthenticated | **reportable — undocumented API** |
| a directory listing of image tags with nothing sensitive behind it | note |

## PITFALLS THAT COST TIME

* **Do not treat the management API as the pull API.** `/api/v2.0/...` and `/v2/...` are
  different path spaces, and the `/v2/` one needs a media-type `Accept` header.
* **Do not count an empty ENV as a secret.** `API_KEY=""` is a runtime injection point.
* **Do not count a UI translation string as a secret.** `"password": "密码"` is a
  label, not a credential. Classify the hits before you count them.
* **Do not infer a config's state from its key name.** `Mode = "dev"` may be the
  analytics mode; a blank `AuthorizationResolver` may be the secure default. Read
  the comment.
* **Do not count `/etc/passwd`'s second field as a password.** It is `x`, a shadow
  reference. Only the shadow file holds a hash.
* **Do not treat a member listing as a file read.** `etc/shadow` in the member list
  means the layer was never opened. Extract it.
* **Do not assume a `public: "true"` project is a misconfiguration.** It is the owner
  saying "publish this".
* **Do not skip the layers.** The interesting file is almost never the image config.
* **Do not report the spec without testing the server.** A spec for a private service is
  not an exposed API.
* **Do not use the registry's UI.** Drive the API; the SPA obscures status codes.
* **Watch the memory ceiling.** A CA image is hundreds of MB. Extract single members
  from single layers, never untar a whole image.
* **Beware the 850-byte SPA.** A JSON path that returns ~850 bytes of HTML is the SPA
  fallback, not an empty result.

## SCOPE

Pulling an image is a GET. But it is **not** an inconsequential GET: the act of pulling a
layer is a request that can trip a registry's pull-rate alerting, and pulling a
`latest` tag is a normal client behaviour that a real attacker also does. It is in scope
to pull public images from an in-scope registry. It is **not** in scope to pull from a
registry you found to be in scope when the program says otherwise, and it is not in
scope to try to authenticate with credentials you happen to find — finding a credential
and *using* it are two different authorizations.
