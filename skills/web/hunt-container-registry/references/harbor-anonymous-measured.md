# Measured: Harbor anonymous access, `/v2` vs `/api/v2.0` (2026-10-24)

A real DigiCert Harbor instance, both hosts in scope. These are the observed
values, not theory. Total 37 requests, GET only, paced 1.2s.

## The two surfaces disagree

```
GET /v2/_catalog                -> 401   Docker Registry API, auth enforced
GET /v2/                        -> 401   challenge: Bearer realm=".../service/token",service="harbor-registry"

GET /api/v2.0/systeminfo        -> 200   {"auth_mode":"oidc_auth", "harbor_version":"v2.0.5-703debf6",
                                         "project_creation_restriction":"adminonly", "self_registration":false}
GET /api/v2.0/projects          -> 200   [{"name":"dcone","repo_count":25,"metadata":{"public":"true"}},
                                         {"name":"trustedge","repo_count":0,"metadata":{"public":"true"}}]
GET /api/v2.0/search?q=a        -> 200   18 repositories, every one project_public:true
GET /api/v2.0/health            -> 200   per-component status, "status":"unhealthy"

GET /api/v2.0/statistics        -> 401   <- correct scoping still exists elsewhere
GET /api/v2.0/users/current     -> 401
GET /api/v2.0/configurations    -> 401
GET /api/v2.0/registries        -> 401
```

Concluding "closed" from the `/v2` 401 would have missed everything.
Conversely the `/api/v2.0/statistics` 401 shows the instance is NOT wide open,
which is what makes the metadata exposure deliberate rather than a misconfig.

## Content access: token then blob

The registry's own 401 names the realm. An anonymous caller can obtain a pull
scope token — the standard registry flow, no credentials:

```
GET https://<host>/service/token?service=harbor-registry&scope=repository:dcone/<repo>:pull
-> 200, token issued
```

Then the content, which is the part that decides severity:

```
GET /v2/dcone/<repo>/manifests/latest
-> 200 946 bytes, 3 layers:
     sha256:8b3d7e22...b559    764,708 bytes
     sha256:72628ef0...5ae9      4,424 bytes
     sha256:b853b740...019b    9,145,683 bytes

GET /v2/dcone/<repo>/blobs/sha256:8b3d7e22...b559
-> 200, layer content, first bytes 1f8b0800...  (gzip magic = real content)
```

**The manifest is metadata; the blob is content.** A manifest lists digests and
sizes. Do not report on a manifest alone — fetch the blob and read its magic
bytes, because that distinguishes a directory listing from a readable image.

## Reading the pull counters before judging

```
dcone/account                      215,998 pulls
dcone/imauth                       190,959 pulls
dcone/certificate-authority        172,538 pulls
dcone/extauth                      169,819 pulls
dcone/signingmanager                63,479 pulls
...  18 repositories, 897,655 pulls total
```

Counters in the hundreds of thousands mean the exposure is **intended
distribution**, not an accident. Say so in the report — a triager will reach for
it immediately, and pre-empting it is what makes the rest of the finding
credible. The finding is then the contents and the naming: repositories called
`certificate-authority`, `signingmanager`, `imauth`, `ldapservice` hand an
anonymous attacker the built PKI service plus a validated inventory of internal
components.

## Companion repositories returning 404 is normal

`dcone/account` on `latest` / `v1` / `master` -> 404 on all three. Guessed tags
404; the tag list has to come from the artifacts API. This is not partial
exposure and must not be reported as such.
