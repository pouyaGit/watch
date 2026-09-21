# AEC-1 Pilot Selection — Approval Sheet

- Rule version: `aec-selection/v1`
- Approval sheet version: `aec-approval-sheet/v1`
- Cases considered: 144
- Selected: 11
- Excluded: 133

> NOT_CONFIRMED: this selection is a work plan for a bounded read-only observation pilot. No vulnerability is confirmed, implied or claimed, and no finding exists or can be created by this phase.

## 1. Approval request

Approval of this selection authorizes **nothing on its own**. It is the P1 input to the AEC-1 gate chain: the operator still has to grant a per-host authorization (P2), approve the per-case observation plans (P3) and start the run (P4).

Requested by: AEC-1 pilot selector (automated, offline).
Decision required from: operator (Authorization Officer).

Proposed distinct hosts:

- `hiringlab.indeed.com` — 5 case(s)
- `indeedflex.com` — 2 case(s)
- `investors.delltechnologies.com` — 4 case(s)

## 2. Selected cases

### 1. `rj-35e22734bb1ac1a6` — IDOR_JSON_RESOURCE

- Host / endpoint / parameter: `hiringlab.indeed.com` `/au/wp-json/wp/v2/pages/{id}` `id`
- Method / category / confidence: `GET` / `idor` / `MEDIUM`
- Risk category: `R1_OBJECT_REFERENCE`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: authorization comparison, object ownership context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): authorization comparison, object ownership context
- What the pilot would attempt: read two distinct publicly listed object references and compare bounded response metadata (status, length, digest) → response difference

### 2. `rj-188a6063bb23e899` — IDOR_JSON_RESOURCE

- Host / endpoint / parameter: `hiringlab.indeed.com` `/en-ca/wp-json/wp/v2/pages/{id}` `id`
- Method / category / confidence: `GET` / `idor` / `MEDIUM`
- Risk category: `R1_OBJECT_REFERENCE`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: authorization comparison, object ownership context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): authorization comparison, object ownership context
- What the pilot would attempt: read two distinct publicly listed object references and compare bounded response metadata (status, length, digest) → response difference

### 3. `rj-aac47f960c2231ec` — IDOR_JSON_RESOURCE

- Host / endpoint / parameter: `hiringlab.indeed.com` `/en-ca/wp-json/wp/v2/posts/{id}` `id`
- Method / category / confidence: `GET` / `idor` / `MEDIUM`
- Risk category: `R1_OBJECT_REFERENCE`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: authorization comparison, object ownership context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): authorization comparison, object ownership context
- What the pilot would attempt: read two distinct publicly listed object references and compare bounded response metadata (status, length, digest) → response difference

### 4. `rj-07c189f6587c17b2` — IDOR_JSON_RESOURCE

- Host / endpoint / parameter: `hiringlab.indeed.com` `/fr-ca/wp-json/wp/v2/pages/{id}` `id`
- Method / category / confidence: `GET` / `idor` / `MEDIUM`
- Risk category: `R1_OBJECT_REFERENCE`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: authorization comparison, object ownership context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): authorization comparison, object ownership context
- What the pilot would attempt: read two distinct publicly listed object references and compare bounded response metadata (status, length, digest) → response difference

### 5. `rj-55fec72aea846ae7` — IDOR_JSON_RESOURCE

- Host / endpoint / parameter: `hiringlab.indeed.com` `/fr/wp-json/wp/v2/pages/{id}` `id`
- Method / category / confidence: `GET` / `idor` / `MEDIUM`
- Risk category: `R1_OBJECT_REFERENCE`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: authorization comparison, object ownership context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): authorization comparison, object ownership context
- What the pilot would attempt: read two distinct publicly listed object references and compare bounded response metadata (status, length, digest) → response difference

### 6. `rj-a20be2a89b88013a` — IDOR_JSON_RESOURCE

- Host / endpoint / parameter: `indeedflex.com` `/wp-json/wp/v2/faq/{id}` `id`
- Method / category / confidence: `GET` / `idor` / `MEDIUM`
- Risk category: `R1_OBJECT_REFERENCE`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: authorization comparison, object ownership context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): authorization comparison, object ownership context
- What the pilot would attempt: read two distinct publicly listed object references and compare bounded response metadata (status, length, digest) → response difference

### 7. `rj-e6720ce091c4cd65` — SSRF_OEMBED

- Host / endpoint / parameter: `indeedflex.com` `/es/wp-json/oembed/1.0/embed` `url`
- Method / category / confidence: `GET` / `ssrf` / `MEDIUM`
- Risk category: `R2_SERVER_FETCH`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: baseline response, remote-resource response behavior, network context, response difference
- Evidence stated missing (the gap this pilot would close): response difference
- Stored artifacts collected: HTTP_METADATA, PARAMETER_BEHAVIOR, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): baseline response, remote-resource response behavior, network context
- What the pilot would attempt: read the endpoint once as a baseline and once with one safe, non-forbidden url-shaped value, comparing bounded metadata → parameter behaviour + response difference

### 8. `rj-6463850641171c86` — XSS_REFLECTED

- Host / endpoint / parameter: `investors.delltechnologies.com` `/financial-information/sec-filings` `q`
- Method / category / confidence: `GET` / `xss` / `MEDIUM`
- Risk category: `R3_REFLECTION`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: reflection confirmation, encoding context, execution context
- Evidence stated missing (the gap this pilot would close): encoding context
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): reflection confirmation, execution context
- What the pilot would attempt: read the parameter raw and encoded, comparing bounded metadata → encoding context

### 9. `rj-8bf993e6a77d67a1` — XSS_REFLECTED

- Host / endpoint / parameter: `investors.delltechnologies.com` `/node/{id}` `q`
- Method / category / confidence: `GET` / `xss` / `MEDIUM`
- Risk category: `R3_REFLECTION`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: reflection confirmation, encoding context, execution context
- Evidence stated missing (the gap this pilot would close): encoding context
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): reflection confirmation, execution context
- What the pilot would attempt: read the parameter raw and encoded, comparing bounded metadata → encoding context

### 10. `rj-bfd6d77bc11dbc00` — XSS_REFLECTED

- Host / endpoint / parameter: `investors.delltechnologies.com` `/node/{id}/ics` `Q`
- Method / category / confidence: `GET` / `xss` / `MEDIUM`
- Risk category: `R3_REFLECTION`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: reflection confirmation, encoding context, execution context
- Evidence stated missing (the gap this pilot would close): encoding context
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): reflection confirmation, execution context
- What the pilot would attempt: read the parameter raw and encoded, comparing bounded metadata → encoding context

### 11. `rj-c8d390a112982432` — XSS_REFLECTED

- Host / endpoint / parameter: `investors.delltechnologies.com` `/node/{id}/pdf` `Q`
- Method / category / confidence: `GET` / `xss` / `MEDIUM`
- Risk category: `R3_REFLECTION`
- Evidence ladder: `L0_STORED_OBSERVATION` → `L3_COMPARATIVE`
- Evidence required: reflection confirmation, encoding context, execution context
- Evidence stated missing (the gap this pilot would close): encoding context
- Stored artifacts collected: HTTP_METADATA, TECHNOLOGY_CONTEXT
- Stored artifacts still missing: RESPONSE_COMPARISON
- Required evidence not listed as missing (no claim that an artifact exists): reflection confirmation, execution context
- What the pilot would attempt: read the parameter raw and encoded, comparing bounded metadata → encoding context

## 3. Excluded cases and reasons

Every considered case receives exactly one outcome.

| Reason | Cases | Meaning |
|---|---:|---|
| `AUTH_REQUIRED` | 12 | Parameter or endpoint is consistent with a session, credential or identity context. The pilot holds no identity and must not acquire one (Phase 2 owns identity custody). |
| `CATEGORY_OUT_OF_PILOT` | 34 | The case does not belong to any of the three pilot families (IDOR wp-json resource, SSRF oEmbed proxy, reflected XSS query). |
| `CHALLENGE_TOKEN` | 1 | Parameter is a bot-management / challenge token. Contacting it would probe a protection mechanism and cannot produce research evidence. |
| `FAMILY_CAP_FULL` | 1 | The case's pilot family has already reached its cap. |
| `HOST_BUDGET_FULL` | 27 | Per-host request budget for this host is already fully allocated by higher-priority cases. |
| `LOGIN_ENDPOINT` | 33 | Endpoint is a login / account / SSO / authorization surface. The pilot never touches authentication surfaces. |
| `NON_GET_METHOD` | 9 | Case is not a GET (GET and HEAD are the only methods the pilot may use). State-changing methods are out of scope. |
| `UPLOAD_CATEGORY` | 16 | File-upload candidate. The pilot never uploads anything. |

Excluded case ids by reason:

- **AUTH_REQUIRED** (12): `rj-1586b1f3493185bc`, `rj-54b9c1d087fc9fde`, `rj-b9bbb545a29dd873`, `rj-ee51069c20b113b7`, `rj-ba65fbb49ebe8713`, `rj-5ea8858d0aa4be7f`, `rj-d471f3a5b91fee3b`, `rj-dafc6dbd60cb121a`, `rj-59f8828912d9c42b`, `rj-701ac5d617285a6a`, `rj-0c4aa5118dfa51d1`, `rj-56469e6406d44113`
- **CATEGORY_OUT_OF_PILOT** (34): `rj-3ac097d8e2884bab`, `rj-0521259c7db689f7`, `rj-e6764519c5e493cd`, `rj-2b2a837401f94a55`, `rj-fcfc1a920c76e262`, `rj-2338ad78645d30ca`, `rj-4bacd05d99723235`, `rj-92d72d81aeb34dbf`, `rj-38102d33537fd096`, `rj-555ed038cb7fcc93`, `rj-41741781fe60c384`, `rj-5acd66697524760c`, `rj-a24fa571a00a193f`, `rj-c15b8bbeaa7f7079`, `rj-0b9eb0a82635a797`, `rj-dde1597a3660c0fe`, `rj-87b9ba8384a5946c`, `rj-c95c62a002e68bc3`, `rj-3e949e9b227480b7`, `rj-ed3aff294bf1d447`, `rj-ada0c71c05dc2e9b`, `rj-a36dcfc5a99a09aa`, `rj-3306ddb94f69b93b`, `rj-2fb7d883513ec3ca`, `rj-b89870785f9a2d77` … (+9 more)
- **CHALLENGE_TOKEN** (1): `rj-67441d581c069f3d`
- **FAMILY_CAP_FULL** (1): `rj-d535af0180bc5bd6`
- **HOST_BUDGET_FULL** (27): `rj-72cb4cf27ece9170`, `rj-d29694201d30b027`, `rj-5d450b7dc658efab`, `rj-e92a8f61b77d1ab4`, `rj-eef65f3ae31f454a`, `rj-d83f0e47c227e83b`, `rj-8fd83e2c70827b68`, `rj-03971306edaf01f1`, `rj-984a0cf3f9103342`, `rj-bc8a7fb0fbc29446`, `rj-0dc01dfbb4d66483`, `rj-e18f6d44747df83a`, `rj-fcf0843050c11d1b`, `rj-2c90287bfd059192`, `rj-3d91ae13b4500c8a`, `rj-d0d081d065ee1708`, `rj-17cd3546e23a133f`, `rj-5ff09bad533bf6a6`, `rj-86e3cc87077fde18`, `rj-71a790c3fe5373ff`, `rj-d4731468176f3472`, `rj-a936a6914c335c4d`, `rj-655c5b015b7a5b7c`, `rj-d2c1c0399d5bfb1f`, `rj-b681d1c9fa57cdb0` … (+2 more)
- **LOGIN_ENDPOINT** (33): `rj-40fbd672b5a274b1`, `rj-95f3d8e9f022eea2`, `rj-e6c998d01fb85baa`, `rj-633de987bcbd141e`, `rj-b84894746d8f1196`, `rj-545cf890bfbe31ab`, `rj-7b34bc1b1bf59b48`, `rj-a9b84b5eeb79dfc7`, `rj-9514259201db4e32`, `rj-1b0fe353abfbc40b`, `rj-c07efd763747851f`, `rj-250e73a53ae1d7c8`, `rj-a3a7b6f5e10b3d73`, `rj-589934b716c15e75`, `rj-7cd20d6d2a556a35`, `rj-2335bf6d8ced2df8`, `rj-3e3cf95077f83636`, `rj-3607f6bcb271b53f`, `rj-f9317fe71b48e1a9`, `rj-66b17eac78d238bf`, `rj-061237c70152fa25`, `rj-04ffa38bb4045257`, `rj-b7d6389cd4c447ec`, `rj-f537815e14d2076a`, `rj-e68aa53b56e8f50a` … (+8 more)
- **NON_GET_METHOD** (9): `rj-beec4187ec188943`, `rj-6041d7ce60f4ed90`, `rj-ac0f6b341c889699`, `rj-089265f8fe9fce4d`, `rj-5e49d890613c4f98`, `rj-831be66bdbd79586`, `rj-c07d6372fb2cdc6a`, `rj-c1ee56d44426da30`, `rj-debb6197c5414e77`
- **UPLOAD_CATEGORY** (16): `rj-14544e987a9001ac`, `rj-915f874db91c2add`, `rj-8df2403e9f944999`, `rj-685f61df9a2021d4`, `rj-0d66dd351a6f960b`, `rj-10c9814a24fe5f58`, `rj-62c4a30ce712aca6`, `rj-312ad22f5ba852c0`, `rj-a4dc3aa02463243d`, `rj-646680fe37f86889`, `rj-9045ab083cdff0f6`, `rj-b72d124e5c591483`, `rj-d2c28becbba0bef7`, `rj-e5aa1383487cc3f4`, `rj-305a6fbd4c34e91f`, `rj-6d69831e2aa47e0d`

## 4. Limits and budget

- Max cases: 20
- Max authorized requests (whole pilot): 60
- Max requests per case: 4
- Max requests per host: 5
- Distinct-host window: [3, 5]
- Min seconds between requests: 1.0
- Max concurrency: 1
- Max wall seconds per run: 600

Per-family usage (selected / cap):

- `IDOR_JSON_RESOURCE`: 6 / 10
- `SSRF_OEMBED`: 1 / 6
- `XSS_REFLECTED`: 4 / 4

Estimated worst-case request count for this selection: 11 × 4 = 44 (hard cap 60).

## 5. What this pilot will NOT do

- No contact with any target before a granted authorization exists.
- No payloads, no injection, no fuzzing, no browsers, no Nuclei, no uploads.
- No POST/PUT/PATCH/DELETE, no request bodies, no redirect following.
- No authentication, no session or identity acquisition.
- No severity assignment, no submission, no confirmed finding of any kind.
- No writes outside `ai_data/aec/` and `agent-reports/`.

Family descriptions:

- `IDOR_JSON_RESOURCE`: WordPress REST resource reference (wp-json wp/v2 resource + id-like parameter): two distinct public object references are comparable.
- `SSRF_OEMBED`: WordPress oEmbed proxy (wp-json/oembed + url-like parameter): the delivery behaviour of the remote-resource parameter is comparable.
- `XSS_REFLECTED`: Reflected query parameter on a public page: raw vs encoded delivery is comparable.
