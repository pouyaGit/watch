# R31.1 CWE Extraction Verification

## Status
PASS

## Code Verified
- Changed files:
  - `ai/knowledge/vulnerability_fingerprint.py` (untracked in git, contains R31.1 fix; `git log` returns no history for this path)
  - `ai/schemas/vulnerability_fingerprint.py` (untracked supporting schema, not modified by this task)
- Extraction strategy (as implemented in `ai/knowledge/vulnerability_fingerprint.py`):
  - `_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)` — case-insensitive CWE pattern.
  - `_normalize_cwes(values)` — uppercases, dedupes, preserves first-seen deterministic order.
  - `_extract_cwes(payload)` priority:
    1. Explicit lists first, first non-empty source wins:
       - `cve.cwes`
       - `metadata.cwes`
       - `research.cwe` (accepts `str` or `list`)
    2. Text fallback via `_CWE_RE.findall()` in order:
       - `research.vulnerability_type`
       - `research.title`
       - `research.summary`
    3. Returns `[]` if no source yields a CWE.
  - `build_vulnerability_fingerprint(payload)` sets `cwe=_extract_cwes(payload)`; matching logic elsewhere untouched.

## Test Commands
Exact commands executed.

Command 1 — required focused verification:
```bash
python - <<'PY'
from ai.knowledge.vulnerability_fingerprint import build_vulnerability_fingerprint
import json

for cve in [
    "CVE-2026-1557",
    "CVE-2026-78207",
]:
    with open(f"ai_data/research/{cve}.cli.json") as f:
        data=json.load(f)

    fp=build_vulnerability_fingerprint(data)

    print(cve)
    print(fp.model_dump())
    print()
PY
```

Command 2 — source-field inspection + No-CWE case:
```bash
python - <<'PY'
from ai.knowledge.vulnerability_fingerprint import build_vulnerability_fingerprint, _extract_cwes, _CWE_RE
import json

# Inspect source fields for both CVEs
for cve in ["CVE-2026-1557", "CVE-2026-78207"]:
    with open(f"ai_data/research/{cve}.cli.json") as f:
        data=json.load(f)
    print("="*60)
    print(cve)
    print("cve.cwes:", (data.get("cve") or {}).get("cwes"))
    print("metadata.cwes:", (data.get("metadata") or {}).get("cwes"))
    print("research.cwe:", (data.get("research") or {}).get("cwe"))
    print("research.vulnerability_type:", (data.get("research") or {}).get("vulnerability_type"))
    print("research.title:", (data.get("research") or {}).get("title"))
    print("research.summary:", repr((data.get("research") or {}).get("summary"))[:500])

# Case 3: No CWE payload
print("="*60)
print("Case 3: No CWE payload")
payload_no_cwe = {"cve": {"id": "CVE-0000-0000"}, "metadata": {}, "research": {"vulnerability_type": "Unknown", "title": "Some bug", "summary": "No CWE here"}}
fp = build_vulnerability_fingerprint(payload_no_cwe)
print(fp.model_dump())
print("cwe == [] ?", fp.cwe == [])
PY
```

Command 3 — git state:
```bash
git status --short
git diff --stat
```

## Results
Include real outputs.

### Command 1 output (verbatim):
```
CVE-2026-1557
{'cve_id': 'CVE-2026-1557', 'products': ['WP Responsive Images'], 'affected_products': ['WP Responsive Images (WordPress plugin)'], 'technologies': ['WordPress'], 'components': [], 'parameters': [], 'versions': ['<=1.0'], 'vulnerability_type': 'Path Traversal (CWE-22)', 'cwe': ['CWE-22'], 'sources': ['ai_data/research/*.cli.json'], 'rule_version': 'r31-1', 'research_only': True}

CVE-2026-78207
{'cve_id': 'CVE-2026-78207', 'products': ['exceljs'], 'affected_products': ['exceljs'], 'technologies': [], 'components': [], 'parameters': [], 'versions': ['<= 4.4.0'], 'vulnerability_type': 'Prototype Pollution (CWE-1321)', 'cwe': ['CWE-1321'], 'sources': ['ai_data/research/*.cli.json'], 'rule_version': 'r31-1', 'research_only': True}
```

### Command 2 output (verbatim):
```
============================================================
CVE-2026-1557
cve.cwes: None
metadata.cwes: None
research.cwe: None
research.vulnerability_type: Path Traversal (CWE-22)
research.title: WP Responsive Images plugin <=1.0 unauthenticated path traversal via 'src' parameter
research.summary: "Path traversal vulnerability in the WP Responsive Images WordPress plugin allowing unauthenticated attackers to read arbitrary files on the server via the 'src' parameter passed to image_handler.php. Affects all versions up to and including 1.0."
============================================================
CVE-2026-78207
cve.cwes: None
metadata.cwes: None
research.cwe: None
research.vulnerability_type: Prototype Pollution (CWE-1321)
research.title: Prototype Pollution in exceljs via deepMerge / Note Serialization
research.summary: "CONFIRMED: The deepMerge helper in exceljs's lib/utils/under-dash.js does not filter __proto__, constructor, or prototype keys when merging note objects. Per the GHSA-qwr4-7h29-chpf vendor advisory, this is reachable via Note.prototype.get model() when cell.note is set to a non-string value (e.g., parsed user-controlled JSON containing an own __proto__ key). A payload can modify Object.prototype, affecting all plain objects in the process. NOT OBSERVED: No public exploit code or PoC was supplie
============================================================
Case 3: No CWE payload
{'cve_id': 'CVE-0000-0000', 'products': [], 'affected_products': [], 'technologies': [], 'components': [], 'parameters': [], 'versions': [], 'vulnerability_type': 'Unknown', 'cwe': [], 'sources': ['ai_data/research/*.cli.json'], 'rule_version': 'r31-1', 'research_only': True}
cwe == [] ? True
```

Interpretation: for both CVEs the explicit list sources (`cve.cwes`, `metadata.cwes`, `research.cwe`) are `None`, so extraction correctly fell through to the `research.vulnerability_type` text fallback.

## Validation Cases

### Case 1: CVE-2026-1557
- Expected: `CWE-22`
- Actual: `['CWE-22']` (field `cwe` in fingerprint; `vulnerability_type='Path Traversal (CWE-22)'`)
- Source: `research.vulnerability_type` fallback (explicit CWE lists absent)
- Result: PASS

### Case 2: CVE-2026-78207
- Expected: `CWE-1321`
- Actual: `['CWE-1321']` (field `cwe` in fingerprint; `vulnerability_type='Prototype Pollution (CWE-1321)'`)
- Source: `research.vulnerability_type` fallback (explicit CWE lists absent)
- Result: PASS

### Case 3: No CWE payload
- Input: `{"cve": {"id": "CVE-0000-0000"}, "metadata": {}, "research": {"vulnerability_type": "Unknown", "title": "Some bug", "summary": "No CWE here"}}`
- Expected: `[]`
- Actual: `[]` (`cwe == []` → `True`)
- Result: PASS

## Git State
Include `git status --short` and `git diff --stat` (captured 2026-09-12 during verification; pre-existing unrelated changes left untouched per scope protection).

`git status --short`:
```
 M wordlists/dell_params.txt
 M wordlists/indeed_params.txt
?? agent-reports/stage-google-vm-git-sync.md
?? agent-reports/stage-r30-3-vm-diagnostic.md
?? ai/knowledge/inventory_loader.py
?? ai/knowledge/vulnerability_fingerprint.py
?? ai/schemas/vulnerability_fingerprint.py
?? ai_data/knowledge/
?? ai_data/reports/
?? crawl/output/
?? dns-bruteforce/
```

`git diff --stat`:
```
 wordlists/dell_params.txt   | 585 ++++++++++++++++++++++++++++++++++++++++++++
 wordlists/indeed_params.txt | 156 ++++++++++++
 2 files changed, 741 insertions(+)
```

Note: `ai/knowledge/vulnerability_fingerprint.py` is untracked (`??`), so it does not appear in `git diff --stat` (tracked-diff only). No production code was modified during this verification-only task.

## Safety
Confirm:
- no network: CONFIRMED — verification only read local files (`ai/knowledge/vulnerability_fingerprint.py`, `ai_data/research/*.cli.json`) and ran local Python; no network calls issued.
- no LLM: CONFIRMED — no LLM provider invoked; deterministic local extraction only.
- no target interaction: CONFIRMED — no scan, browser, payload execution, or target requests; only local JSON fingerprint building.
- no scheduler changes: CONFIRMED — scheduler/backend/crawler/DNS/wordlists/`ai_data` runtime artifacts untouched; no files modified in this task (report creation only).
