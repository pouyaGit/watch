"""R69 Watch-native security research skill definitions.

Original, bounded, research-only methodology extracted from public
bug-bounty/red-team research methodology references (for example the MIT
licensed Claude-Red skill library) and rewritten for Watch's evidence-grounded
research pipeline. These are methodology notes for authorized security
research and hypothesis generation only:

- no payloads, no exploit instructions, no target interaction;
- skills never grant authorization and never prove a vulnerability;
- every skill carries explicit false-positive and rejection guidance;
- confidence/priority constraints mirror the existing R65 strength caps.

The structured fields exist for future specialist agents; the LLM prompt only
receives the compact rendering produced by ``security_skills.library``.
"""

from __future__ import annotations

SKILLS: tuple[dict, ...] = (
    {
        "skill_id": "idor-bola",
        "category": "IDOR",
        "title": "IDOR / BOLA object-level authorization",
        "applicability": "object references or an IDOR watch signal",
        "trigger_conditions": (
            "IDOR watch signal present",
            "object-reference-shaped route or parameter evidence",
        ),
        "required_evidence": (
            "an observed object-reference route/parameter",
            "authorization behavior or its absence in stored records",
        ),
        "useful_evidence_types": (
            "object-reference parameters",
            "stored cross-object responses",
            "authorization errors",
        ),
        "methodology": (
            "identify the reference and its scope",
            "separate a structural identifier from per-object authorization "
            "evidence",
            "name the missing authorization evidence",
        ),
        "hypothesis_patterns": (
            "references may cross authorization boundaries if per-object "
            "checks are absent",
        ),
        "false_positives": (
            "an {id} placeholder alone is not IDOR",
            "id/user/account names are not object references",
            "REST shape is not an authorization failure",
        ),
        "confidence_constraints": (
            "structural-only caps MEDIUM; name-only caps LOW"
        ),
        "priority_constraints": (
            "HIGH requires observed authorization-relevant behavior"
        ),
        "rejection_cases": (
            "no object-reference observation",
            "no authorization-relevant evidence beyond structure",
            "confirmation wording",
        ),
        "safe_next_actions": (
            "review stored cross-object responses for authorization outcomes",
        ),
        "watch_signals": ("IDOR",),
    },
    {
        "skill_id": "ssrf",
        "category": "SSRF",
        "title": "SSRF server-side request influence",
        "applicability": "URL/host inputs or an SSRF watch signal",
        "trigger_conditions": (
            "SSRF watch signal present",
            "URL/host-shaped parameter evidence",
            "stored fetch/callback/redirect indicators",
        ),
        "required_evidence": (
            "URL/network evidence or a stored fetch-behavior indicator",
            "conditional framing when that evidence is absent",
        ),
        "useful_evidence_types": (
            "URL/host parameters",
            "stored fetch/callback records",
            "redirect/error/timing differences",
        ),
        "methodology": (
            "separate an input name from server-side fetch behavior",
            "look for fetch/callback/internal-network indicators in stored "
            "evidence",
            "state what distinguishes reachability from influence",
        ),
        "hypothesis_patterns": (
            "a URL/host input may influence server-side requests if fetch "
            "behavior is observed",
        ),
        "false_positives": (
            "a URL-like parameter name is not SSRF",
            "client-side redirects are not SSRF",
            "an open redirect alone is not SSRF",
        ),
        "confidence_constraints": "LOW without URL/network or SSRF signal",
        "priority_constraints": "MEDIUM/HIGH require network evidence",
        "rejection_cases": (
            "no URL/network evidence and no conditional framing",
            "unconditional backend-request claims",
        ),
        "safe_next_actions": (
            "review stored responses for fetch behavior and allowlist failures",
        ),
        "watch_signals": ("SSRF",),
    },
    {
        "skill_id": "xss",
        "category": "XSS",
        "title": "XSS reflection and execution context",
        "applicability": "reflection evidence or an XSS watch signal",
        "trigger_conditions": (
            "XSS watch signal present",
            "stored reflection evidence",
        ),
        "required_evidence": (
            "stored evidence of a parameter reaching an executable context, "
            "or an XSS watch signal",
        ),
        "useful_evidence_types": (
            "reflected values in responses",
            "output encoding behavior",
            "CSP/sanitization metadata",
        ),
        "methodology": (
            "locate reflection points in stored responses",
            "separate parameter presence from reflection",
            "separate encoding from an executable context",
            "name the missing context evidence",
        ),
        "hypothesis_patterns": (
            "a reflected parameter may reach an executable context if encoding "
            "is absent",
        ),
        "false_positives": (
            "a parameter name is not XSS",
            "reflected markup without context is not XSS",
        ),
        "confidence_constraints": "LOW without reflection/context evidence",
        "priority_constraints": "HIGH requires response evidence",
        "rejection_cases": ("no reflection/context evidence and no XSS signal",),
        "safe_next_actions": (
            "review stored response bodies for reflection and encoding",
        ),
        "watch_signals": ("XSS",),
    },
    {
        "skill_id": "sqli",
        "category": "SQLI",
        "title": "SQL injection evidence discipline",
        "applicability": "database-behavior indicators or a SQLI signal",
        "trigger_conditions": (
            "SQLI watch signal present",
            "stored database error or timing indicators",
        ),
        "required_evidence": (
            "a SQLI watch signal or stored database error/timing evidence "
            "tied to a parameter",
        ),
        "useful_evidence_types": (
            "database error strings",
            "response timing/size differences",
        ),
        "methodology": (
            "separate parameter presence from injection evidence",
            "examine stored errors and response differences",
            "name the missing behavioral evidence",
        ),
        "hypothesis_patterns": (
            "a parameter may reach a database query if stored errors or "
            "timing indicate it",
        ),
        "false_positives": (
            "id/q/sort names are not injection evidence",
            "generic error pages are not SQL errors",
        ),
        "confidence_constraints": "LOW absent signal evidence",
        "priority_constraints": "HIGH requires database behavior evidence",
        "rejection_cases": ("no SQLI signal and no stored behavior evidence",),
        "safe_next_actions": (
            "review stored response differences and error artifacts",
        ),
        "watch_signals": ("SQLI",),
    },
    {
        "skill_id": "jwt",
        "category": "JWT",
        "title": "JWT artifact and validation evidence",
        "applicability": "token artifacts or a JWT signal; names are leads",
        "trigger_conditions": (
            "JWT watch signal present",
            "observed token structure/claim/algorithm evidence",
        ),
        "required_evidence": (
            "observed token structure, claims or algorithm, or a JWT signal",
        ),
        "useful_evidence_types": (
            "token strings and decoded claims",
            "algorithm/signature metadata",
            "cookie/header records",
        ),
        "methodology": (
            "separate session identifiers from JWTs",
            "require observed token structure before a JWT hypothesis",
            "state the missing validation evidence",
        ),
        "hypothesis_patterns": (
            "a token may carry unverified claims if token artifacts are "
            "observed",
        ),
        "false_positives": (
            "sid/token/session names are not JWTs",
            "generic auth flows are not JWT flows",
        ),
        "confidence_constraints": "name-only caps LOW; token evidence MEDIUM",
        "priority_constraints": "HIGH requires validation behavior evidence",
        "rejection_cases": ("no token/algorithm evidence and no JWT signal",),
        "safe_next_actions": (
            "review stored headers/cookies for token format and algorithm",
        ),
        "watch_signals": ("JWT",),
    },
    {
        "skill_id": "oauth",
        "category": "OAUTH",
        "title": "OAuth/OIDC flow artifact discipline",
        "applicability": "OAuth/OIDC artifacts or an OAUTH signal",
        "trigger_conditions": (
            "OAUTH watch signal present",
            "observed authorize/token/redirect artifacts",
        ),
        "required_evidence": (
            "observed OAuth/OIDC flow artifacts; names alone are weak",
        ),
        "useful_evidence_types": (
            "authorize/token requests",
            "redirect_uri/state/nonce records",
            "assertion/id_token artifacts",
        ),
        "methodology": (
            "separate generic auth from OAuth/OIDC artifacts",
            "identify redirect URI, state/nonce and code/token handling",
            "state the missing flow evidence",
        ),
        "hypothesis_patterns": (
            "a flow may mishandle redirect/state/token semantics if artifacts "
            "are observed",
        ),
        "false_positives": (
            "code/state parameters alone are not OAuth",
            "generic login pages are not OAuth providers",
        ),
        "confidence_constraints": "name-only caps LOW",
        "priority_constraints": "MEDIUM/HIGH require flow artifacts",
        "rejection_cases": ("no OAuth artifacts and no OAUTH signal",),
        "safe_next_actions": (
            "review stored requests for authorize/token/redirect artifacts",
        ),
        "watch_signals": ("OAUTH",),
    },
    {
        "skill_id": "api-security",
        "category": "RECON",
        "title": "API surface structural discipline",
        "applicability": "API-shaped or versioned surfaces or a RECON signal",
        "trigger_conditions": (
            "RECON watch signal present",
            "API-shaped paths/parameters in evidence",
        ),
        "required_evidence": (
            "observed API paths/parameters/versioning in stored evidence",
        ),
        "useful_evidence_types": (
            "path/parameter inventories",
            "versioned routes",
            "record references",
        ),
        "methodology": (
            "describe structural facts only",
            "group endpoints by observed surface",
            "name the missing method/auth/response evidence",
        ),
        "hypothesis_patterns": (
            "an API surface may warrant review where structure indicates "
            "versioned or undocumented routes",
        ),
        "false_positives": (
            "endpoint names do not prove purpose",
            "versioned paths are not vulnerabilities",
            "REST shape is not an authorization failure",
        ),
        "confidence_constraints": "structural-only caps MEDIUM",
        "priority_constraints": "HIGH requires non-structural evidence",
        "rejection_cases": ("purpose claims derived from names alone",),
        "safe_next_actions": (
            "review stored records for method/auth/response structure",
        ),
        "watch_signals": ("RECON",),
    },
    {
        "skill_id": "business-logic",
        "category": "RECON",
        "title": "Business logic and workflow discipline",
        "applicability": "workflow/state/value indicators in evidence",
        "trigger_conditions": (
            "observed multi-step flows",
            "client-controlled business values in records",
        ),
        "required_evidence": (
            "observed flow/state/value evidence in stored records",
        ),
        "useful_evidence_types": (
            "multi-step request sequences",
            "price/quantity/role/plan parameters",
            "state transitions",
        ),
        "methodology": (
            "map observed steps and client-controlled values",
            "identify where server-side enforcement evidence is missing",
            "keep state/sequence hypotheses conditional",
        ),
        "hypothesis_patterns": (
            "a workflow may rely on client-controlled state if stored evidence "
            "shows it unvalidated",
        ),
        "false_positives": (
            "parameter names are not logic flaws",
            "missing evidence is not a flaw",
        ),
        "confidence_constraints": "LOW/MEDIUM per observed flow evidence",
        "priority_constraints": "HIGH requires enforcement behavior evidence",
        "rejection_cases": ("no observed flow/state evidence",),
        "safe_next_actions": (
            "review stored flows for server-side validation evidence",
        ),
        "watch_signals": ("RECON",),
    },
    {
        "skill_id": "open-redirect",
        "category": "RECON",
        "title": "Open redirect behavior evidence",
        "applicability": "stored redirect behavior or redirect-shaped inputs",
        "trigger_conditions": (
            "stored Location/3xx evidence",
            "redirect-shaped parameter evidence",
        ),
        "required_evidence": (
            "observed server-side redirect behavior in stored records",
        ),
        "useful_evidence_types": (
            "Location headers and 3xx records",
            "redirect parameter records",
        ),
        "methodology": (
            "require observed server-side redirect behavior",
            "separate client-side navigation from a 3xx response",
            "check allowlist/relative-target handling in stored evidence",
        ),
        "hypothesis_patterns": (
            "a redirect target may be influenced if stored 3xx behavior shows "
            "it",
        ),
        "false_positives": (
            "continue/next/return/url names are not open redirects",
            "client-side routing is not a server redirect",
        ),
        "confidence_constraints": "name-only caps LOW",
        "priority_constraints": "MEDIUM/HIGH require redirect evidence",
        "rejection_cases": ("no redirect/location evidence",),
        "safe_next_actions": (
            "review stored responses for Location headers and redirects",
        ),
        "watch_signals": ("RECON",),
    },
    {
        "skill_id": "graphql",
        "category": "RECON",
        "title": "GraphQL surface evidence",
        "applicability": "GraphQL paths or query artifacts in evidence",
        "trigger_conditions": (
            "GraphQL path evidence with a RECON signal",
            "observed GraphQL query artifacts",
        ),
        "required_evidence": (
            "observed GraphQL path/query artifacts in stored evidence",
        ),
        "useful_evidence_types": (
            "GraphQL endpoint paths",
            "query documents",
            "schema/introspection responses",
        ),
        "methodology": (
            "confirm the GraphQL surface from stored artifacts",
            "describe the schema/introspection evidence state",
            "treat aliasing/batching as structural possibilities only",
        ),
        "hypothesis_patterns": (
            "a GraphQL surface may warrant per-field authorization review if "
            "query artifacts are observed",
        ),
        "false_positives": (
            "a /graphql name without observed artifacts is not a confirmed "
            "surface",
        ),
        "confidence_constraints": "LOW/MEDIUM per observed artifacts",
        "priority_constraints": "HIGH requires schema/response evidence",
        "rejection_cases": ("no GraphQL artifacts",),
        "safe_next_actions": (
            "review stored records for query documents and schema responses",
        ),
        "watch_signals": ("RECON",),
    },
    {
        "skill_id": "cve-research",
        "category": "CVE_RESEARCH",
        "title": "Technology/version CVE research discipline",
        "applicability": "technology+version evidence or a CVE_RESEARCH signal",
        "trigger_conditions": (
            "CVE_RESEARCH watch signal present",
            "technology and version evidence present",
        ),
        "required_evidence": (
            "both a technology observation and a version observation",
        ),
        "useful_evidence_types": (
            "technology labels",
            "version strings",
            "CVE match records",
        ),
        "methodology": (
            "require technology and version together",
            "do not map versions to technologies unless observed",
            "separate a version observation from exploitability",
            "cite only CVEs present in context",
        ),
        "hypothesis_patterns": (
            "observed technology/version pairs may warrant offline CVE "
            "correlation",
        ),
        "false_positives": (
            "a version string is not an exploitable CVE",
            "unassociated versions are not component versions",
        ),
        "confidence_constraints": "MEDIUM structural; lower without mapping",
        "priority_constraints": "HIGH requires a confirmed association",
        "rejection_cases": (
            "missing technology or version observation",
            "invented CVE ids",
        ),
        "safe_next_actions": (
            "correlate stored version/technology records with offline CVE "
            "references",
        ),
        "watch_signals": ("CVE_RESEARCH",),
    },
)

__all__ = ["SKILLS"]
