"""Deterministic vulnerability-intelligence extraction (Stage R12-R15).

Pure, offline, bounded rule engine. No LLM, no network, no subprocess,
no target execution, no scoring, and no inference beyond explicit
deterministic textual or structured evidence.

Every extracted non-empty field carries bounded provenance:
``source_artifact``, ``source_url`` (when the evidence comes from a
reference; otherwise the research artifact), a bounded verbatim
``evidence`` snippet, and a stable ``rule_id``/``rule_version`` pair.

Stage R15 adds a deterministic **exploitability** projection
(authentication/privilege/user-interaction requirements, exploit/public-PoC
availability, active exploitation, complexity) plus structured CVSS metric
extraction. It remains research-only and never executes or validates
anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field

INTELLIGENCE_RULE_VERSION = "r15-1"

# Stage R15 exploitability is a separate, additive rule family. Its claims
# reuse the same provenance record shape and the same rule-version field.
EXPLOITABILITY_CLAIM_FIELDS: tuple[str, ...] = (
    "authentication_required",
    "privilege_required",
    "user_interaction_required",
    "exploit_available",
    "public_poc",
    "active_exploitation",
    "exploit_complexity",
)
_EXPLOITABILITY_FIELD_PREFIX = "exploitability."
_EXPLOITABILITY_TRUEFALSE_FIELDS = EXPLOITABILITY_CLAIM_FIELDS[:-1]
_EXPLOITABILITY_ALLOWED_VALUES: dict[str, frozenset[str]] = {
    field: frozenset({"true", "false"})
    for field in _EXPLOITABILITY_TRUEFALSE_FIELDS
}
_EXPLOITABILITY_ALLOWED_VALUES["exploit_complexity"] = frozenset({"low", "high"})

_CVSS_STRUCTURAL_FIELDS: tuple[str, ...] = (
    "attack_vector",
    "attack_complexity",
    "attack_requirements",
    "privileges_required",
    "user_interaction",
)
_CVSS_ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attack_vector": frozenset({"N", "A", "L", "P"}),
    "attack_complexity": frozenset({"L", "H"}),
    "attack_requirements": frozenset({"N", "P"}),
    "privileges_required": frozenset({"N", "L", "H"}),
    "user_interaction": frozenset({"N", "R", "P", "A"}),
}
_CVSS_METRIC_TO_FIELD: dict[str, str] = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "AT": "attack_requirements",
    "PR": "privileges_required",
    "UI": "user_interaction",
}

# ---------------------------------------------------------------------------
# Stage R16: deterministic research prioritization (research-only).
#
# A transparent, bounded 0-100 score over the persisted R12-R15 intelligence.
# It never calculates a CVSS score, never executes anything, and never turns a
# missing (unknown) value into a negative signal. Priority classes describe
# research attention only: they are not "exploitable"/"verified"/"confirmed".
# ---------------------------------------------------------------------------
PRIORITY_RULE_VERSION = "r16-1"

PRIORITY_CLASSES: tuple[str, ...] = (
    "CRITICAL_RESEARCH",
    "HIGH_RESEARCH",
    "MEDIUM_RESEARCH",
    "LOW_RESEARCH",
    "INSUFFICIENT_DATA",
)
# (class, minimum score) evaluated highest-first.
PRIORITY_THRESHOLDS: tuple[tuple[str, int], ...] = (
    ("CRITICAL_RESEARCH", 70),
    ("HIGH_RESEARCH", 50),
    ("MEDIUM_RESEARCH", 30),
)
PRIORITY_MIN_SCORE = 0
PRIORITY_MAX_SCORE = 100

# Every point value has exactly one explicit rule.
PRIORITY_WEIGHTS: dict[str, int] = {
    # exploit availability (family cap 40)
    "active_exploitation": 25,
    "public_poc": 12,
    "exploit_available": 8,
    # access (family cap 30)
    "no_authentication": 12,
    "no_privileges": 10,
    "no_user_interaction": 8,
    # complexity (additive, may be negative)
    "low_complexity": 10,
    "high_complexity": -10,
    # attack vector (additive, may be negative)
    "attack_vector_network": 10,
    "attack_vector_adjacent": 5,
    "attack_vector_local": -5,
    "attack_vector_physical": -10,
    # research relevance (family cap 10)
    "vulnerability_type": 3,
    "affected_component": 4,
    "affected_parameter": 3,
    "cwe_mapped": 2,
}
PRIORITY_FAMILY_CAPS: dict[str, int] = {
    "exploit_availability": 40,
    "access": 30,
    "research_relevance": 10,
}

# Keep both input scanning and verbatim snippets bounded. These caps are
# time/space guards, not semantic truncation points in the rules.
MAX_INTELLIGENCE_TEXT_CHARS = 50_000
MAX_EVIDENCE_SNIPPET_CHARS = 240
MAX_EVIDENCE_WINDOW_CHARS = 90

# Small, conservative identifier-shaped vocabulary for extracted names.
_PARAMETER_RE = r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}"
_NON_PARAMETER_NAMES = frozenset(
    {
        "a", "after", "all", "also", "an", "and", "another", "any", "are",
        "as", "at", "be", "been", "before", "being", "both", "but", "by",
        "can", "caused", "causes", "could", "did", "does", "during",
        "each", "exists", "false", "for", "found", "from", "had", "has",
        "have", "here", "how", "if", "in", "into", "is", "it", "its",
        "leads", "less", "many", "may", "might", "more", "most", "must",
        "no", "none", "not", "null", "of", "on", "or", "other", "others",
        "parameter", "parameters", "passed", "plus", "present", "provided",
        "rendered", "reflected", "echoed", "encoded", "decoded", "sanitized",
        "validated", "vulnerable", "exploited", "triggered", "inserted",
        "injected", "escaped", "unescaped", "processed", "displayed",
        "executed", "occurs", "called", "named", "comes",
        "get", "post", "put", "patch", "delete", "url", "uri", "query",
        "should", "since", "some", "such", "supplied", "than", "that",
        "the", "their", "them", "then", "there", "these", "they", "this",
        "those", "to", "true", "underlying", "unknown", "until", "used",
        "using", "via", "was", "we", "were", "when", "where", "whether",
        "which", "while", "who", "will", "with", "without", "would",
        "you",
    }
)

_CWE_PATTERN = re.compile(r"\bCWE-(?P<number>\d{1,4})\b", re.IGNORECASE)

# Every CVE identifier literally present in a document, with positions.
# Used by the attribution engine: on a page that names multiple CVEs,
# only the identifier nearest to a match may attribute the phrase, so
# feed/aggregator lines about a different CVE are never credited here.
_ANY_CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Product/vendor terms must be meaningful before they can structurally
# attribute an otherwise CVE-silent reference document.
_MIN_PRODUCT_TERM_CHARS = 5


@dataclass(frozen=True)
class IntelligenceEvidence:
    """One verbatim provenance record for one extracted value."""

    field: str
    value: str
    source_artifact: str
    source_url: str | None
    source_type: str
    evidence: str
    rule_id: str
    rule_version: str = INTELLIGENCE_RULE_VERSION


@dataclass
class CvssExploitability:
    """Structured CVSS-derived exploitability metrics (never a score)."""

    attack_vector: str = "unknown"
    attack_complexity: str = "unknown"
    attack_requirements: str = "unknown"
    privileges_required: str = "unknown"
    user_interaction: str = "unknown"
    source: str = "unknown"


@dataclass
class Exploitability:
    """Aggregated, conflict-resolved exploitability projection."""

    authentication_required: str = "unknown"
    privilege_required: str = "unknown"
    user_interaction_required: str = "unknown"
    exploit_available: str = "unknown"
    public_poc: str = "unknown"
    active_exploitation: str = "unknown"
    exploit_complexity: str = "unknown"
    cvss: CvssExploitability = dataclass_field(default_factory=CvssExploitability)
    conflicts: list[str] = dataclass_field(default_factory=list)


@dataclass
class ResearchPriority:
    """Deterministic, explainable research-priority projection.

    ``priority`` is a research-attention class (never a verdict); ``score`` is
    a bounded 0-100 sum of explicit rule points; every non-zero score carries
    ``reasons``. ``negative_factors`` and ``unknown_factors`` are preserved so
    unknown is never silently treated as false.
    """

    priority: str = "INSUFFICIENT_DATA"
    score: int = 0
    reasons: list[str] = dataclass_field(default_factory=list)
    negative_factors: list[str] = dataclass_field(default_factory=list)
    unknown_factors: list[str] = dataclass_field(default_factory=list)
    evidence: list[IntelligenceEvidence] = dataclass_field(default_factory=list)
    rule_version: str = PRIORITY_RULE_VERSION


@dataclass
class ExtractedIntelligence:
    """Deterministic extraction result, including bounded provenance."""

    vulnerability_types: list[str] = dataclass_field(default_factory=list)
    cwes: list[str] = dataclass_field(default_factory=list)
    xss_types: list[str] = dataclass_field(default_factory=list)
    contexts: list[str] = dataclass_field(default_factory=list)
    parameters: list[str] = dataclass_field(default_factory=list)
    # Stage R14: vulnerable component / file / endpoint evidence.
    components: list[str] = dataclass_field(default_factory=list)
    # Stage R15: deterministic exploitability projection.
    exploitability: Exploitability = dataclass_field(default_factory=Exploitability)
    evidence: list[IntelligenceEvidence] = dataclass_field(default_factory=list)

# Maps an explicit textual vulnerability phrase to a normalized type.
# Each rule requires the full phrase shown below; a solitary weak token
# (for example, "injection") is intentionally insufficient.
VULNERABILITY_TYPE_TEXT_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "vulnerability-type-sql-injection",
        "sql_injection",
        r"\b(?:sql\s+injection|sqli)\b",
    ),
    (
        "vulnerability-type-cross-site-scripting",
        "xss",
        r"\bcross[-\s]?site\s+script(?:ing)?\b|\bxss\b",
    ),
    (
        "vulnerability-type-path-traversal",
        "path_traversal",
        r"\b(?:path|directory)\s+traversal\b",
    ),
    (
        "vulnerability-type-authentication-bypass",
        "authentication_bypass",
        r"\bauthentication\s+bypass\b",
    ),
    (
        "vulnerability-type-code-injection",
        "code_injection",
        r"\bcode\s+injection\b",
    ),
    (
        "vulnerability-type-command-injection",
        "command_injection",
        r"\b(?:os\s+)?command\s+injection\b",
    ),
    (
        "vulnerability-type-cross-site-request-forgery",
        "csrf",
        r"\bcross[-\s]?site\s+request\s+forgery\b|\bcsrf\b",
    ),
    (
        "vulnerability-type-server-side-request-forgery",
        "ssrf",
        r"\bserver[-\s]?side\s+request\s+forgery\b|\bssrf\b",
    ),
    (
        "vulnerability-type-xml-external-entity",
        "xxe",
        r"\bxml\s+external\s+entit(?:y|ies)\b|\bxxe\b",
    ),
    (
        "vulnerability-type-local-file-inclusion",
        "local_file_inclusion",
        r"\blocal\s+file\s+inclusion\b|\blfi\b",
    ),
    (
        "vulnerability-type-remote-code-execution",
        "remote_code_execution",
        r"\bremote\s+code\s+execution\b|\brce\b",
    ),
)

# Maps unambiguous NVD weakness identifiers to normalized types.
# CWE alone never implies an XSS subtype or an injection context.
VULNERABILITY_TYPE_CWE_RULES: tuple[tuple[str, str, str], ...] = (
    ("vulnerability-type-cwe-79", "xss", "79"),
    ("vulnerability-type-cwe-89", "sql_injection", "89"),
    ("vulnerability-type-cwe-22", "path_traversal", "22"),
    ("vulnerability-type-cwe-352", "csrf", "352"),
    ("vulnerability-type-cwe-611", "xxe", "611"),
    ("vulnerability-type-cwe-78", "command_injection", "78"),
    ("vulnerability-type-cwe-94", "code_injection", "94"),
    ("vulnerability-type-cwe-918", "ssrf", "918"),
)

# XSS subtypes require their explicit identifying phrases. Generic XSS
# wording therefore supports vulnerability_type=xss but never an XSS
# subtype. Case is ignored by the compiled expressions below.
XSS_TYPE_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "xss-type-reflected",
        "reflected",
        r"\breflected\s+(?:cross[-\s]?site\s+)?script(?:ing)?\b|\breflected\s+xss\b",
    ),
    (
        "xss-type-stored",
        "stored",
        r"\b(?:stored|persistent)\s+(?:cross[-\s]?site\s+)?script(?:ing)?\b"
        r"|\b(?:stored|persistent)\s+xss\b",
    ),
    (
        "xss-type-dom",
        "dom",
        r"\bdom(?:[-\s]?based)?\s+(?:cross[-\s]?site\s+)?script(?:ing)?\b"
        r"|\bdom(?:[-\s]?based)?\s+xss\b",
    ),
)

# Injection/sink contexts require explicit context wording. The query
# or artifact being XSS-adjacent is not enough.
CONTEXT_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "injection-context-html-attribute",
        "html_attribute",
        r"\bhtml\s+attributes?\b|\battribute\s+contexts?\b|\bquoted\s+attributes?\b"
        r"|\bevent\s+handlers?\b",
    ),
    (
        "injection-context-script",
        "script",
        r"\bscript\s+contexts?\b|\bwithin\s+a\s+script\b|\binside\s+a\s+script\b"
        r"|\bscript\s+blocks?\b",
    ),
    (
        "injection-context-javascript",
        "javascript",
        r"\bjavascript\s+(?:contexts?|code)\b|\bjs\s+contexts?\b",
    ),
    (
        "injection-context-url",
        "url",
        r"\burl\s+contexts?\b|\burl[-\s]?based\s+contexts?\b|\bin\s+the\s+url\b",
    ),
)

# Named injection parameters require either the conventional quoted
# "the <name> parameter" construction or an explicit request-source
# qualifier ("GET/POST/URL parameter <name>"). Generic reports that a
# vulnerability merely has parameters cannot identify a name.
PARAMETER_RULES: tuple[tuple[str, str], ...] = (
    (
        "parameter-named-explicit",
        rf"\bthe\s+[`'\"‘’“”]?({_PARAMETER_RE})[`'\"‘’“”]?\s+"
        r"(?:get|post|http|url|query|request|form|cookie)?\s*"
        r"(?:parameter|argument|field)\b",
    ),
    (
        "parameter-request-qualified",
        rf"\b(?:get|post|http|url|query|request|form|cookie)\s+"
        rf"(?:parameter|argument|field|variable)\s+[`'\"‘’“”]?({_PARAMETER_RE})",
    ),
    (
        "parameter-name-first",
        rf"\bparameter\s+[`'\"‘’“”]?({_PARAMETER_RE})",
    ),
)

_VULNERABILITY_TEXT_PATTERNS = tuple(
    (rule_id, value, re.compile(pattern, re.IGNORECASE))
    for rule_id, value, pattern in VULNERABILITY_TYPE_TEXT_RULES
)
_XSS_PATTERNS = tuple(
    (rule_id, value, re.compile(pattern, re.IGNORECASE))
    for rule_id, value, pattern in XSS_TYPE_RULES
)
_CONTEXT_PATTERNS = tuple(
    (rule_id, value, re.compile(pattern, re.IGNORECASE))
    for rule_id, value, pattern in CONTEXT_RULES
)
_PARAMETER_PATTERNS = tuple(
    (rule_id, re.compile(pattern, re.IGNORECASE))
    for rule_id, pattern in PARAMETER_RULES
)

# ---------------------------------------------------------------------------
# Stage R14: parameter + component/file/endpoint evidence rules.
# Still deterministic, bounded, and conservative: every rule requires
# explicit parameter/component wording, generic nouns are rejected by
# the blocklist/validator, and file/endpoint candidates must carry
# vulnerability-oriented context in their bounded window.
# ---------------------------------------------------------------------------

# Explicit "the value is the parameter" label forms:
#   vulnerable parameter: id        vulnerable parameter is "id"
#   parameter name = user_id        parameter name: search
PARAMETER_LABEL_RULES: tuple[tuple[str, str], ...] = (
    (
        "parameter-vulnerable-labeled",
        rf"\bvulnerable\s+(?:parameter|argument|field)s?\s*"
        rf"(?:is\s*[:=]?|name\s*[:=]?|[:=])\s*[`'\x22\u2018\u2019\u201c\u201d]?"
        rf"({_PARAMETER_RE})",
    ),
    (
        "parameter-name-labeled",
        rf"\b(?:parameter|argument|field)\s+name\s*"
        rf"(?:is\s*[:=]?|[:=])\s*[`'\x22\u2018\u2019\u201c\u201d]?"
        rf"({_PARAMETER_RE})",
    ),
)

# Bare "<name> parameter" form ("id parameter of view_each_faculty.php").
# The blocklist + validator reject sentence words ("of the parameter",
# "a parameter", "this parameter"), so this stays conservative.
PARAMETER_BARE_RULE: tuple[str, str] = (
    "parameter-name-bare",
    rf"\b[`'\x22\u2018\u2019\u201c\u201d]?({_PARAMETER_RE})"
    rf"[`'\x22\u2018\u2019\u201c\u201d]?\s+"
    rf"(?:parameters?|arguments?|fields?)\b",
)

_PARAMETER_LABEL_PATTERNS = tuple(
    (rule_id, re.compile(pattern, re.IGNORECASE))
    for rule_id, pattern in PARAMETER_LABEL_RULES
)

# Forward "parameter <name>" form ("parameter id", "GET parameter id",
# 'parameter "id"'). Singular keyword only: plural discussion ("has
# parameters and arguments everywhere") is generic prose, not a claim.
# "parameter name ..." is excluded by lookahead so the label rule owns it.
PARAMETER_FORWARD_RULE: tuple[str, str] = (
    "parameter-name-forward",
    rf"\b(?:parameter|argument|field)\s+"
    rf"(?!name\b)[`'\x22\u2018\u2019\u201c\u201d]?({_PARAMETER_RE})",
)

_PARAMETER_FORWARD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (PARAMETER_FORWARD_RULE[0],
     re.compile(PARAMETER_FORWARD_RULE[1], re.IGNORECASE)),
)

# Vulnerability-oriented context required before ANY component/file/
# endpoint candidate may be extracted. A filename in a plain project
# listing or a code block with no vulnerability wording yields nothing.
VULN_CONTEXT_PATTERN = re.compile(
    r"\b(?:vulnerab\w*|affected|injection|xss|sql\s+injection|sqli|"
    r"arbitrary\s+file|traversal|endpoint|parameter|exploit\w*|"
    r"security\s+issue|insecure|unauthorized|disclosure)\b",
    re.IGNORECASE,
)

# Source-file candidates: relative paths or bare files with a known
# source extension. Bounded character classes, no nested quantifiers.
_COMPONENT_FILE_PATTERN = re.compile(
    r"\b[A-Za-z0-9_\-./]{1,150}\."
    r"(?:php\d?|jsp|jspx|asp|aspx|ascx|cgi|pl|pm|py|rb|erb|html?|htm|"
    r"js|ts|jsx|tsx|java|cs|go|sh|bat|sql|conf|ini|xml|json)\b",
    re.IGNORECASE,
)

# Explicitly labeled URL paths / API endpoints:
#   endpoint /api/users      the affected endpoint is /api/foo
#   url: /admin/login.php    path /admin/export.php
_COMPONENT_ENDPOINT_RULES: tuple[tuple[str, str], ...] = (
    (
        "component-endpoint-named",
        r"\b(?:endpoint|url|uri|route|path|script|page|file|component)s?\s+"
        r"(?:is\s+|are\s+|of\s+|:|=)?\s*[`'\x22\u2018\u2019\u201c\u201d]?"
        r"(/[A-Za-z0-9_\-./]{1,150})",
    ),
)

_COMPONENT_LABEL_RULES: tuple[tuple[str, str], ...] = (
    (
        "component-vulnerable-labeled",
        r"\b(?:vulnerable|affected|insecure)\s+"
        r"(?:file|component|endpoint|script|page|url|path|plugin)s?\s*"
        r"(?:is\s*[:=]?|name\s*[:=]?|[:=])\s*[`'\x22\u2018\u2019\u201c\u201d]?"
        r"([A-Za-z0-9_\-./]{1,150})",
    ),
)

_MAX_COMPONENT_CHARS = 150

# File extensions that mark a candidate as a component/file rather than
# a parameter-like token.
_SOURCE_FILE_EXTENSION_RE = re.compile(
    r"\.(?:php\d?|jsp|jspx|asp|aspx|ascx|cgi|pl|pm|py|rb|erb|html?|htm|"
    r"js|ts|jsx|tsx|java|cs|go|sh|bat|sql|conf|ini|xml|json)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Stage R15: deterministic exploitability rules (research-only).
#
# Each rule maps an explicit phrase to one or more claims. ``negation_scope``
# is ``None`` for wording that is already negative, ``"immediate"`` for
# positive wording that must not fire directly after a negation in the same
# clause, and ``"sentence"`` for positive wording that may be negated by a
# phrase such as "no evidence ... active exploitation" earlier in the
# sentence. Generic words ("exploit", "attack", "vulnerable") are never
# sufficient on their own.
# ---------------------------------------------------------------------------

# (rule_id, ((claim_field, claim_value), ...), pattern, negation_scope)
EXPLOITABILITY_TEXT_RULES: tuple[
    tuple[str, tuple[tuple[str, str], ...], str, str | None], ...
] = (
    # --- authentication ---
    (
        "exploitability-auth-unauthenticated",
        (("authentication_required", "false"),),
        r"\bunauthenticated\b",
        None,
    ),
    (
        "exploitability-auth-not-required",
        (("authentication_required", "false"),),
        r"\bno authentication (?:is )?required\b"
        r"|\bwithout (?:any )?authentication\b"
        r"|\bauthentication (?:is )?not required\b"
        r"|\bdoes not require authentication\b"
        r"|\brequires no authentication\b"
        r"|\bno credentials (?:are )?required\b"
        r"|\bpre[-\s]?auth(?:entication)?\b",
        None,
    ),
    (
        "exploitability-auth-required",
        (("authentication_required", "true"),),
        r"\bauthentication (?:is )?required\b"
        r"|\brequires authentication\b"
        r"|\bauthenticated (?:user|attacker|administrator|account)\b"
        r"|\brequires (?:valid )?credentials\b"
        r"|\blogin (?:is )?required\b",
        "immediate",
    ),
    # --- privileges ---
    (
        "exploitability-privileges-low",
        (("privilege_required", "false"),),
        r"\blow[-\s]privileg(?:e|ed|es)\b"
        r"|\blow[-\s]privileged (?:user|attacker|account)\b"
        r"|\bunprivileged\b"
        r"|\bnon[-\s]?privileged\b"
        r"|\bnon[-\s]?admin(?:istrator)?\b"
        r"|\bwithout (?:any )?privileges\b"
        r"|\bno privileges (?:are )?required\b"
        r"|\brequires only low privileges\b",
        None,
    ),
    (
        "exploitability-privileges-admin",
        (("privilege_required", "true"),),
        r"\b(?:requires?|with)\s+(?:administrator|admin|root|elevated|high)\s+"
        r"(?:privileges?|access|rights|permissions?)\b"
        r"|\b(?:administrator|admin|root)\s+"
        r"(?:privileges?|access|rights|account|user)\b"
        r"|\b(?<!low-)(?<!non-)(?<!un)privileged\s+(?:account|user)\b"
        r"|\brequires? (?:an )?administrator\b"
        r"|\bhighly privileged\b",
        "immediate",
    ),
    # --- user interaction ---
    (
        "exploitability-interaction-required",
        (("user_interaction_required", "true"),),
        r"\buser interaction (?:is )?required\b"
        r"|\brequires user interaction\b"
        r"|\bvictim interaction\b"
        r"|\brequires (?:the )?(?:victim|user) to "
        r"(?:click|visit|open|interact|browse)\b",
        "immediate",
    ),
    (
        "exploitability-interaction-none",
        (("user_interaction_required", "false"),),
        r"\bno user interaction\b"
        r"|\bwithout user interaction\b"
        r"|\buser interaction (?:is )?not required\b",
        None,
    ),
    # --- exploit availability / public PoC ---
    (
        "exploitability-poc-public",
        (("public_poc", "true"), ("exploit_available", "true")),
        r"\bpublic(?:ly)? (?:poc|proof[-\s]?of[-\s]?concept)\b"
        r"|\bproof[-\s]?of[-\s]?concept\b"
        r"|\b(?:poc|proof[-\s]?of[-\s]?concept) (?:code )?(?:is )?"
        r"(?:publicly )?(?:available|released|published|merged)\b",
        "immediate",
    ),
    (
        "exploitability-exploit-available",
        (("exploit_available", "true"),),
        r"\bexploit(?: code| script)? (?:is )?(?:publicly )?"
        r"(?:available|released|published)\b"
        r"|\bpublic exploit\b"
        r"|\bweaponized exploit\b"
        r"|\bexploit code available\b"
        r"|\bexploit (?:has been )?(?:released|published)\b",
        "immediate",
    ),
    (
        "exploitability-exploit-none",
        (("exploit_available", "false"), ("public_poc", "false")),
        r"\bno (?:public |known |available )?(?:poc|proof[-\s]?of[-\s]?concept|exploit)\b"
        r"|\bno exploit (?:code )?(?:is )?available\b"
        r"|\bwithout a (?:public |known )?exploit\b"
        r"|\bno known exploit code\b"
        r"|\bno weaponized exploit\b",
        None,
    ),
    # --- active exploitation ---
    (
        "exploitability-active-exploitation",
        (("active_exploitation", "true"),),
        r"\bexploited in the wild\b"
        r"|\bactive(?:ly)? exploit(?:ed|ation)\b"
        r"|\bexploitation (?:has been |was |is )?observed\b"
        r"|\bknown exploited vulnerabilit(?:y|ies)\b"
        r"|\bCISA KEV\b"
        r"|\bKEV catalog(?:ue)?\b",
        "sentence",
    ),
    (
        "exploitability-no-active-exploitation",
        (("active_exploitation", "false"),),
        r"\bno (?:evidence|reports?|indications?|signs?)\b[^.\n]{0,120}?"
        r"\b(?:active exploitation|exploited in the wild|exploitation in the wild)\b"
        r"|\bnot (?:been )?exploited in the wild\b"
        r"|\bno (?:known |observed |confirmed )?(?:active )?exploitation\b"
        r"|\bexploitation (?:has not|hasn't) been observed\b"
        r"|\bno exploitation (?:has been |was |is )?observed\b",
        None,
    ),
    # --- complexity ---
    (
        "exploitability-complexity-low",
        (("exploit_complexity", "low"),),
        r"\blow (?:exploit |attack )?complexity\b"
        r"|\bexploit(?:ation)? (?:is )?(?:trivial|simple|easy)\b",
        "immediate",
    ),
    (
        "exploitability-complexity-high",
        (("exploit_complexity", "high"),),
        r"\bhigh (?:exploit |attack )?complexity\b|\bcomplex to exploit\b",
        "immediate",
    ),
)

_EXPLOITABILITY_TEXT_PATTERNS = tuple(
    (rule_id, claims, re.compile(pattern, re.IGNORECASE), scope)
    for rule_id, claims, pattern, scope in EXPLOITABILITY_TEXT_RULES
)

# CVSS vectors: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/..." (3.x) and the CVSS 4.0
# form with AT:. Only the listed structural metrics are parsed; no score is
# ever calculated.
_CVSS_VECTOR_RE = re.compile(
    r"CVSS:[0-9](?:\.[0-9])?(?:\s*/\s*[A-Za-z]{1,4}\s*:\s*[A-Za-z0-9.]+)+",
    re.IGNORECASE,
)
_CVSS_METRIC_RE = re.compile(r"([A-Za-z]{1,4})\s*:\s*([A-Za-z0-9.]+)")

_NEGATION_TOKEN_RE = re.compile(
    r"\b(?:no|non|not|never|without|none|cannot|isn't|aren't|doesn't|don't|"
    r"won't|neither|nor)\b",
    re.IGNORECASE,
)
_PHRASE_NEGATION_RE = re.compile(
    r"\bno\s+(?:evidence|reports?|indications?|signs?|proof)\b",
    re.IGNORECASE,
)
_CLAUSE_BREAK_RE = re.compile(r"[.!?;:\n]")

# Structured research flags (explicit booleans) mapped onto claims.
_STRUCTURED_RESEARCH_FLAGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("public_exploit", ("public_poc", "exploit_available")),
    ("actively_exploited", ("active_exploitation",)),
)


def _is_negated(text: str, start: int, scope: str | None) -> bool:
    """Return True when positive wording at ``start`` sits in a negation.

    ``immediate`` looks only at the short clause right before the match
    ("no user interaction required"); ``sentence`` also honours phrase
    negation anywhere in the sentence ("no evidence ... active exploitation").
    """

    if scope is None:
        return False
    immediate_prefix = text[max(0, start - 20):start]
    immediate_clause = _CLAUSE_BREAK_RE.split(immediate_prefix)[-1]
    if _NEGATION_TOKEN_RE.search(immediate_clause):
        return True
    if scope == "sentence":
        sentence = _CLAUSE_BREAK_RE.split(text[:start])[-1]
        return bool(
            _NEGATION_TOKEN_RE.search(sentence)
            or _PHRASE_NEGATION_RE.search(sentence)
        )
    return False


def _tristate_bool(value: object) -> str | None:
    """Deterministically map an explicit structured boolean to a tri-state."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "yes"):
            return "true"
        if normalized in ("false", "no"):
            return "false"
    return None


def _parse_cvss_metrics(vector: str) -> dict[str, str]:
    """Parse the supported structural metrics out of a CVSS vector string."""

    metrics: dict[str, str] = {}
    for match in _CVSS_METRIC_RE.finditer(vector):
        key = match.group(1).upper()
        value = match.group(2).upper()
        field = _CVSS_METRIC_TO_FIELD.get(key)
        if field and value in _CVSS_ALLOWED_VALUES[field]:
            metrics[key] = value
    return metrics



def _ordered_unique(values: list[str]) -> list[str]:
    """Return values once each, preserving deterministic first-seen order."""

    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _normalize_parameter_name(name: str | None) -> str | None:
    """Normalize a candidate parameter and reject generic wording."""

    if not name:
        return None
    normalized = name.strip().strip("`'\"‘’“”").strip().lower()
    normalized = normalized.rstrip("=:,;.")
    if not re.fullmatch(_PARAMETER_RE, normalized, re.IGNORECASE):
        return None
    if normalized in _NON_PARAMETER_NAMES:
        return None
    if normalized.startswith(("http", "www", "cve-", "file-")):
        return None
    return normalized


# Generic words that are only acceptable as parameters when an explicit
# label names them ("vulnerable parameter: input"); bare "<word> is a
# parameter"-style adjacency must not promote them on its own. (The R12
# _NON_PARAMETER_NAMES blocklist still applies to every candidate.)
_BARE_ADJACENCY_GENERIC_NAMES = frozenset(
    {"input", "request", "response", "value", "data", "content",
     "text", "string", "code"}
)


def _validate_component_value(value: str | None) -> str | None:
    """Validate/normalize a candidate component, file, or endpoint.

    Deterministic normalization keeps meaningful path distinctions:
    a leading slash is stripped only when it is not the sole marker of
    a labeled endpoint (bare files keep no slash), and case is folded
    for source files. Rejected: URLs, query strings, HTML fragments,
    whitespace/punctuation-heavy strings, and oversized captures.
    """

    if not value:
        return None
    candidate = value.strip().strip("`'\"‘’“”").strip()
    if not candidate or len(candidate) > _MAX_COMPONENT_CHARS:
        return None
    # URLs are components never; keep only the path of an absolute URL.
    scheme_match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate)
    if scheme_match:
        rest = candidate[scheme_match.end():]
        path_start = rest.find("/")
        if path_start < 0:
            return None
        candidate = rest[path_start:]
        candidate = candidate.split("?", 1)[0].split("#", 1)[0]
    elif candidate.startswith(("http://", "https://")):
        return None
    if candidate.startswith("//"):
        return None
    had_leading_slash = candidate.startswith("/")
    candidate = candidate.split("?", 1)[0].split("#", 1)[0]
    if " " in candidate or "\t" in candidate or "\n" in candidate:
        return None
    if "<" in candidate or ">" in candidate or '"' in candidate:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_\-./]{1,150}", candidate):
        return None
    if not _SOURCE_FILE_EXTENSION_RE.search(candidate) and not had_leading_slash:
        # Bare token without a source extension and without a leading
        # slash: not recognizable as a file or endpoint — reject.
        return None
    # Strip leading slashes for dedup ("/api/users" == "api/users");
    # deeper path structure is preserved.
    candidate = candidate.lstrip("/")
    if not candidate:
        return None
    lowered = candidate.lower()
    if lowered in _NON_PARAMETER_NAMES:
        return None
    if lowered.startswith(("http", "www.", "cve-", "mailto")):
        return None
    return lowered


def _normalize_component_key(value: str) -> str:
    """Deterministic dedup key: leading-slash and case-insensitive."""

    return value.strip().strip("/").lower()


def _normalize_parameter_key(value: str) -> str:
    return value.strip().lower()


def _mentions_cve_id(text: str, cve_id: str) -> bool:
    """Check whether text names this CVE (case-insensitive)."""

    normalized_cve = (cve_id or "").strip().lower()
    return bool(normalized_cve) and normalized_cve in text.lower()


def _window_mentions_cve_id(
    text: str, match: re.Match[str], cve_id: str
) -> bool:
    """Require the same CVE near the extraction match (bounded)."""

    window = text[
        max(0, match.start() - MAX_EVIDENCE_WINDOW_CHARS) : min(
            len(text), match.end() + MAX_EVIDENCE_WINDOW_CHARS
        )
    ].lower()
    return _mentions_cve_id(window, cve_id)


class _Attributor:
    """Decide which CVE a matched phrase belongs to (deterministic).

    Attribution modes, in strictness order, evaluated per document text:

    - ``structural``: the text comes from this CVE's own research
      artifact whose ``cve.id`` equals this CVE; every match in it is
      about this CVE by construction.
    - Multi-CVE document (names a CVE other than ours): a match is
      attributable only when our CVE is the unique nearest CVE
      identifier and lies within the bounded evidence window. A tie in
      distance rejects (ambiguous).
    - Single-CVE document (names only ours): bounded-window adjacency
      to one of our CVE mentions (as before).
    - CVE-silent document (names no CVE id): attributable only when a
      normalized product/vendor term of this CVE literally occurs in
      the document, linking the page to this CVE's NVD identity.
      Conservative: the same explicit-phrase rules still gate every
      extracted value; no CVE id anywhere means no subtype can be
      invented unless the subtype phrase itself is literally present.
    """

    __slots__ = ("cve_id", "ours", "others", "product_terms", "structural")

    def __init__(
        self,
        cve_id: str,
        text: str,
        *,
        product_terms: tuple[str, ...] = (),
        structural: bool = False,
    ) -> None:
        self.cve_id = (cve_id or "").strip().lower()
        self.structural = structural
        self.ours: list[tuple[int, int]] = []
        self.others: list[tuple[int, int]] = []
        for match in _ANY_CVE_ID_PATTERN.finditer(text):
            if match.group(0).lower() == self.cve_id and self.cve_id:
                self.ours.append((match.start(), match.end()))
            else:
                self.others.append((match.start(), match.end()))
        lowered = text.lower()
        self.product_terms = tuple(
            term
            for term in (t.lower() for t in product_terms)
            if len(term) >= _MIN_PRODUCT_TERM_CHARS and term in lowered
        )

    @staticmethod
    def _distance(match: re.Match[str], spans: list[tuple[int, int]]) -> int:
        best = None
        for start, end in spans:
            if end <= match.start():
                delta = match.start() - end
            elif start >= match.end():
                delta = start - match.end()
            else:
                delta = 0
            if best is None or delta < best:
                best = delta
        return -1 if best is None else best

    def accepts(self, text: str, match: re.Match[str]) -> bool:
        if self.structural:
            return True
        ours_distance = self._distance(match, self.ours)
        others_distance = self._distance(match, self.others)
        if self.ours and self.others:
            if ours_distance < 0 or ours_distance > MAX_EVIDENCE_WINDOW_CHARS:
                return False
            if others_distance >= 0 and others_distance <= ours_distance:
                return False
            return True
        if self.ours:
            return _window_mentions_cve_id(text, match, self.cve_id)
        return bool(self.product_terms)


def _evidence_window(text: str, start: int, end: int) -> str:
    """Return one bounded verbatim window around a regex match."""

    window_start = max(0, start - MAX_EVIDENCE_WINDOW_CHARS)
    window_end = min(len(text), end + MAX_EVIDENCE_WINDOW_CHARS)
    snippet = " ".join(text[window_start:window_end].split())
    if len(snippet) > MAX_EVIDENCE_SNIPPET_CHARS:
        snippet = snippet[:MAX_EVIDENCE_SNIPPET_CHARS].rstrip()
    return snippet


def _record(
    result: ExtractedIntelligence,
    *,
    field: str,
    value: str,
    text: str,
    start: int,
    end: int,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
    rule_id: str,
    rule_version: str = INTELLIGENCE_RULE_VERSION,
) -> None:
    result.evidence.append(
        IntelligenceEvidence(
            field=field,
            value=value,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=source_type,
            evidence=_evidence_window(text, start, end),
            rule_id=rule_id,
            rule_version=rule_version,
        )
    )


def _record_exploitability_claim(
    result: ExtractedIntelligence,
    *,
    claim_field: str,
    claim_value: str,
    text: str,
    start: int,
    end: int,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
    rule_id: str,
) -> None:
    """Record one exploitability claim into the shared evidence stream."""

    _record(
        result,
        field=_EXPLOITABILITY_FIELD_PREFIX + claim_field,
        value=claim_value,
        text=text,
        start=start,
        end=end,
        source_artifact=source_artifact,
        source_url=source_url,
        source_type=source_type,
        rule_id=rule_id,
        rule_version=INTELLIGENCE_RULE_VERSION,
    )


def _extract_cvss_claims(
    result: ExtractedIntelligence,
    vector: str,
    *,
    kind: str,
    source_artifact: str,
    source_url: str | None,
    text: str,
    start: int,
    end: int,
) -> None:
    """Record structured/prose CVSS metrics and their mapped claims.

    ``kind`` is ``"structured"`` (an explicit machine-readable field) or
    ``"prose"`` (a vector embedded in reference text); the merge step prefers
    structured provenance for the corresponding field.
    """

    metrics = _parse_cvss_metrics(vector)
    if not metrics:
        return
    for key, value in metrics.items():
        structural = _CVSS_METRIC_TO_FIELD[key]
        _record_exploitability_claim(
            result,
            claim_field=f"cvss.{structural}",
            claim_value=value,
            text=text,
            start=start,
            end=end,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=kind,
            rule_id=f"exploitability-cvss-{kind}-{structural}",
        )
    if "PR" in metrics:
        _record_exploitability_claim(
            result,
            claim_field="privilege_required",
            claim_value="false" if metrics["PR"] == "N" else "true",
            text=text,
            start=start,
            end=end,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=kind,
            rule_id=f"exploitability-cvss-{kind}-privilege-required",
        )
    if "UI" in metrics:
        _record_exploitability_claim(
            result,
            claim_field="user_interaction_required",
            claim_value="false" if metrics["UI"] == "N" else "true",
            text=text,
            start=start,
            end=end,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=kind,
            rule_id=f"exploitability-cvss-{kind}-user-interaction",
        )
    if "AC" in metrics:
        _record_exploitability_claim(
            result,
            claim_field="exploit_complexity",
            claim_value="low" if metrics["AC"] == "L" else "high",
            text=text,
            start=start,
            end=end,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=kind,
            rule_id=f"exploitability-cvss-{kind}-exploit-complexity",
        )


def _structured_cvss_vector(payload: dict[str, object]) -> str | None:
    """Return the first explicit CVSS vector present in the payload."""

    for container_key in ("cve", "metadata"):
        container = payload.get(container_key)
        if not isinstance(container, dict):
            continue
        for key in (
            "cvss_vector",
            "cvss_v3_vector",
            "cvss_v31_vector",
            "cvss_v4_vector",
            "cvss40_vector",
        ):
            value = container.get(key)
            if not isinstance(value, str):
                continue
            match = _CVSS_VECTOR_RE.search(value)
            if match:
                return match.group(0)
    return None


def _extract_structured_cvss(
    result: ExtractedIntelligence, payload: dict[str, object], source_artifact: str
) -> None:
    vector = _structured_cvss_vector(payload)
    if not vector:
        return
    _extract_cvss_claims(
        result,
        vector,
        kind="structured",
        source_artifact=source_artifact,
        source_url=None,
        text=vector,
        start=0,
        end=len(vector),
    )


def _extract_structured_research_flags(
    result: ExtractedIntelligence, payload: dict[str, object], source_artifact: str
) -> None:
    """Map explicit research booleans (public_exploit/actively_exploited)."""

    research = payload.get("research")
    if not isinstance(research, dict):
        return
    for flag, claim_fields in _STRUCTURED_RESEARCH_FLAGS:
        state = _tristate_bool(research.get(flag))
        if state is None:
            continue
        text = f"research.{flag}={state}"
        for claim_field in claim_fields:
            _record_exploitability_claim(
                result,
                claim_field=claim_field,
                claim_value=state,
                text=text,
                start=0,
                end=len(text),
                source_artifact=source_artifact,
                source_url=None,
                source_type="structured",
                rule_id=f"exploitability-structured-{flag.replace('_', '-')}",
            )


def _extract_exploitability_from_text(
    result: ExtractedIntelligence,
    bounded: str,
    attributor: "_Attributor",
    *,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
) -> None:
    """Deterministic prose exploitability rules for one bounded text."""

    for rule_id, claims, pattern, scope in _EXPLOITABILITY_TEXT_PATTERNS:
        for match in pattern.finditer(bounded):
            if _is_negated(bounded, match.start(), scope):
                continue
            if not attributor.accepts(bounded, match):
                continue
            for claim_field, claim_value in claims:
                _record_exploitability_claim(
                    result,
                    claim_field=claim_field,
                    claim_value=claim_value,
                    text=bounded,
                    start=match.start(),
                    end=match.end(),
                    source_artifact=source_artifact,
                    source_url=source_url,
                    source_type=source_type,
                    rule_id=rule_id,
                )
    # Prose CVSS vectors found inside reference/research text.
    for match in _CVSS_VECTOR_RE.finditer(bounded):
        if not attributor.accepts(bounded, match):
            continue
        _extract_cvss_claims(
            result,
            match.group(0),
            kind="prose",
            source_artifact=source_artifact,
            source_url=source_url,
            text=bounded,
            start=match.start(),
            end=match.end(),
        )


def _dedupe_exploitability_evidence(result: ExtractedIntelligence) -> None:
    """Keep the first deterministic evidence record per exploitability claim."""

    seen: set[tuple] = set()
    kept: list[IntelligenceEvidence] = []
    for item in result.evidence:
        if item.field.startswith(_EXPLOITABILITY_FIELD_PREFIX):
            key = (
                item.field,
                item.value,
                item.source_artifact,
                item.source_url or "",
                item.source_type,
                item.evidence,
                item.rule_id,
                item.rule_version,
            )
            if key in seen:
                continue
            seen.add(key)
        kept.append(item)
    result.evidence[:] = kept


def _distinct_allowed(items: list, allowed: frozenset[str]) -> list[str]:
    values: list[str] = []
    for item in items:
        value = getattr(item, "value", "")
        if value in allowed and value not in values:
            values.append(value)
    return values


def _resolve_claim(items: list, allowed: frozenset[str]) -> tuple[str, bool]:
    """Resolve one claim: structured provenance wins, then prose.

    Returns ``(value, conflicted)``. Prose true/false disagreement (with no
    structured source) resolves to ``"unknown"`` while the conflict is kept.
    """

    structured = [
        item for item in items
        if (getattr(item, "source_type", "") or "") == "structured"
    ]
    structured_ids = {id(item) for item in structured}
    prose = [item for item in items if id(item) not in structured_ids]

    structured_values = _distinct_allowed(structured, allowed)
    if len(structured_values) == 1:
        return structured_values[0], False
    if len(structured_values) > 1:
        return "unknown", True

    prose_values = _distinct_allowed(prose, allowed)
    if len(prose_values) == 1:
        return prose_values[0], False
    if len(prose_values) > 1:
        return "unknown", True
    return "unknown", False


def summarize_exploitability(evidence: object) -> Exploitability:
    """Deterministically aggregate exploitability claims from evidence.

    The evidence records are the single source of truth; this projection is
    recomputable and order-independent. Structured (CVSS/explicit boolean)
    provenance is preferred for the field it describes; conflicting prose
    evidence is preserved in ``conflicts`` and resolves to ``"unknown"``.
    """

    groups: dict[str, list] = {}
    for item in evidence or []:
        field = getattr(item, "field", "") or ""
        if field.startswith(_EXPLOITABILITY_FIELD_PREFIX):
            groups.setdefault(field, []).append(item)

    kwargs: dict[str, str] = {}
    conflicts: list[str] = []
    for field in EXPLOITABILITY_CLAIM_FIELDS:
        allowed = _EXPLOITABILITY_ALLOWED_VALUES[field]
        items = groups.get(_EXPLOITABILITY_FIELD_PREFIX + field, [])
        value, _ = _resolve_claim(items, allowed)
        kwargs[field] = value
        if len(_distinct_allowed(items, allowed)) > 1:
            conflicts.append(field)

    cvss_kwargs: dict[str, str] = {}
    cvss_kinds: set[str] = set()
    for field in _CVSS_STRUCTURAL_FIELDS:
        allowed = _CVSS_ALLOWED_VALUES[field]
        items = groups.get(
            f"{_EXPLOITABILITY_FIELD_PREFIX}cvss.{field}", []
        )
        value, _ = _resolve_claim(items, allowed)
        cvss_kwargs[field] = value
        if len(_distinct_allowed(items, allowed)) > 1:
            conflicts.append(f"cvss.{field}")
        cvss_kinds.update(
            getattr(item, "source_type", "") or "" for item in items
        )
    if "structured" in cvss_kinds:
        cvss_source = "structured"
    elif "prose" in cvss_kinds:
        cvss_source = "prose"
    else:
        cvss_source = "unknown"

    return Exploitability(
        cvss=CvssExploitability(source=cvss_source, **cvss_kwargs),
        conflicts=sorted(set(conflicts)),
        **kwargs,
    )


def _evidence_record_dict(item: object) -> dict[str, object]:
    return {
        "field": getattr(item, "field", ""),
        "value": getattr(item, "value", ""),
        "source_artifact": getattr(item, "source_artifact", ""),
        "source_url": getattr(item, "source_url", None),
        "source_type": getattr(item, "source_type", ""),
        "evidence": getattr(item, "evidence", ""),
        "rule_id": getattr(item, "rule_id", ""),
        "rule_version": getattr(item, "rule_version", ""),
    }


def exploitability_projection(evidence: object) -> dict[str, object]:
    """Build the serialized exploitability dict for the knowledge schema.

    Used by ingestion (and available to the store) so the tri-state fields,
    CVSS metrics, conflicts and evidence all derive from one deterministic
    aggregation over the shared evidence stream.
    """

    summary = summarize_exploitability(evidence)
    records = sorted(
        (
            item
            for item in (evidence or [])
            if (getattr(item, "field", "") or "").startswith(
                _EXPLOITABILITY_FIELD_PREFIX
            )
        ),
        key=lambda item: (
            getattr(item, "field", ""),
            getattr(item, "value", ""),
            getattr(item, "rule_id", ""),
            getattr(item, "source_url", "") or "",
            getattr(item, "evidence", ""),
        ),
    )
    return {
        "authentication_required": summary.authentication_required,
        "privilege_required": summary.privilege_required,
        "user_interaction_required": summary.user_interaction_required,
        "exploit_available": summary.exploit_available,
        "public_poc": summary.public_poc,
        "active_exploitation": summary.active_exploitation,
        "exploit_complexity": summary.exploit_complexity,
        "cvss": {
            "attack_vector": summary.cvss.attack_vector,
            "attack_complexity": summary.cvss.attack_complexity,
            "attack_requirements": summary.cvss.attack_requirements,
            "privileges_required": summary.cvss.privileges_required,
            "user_interaction": summary.cvss.user_interaction,
            "source": summary.cvss.source,
        },
        "conflicts": list(summary.conflicts),
        "exploitability_evidence": [
            _evidence_record_dict(item) for item in records
        ],
    }


def _priority_evidence(
    evidence: object, fields: set[str]
) -> list[IntelligenceEvidence]:
    """Deterministic evidence references backing the contributing signals."""

    wanted = set(fields)
    records = [
        item
        for item in (evidence or [])
        if getattr(item, "field", "") in wanted
    ]
    records.sort(
        key=lambda item: (
            getattr(item, "field", ""),
            getattr(item, "value", ""),
            getattr(item, "source_artifact", ""),
            getattr(item, "source_url", "") or "",
            getattr(item, "source_type", ""),
            getattr(item, "evidence", ""),
            getattr(item, "rule_id", ""),
            getattr(item, "rule_version", ""),
        )
    )
    seen: set[tuple] = set()
    kept: list[IntelligenceEvidence] = []
    for item in records:
        key = (
            getattr(item, "field", ""),
            getattr(item, "value", ""),
            getattr(item, "source_url", None),
            getattr(item, "evidence", ""),
            getattr(item, "rule_id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)
    return kept


def summarize_research_priority(
    evidence: object,
    *,
    vulnerability_types: object = (),
    cwes: object = (),
    components: object = (),
    parameters: object = (),
) -> ResearchPriority:
    """Deterministically prioritize research attention from persisted evidence.

    Pure, order-independent, and idempotent: it reads the R15 exploitability
    projection derived from the same evidence stream plus the R12-R14 list
    fields. Missing (unknown) values never score and never become negative.
    The score is clamped to [PRIORITY_MIN_SCORE, PRIORITY_MAX_SCORE].
    """

    exploitability = summarize_exploitability(evidence)
    av = exploitability.cvss.attack_vector

    score = 0
    reasons: list[str] = []
    negatives: list[str] = []
    contributing: set[str] = set()

    # --- Exploit availability family (capped) ---
    exploit_points = 0
    if exploitability.active_exploitation == "true":
        exploit_points += PRIORITY_WEIGHTS["active_exploitation"]
        reasons.append("active exploitation reported")
        contributing.add("exploitability.active_exploitation")
    if exploitability.public_poc == "true":
        exploit_points += PRIORITY_WEIGHTS["public_poc"]
        reasons.append("public proof-of-concept available")
        contributing.add("exploitability.public_poc")
    if exploitability.exploit_available == "true":
        exploit_points += PRIORITY_WEIGHTS["exploit_available"]
        reasons.append("exploit availability reported")
        contributing.add("exploitability.exploit_available")
    score += min(
        exploit_points, PRIORITY_FAMILY_CAPS["exploit_availability"]
    )

    # --- Access family (capped) ---
    access_points = 0
    if exploitability.authentication_required == "false":
        access_points += PRIORITY_WEIGHTS["no_authentication"]
        reasons.append("no authentication required")
        contributing.add("exploitability.authentication_required")
    if exploitability.privilege_required == "false":
        access_points += PRIORITY_WEIGHTS["no_privileges"]
        reasons.append("no privileges required")
        contributing.add("exploitability.privilege_required")
    if exploitability.user_interaction_required == "false":
        access_points += PRIORITY_WEIGHTS["no_user_interaction"]
        reasons.append("no user interaction required")
        contributing.add("exploitability.user_interaction_required")
    score += min(access_points, PRIORITY_FAMILY_CAPS["access"])

    # --- Exploit complexity ---
    if exploitability.exploit_complexity == "low":
        score += PRIORITY_WEIGHTS["low_complexity"]
        reasons.append("low exploit complexity")
        contributing.add("exploitability.exploit_complexity")
    elif exploitability.exploit_complexity == "high":
        score += PRIORITY_WEIGHTS["high_complexity"]
        negatives.append("high exploit complexity")
        contributing.add("exploitability.exploit_complexity")

    # --- Attack vector ---
    if av == "N":
        score += PRIORITY_WEIGHTS["attack_vector_network"]
        reasons.append("network attack vector")
        contributing.add("exploitability.cvss.attack_vector")
    elif av == "A":
        score += PRIORITY_WEIGHTS["attack_vector_adjacent"]
        reasons.append("adjacent attack vector")
        contributing.add("exploitability.cvss.attack_vector")
    elif av == "L":
        score += PRIORITY_WEIGHTS["attack_vector_local"]
        negatives.append("local attack vector")
        contributing.add("exploitability.cvss.attack_vector")
    elif av == "P":
        score += PRIORITY_WEIGHTS["attack_vector_physical"]
        negatives.append("physical attack vector")
        contributing.add("exploitability.cvss.attack_vector")

    # --- Research relevance family (capped) ---
    relevance_points = 0
    if vulnerability_types:
        relevance_points += PRIORITY_WEIGHTS["vulnerability_type"]
        reasons.append("vulnerability type identified")
        contributing.add("vulnerability_type")
    if components:
        relevance_points += PRIORITY_WEIGHTS["affected_component"]
        reasons.append("affected component identified")
        contributing.add("component")
    if parameters:
        relevance_points += PRIORITY_WEIGHTS["affected_parameter"]
        reasons.append("affected parameter identified")
        contributing.add("parameter")
    if cwes:
        relevance_points += PRIORITY_WEIGHTS["cwe_mapped"]
        reasons.append("CWE mapped")
        contributing.add("cwe")
    score += min(
        relevance_points, PRIORITY_FAMILY_CAPS["research_relevance"]
    )

    # --- Unknown factors (never negative, never false) ---
    unknown_signals = (
        (exploitability.active_exploitation, "active exploitation status unknown"),
        (exploitability.public_poc, "public proof-of-concept status unknown"),
        (exploitability.exploit_available, "exploit availability status unknown"),
        (exploitability.authentication_required, "authentication requirement unknown"),
        (exploitability.privilege_required, "privilege requirement unknown"),
        (exploitability.user_interaction_required, "user interaction requirement unknown"),
        (exploitability.exploit_complexity, "exploit complexity unknown"),
        (av, "attack vector unknown"),
    )
    unknown_factors = [
        label for value, label in unknown_signals if value == "unknown"
    ]

    score = max(PRIORITY_MIN_SCORE, min(PRIORITY_MAX_SCORE, score))

    sufficient = bool(
        any(
            value != "unknown"
            for value in (
                exploitability.active_exploitation,
                exploitability.public_poc,
                exploitability.exploit_available,
                exploitability.authentication_required,
                exploitability.privilege_required,
                exploitability.user_interaction_required,
                exploitability.exploit_complexity,
                av,
            )
        )
        or vulnerability_types
        or cwes
        or components
        or parameters
    )
    if not sufficient:
        return ResearchPriority(
            priority="INSUFFICIENT_DATA",
            score=0,
            reasons=[],
            negative_factors=[],
            unknown_factors=unknown_factors,
            evidence=[],
        )

    priority = "LOW_RESEARCH"
    for name, threshold in PRIORITY_THRESHOLDS:
        if score >= threshold:
            priority = name
            break

    return ResearchPriority(
        priority=priority,
        score=score,
        reasons=reasons,
        negative_factors=negatives,
        unknown_factors=unknown_factors,
        evidence=_priority_evidence(evidence, contributing),
    )


def research_priority_projection(
    evidence: object,
    *,
    vulnerability_types: object = (),
    cwes: object = (),
    components: object = (),
    parameters: object = (),
) -> dict[str, object]:
    """Serialize the research-priority projection for the knowledge schema."""

    summary = summarize_research_priority(
        evidence,
        vulnerability_types=vulnerability_types,
        cwes=cwes,
        components=components,
        parameters=parameters,
    )
    return {
        "priority": summary.priority,
        "score": summary.score,
        "reasons": list(summary.reasons),
        "negative_factors": list(summary.negative_factors),
        "unknown_factors": list(summary.unknown_factors),
        "evidence": [
            _evidence_record_dict(item) for item in summary.evidence
        ],
        "rule_version": summary.rule_version,
    }


def _texts_from_research(payload: dict[str, object]) -> dict[str, str]:
    """Collect explicit research text without manufacturing prose."""

    research = payload.get("research")
    research_map = research if isinstance(research, dict) else {}
    texts: dict[str, str] = {}
    for key in (
        "title",
        "summary",
        "vulnerability_type",
        "root_cause",
        "description",
    ):
        value = research_map.get(key)
        if isinstance(value, str) and value.strip():
            texts[f"research.{key}"] = value
    for key in ("evidence", "references", "impact", "attack_requirements"):
        value = research_map.get(key)
        if isinstance(value, list):
            joined = "\n".join(
                str(item).strip() for item in value if str(item).strip()
            )
            if joined:
                texts[f"research.{key}"] = joined
    return texts


def _cwes_from_research(payload: dict[str, object]) -> list[str]:
    """Collect explicit NVD/CVE weakness identifiers when present."""

    candidates: list[str] = []
    for container in (payload.get("cve"), payload.get("metadata")):
        if not isinstance(container, dict):
            continue
        for key in ("cwes", "weaknesses", "cwe"):
            value = container.get(key)
            if isinstance(value, str):
                candidates.append(value)
            elif isinstance(value, list):
                candidates.extend(str(item) for item in value)
    cwes: list[str] = []
    for candidate in candidates:
        cwes.extend(
            f"CWE-{match.group('number')}"
            for match in _CWE_PATTERN.finditer(candidate)
        )
    return _ordered_unique(cwes)


def _extract_cwe_types(
    result: ExtractedIntelligence,
    cwes: list[str],
    *,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
) -> None:
    """Map only unambiguous weakness identifiers to broad types."""

    for candidate in cwes:
        number = candidate.upper().replace("CWE-", "", 1)
        for rule_id, value, rule_number in VULNERABILITY_TYPE_CWE_RULES:
            if number != rule_number:
                continue
            result.vulnerability_types.append(value)
            result.cwes.append(candidate.upper())
            _record(
                result,
                field="vulnerability_type",
                value=value,
                text=candidate,
                start=0,
                end=len(candidate),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
            _record(
                result,
                field="cwe",
                value=candidate.upper(),
                text=candidate,
                start=0,
                end=len(candidate),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )


def _extract_types_from_text(
    result: ExtractedIntelligence,
    text: str,
    attributor: _Attributor,
    *,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
) -> None:
    """Apply explicit vulnerability, subtype, and context phrases.

    Attribution is decided by the ``_Attributor`` for this document:
    evidence about a neighboring CVE (or page chrome naming another
    CVE) is never credited to this CVE's intelligence.
    """

    bounded = text[:MAX_INTELLIGENCE_TEXT_CHARS]
    for rule_id, value, pattern in _VULNERABILITY_TEXT_PATTERNS:
        for match in pattern.finditer(bounded):
            if not attributor.accepts(bounded, match):
                continue
            result.vulnerability_types.append(value)
            _record(
                result,
                field="vulnerability_type",
                value=value,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    for rule_id, value, pattern in _XSS_PATTERNS:
        for match in pattern.finditer(bounded):
            if not attributor.accepts(bounded, match):
                continue
            result.xss_types.append(value)
            _record(
                result,
                field="xss_type",
                value=value,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    for rule_id, value, pattern in _CONTEXT_PATTERNS:
        for match in pattern.finditer(bounded):
            if not attributor.accepts(bounded, match):
                continue
            result.contexts.append(value)
            _record(
                result,
                field="context",
                value=value,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    # Stage R14: explicit parameter label forms ("vulnerable parameter:
    # id", "parameter name = user_id"). These are the strongest forms and
    # may legitimately name otherwise-generic words like "input".
    for rule_id, pattern in _PARAMETER_LABEL_PATTERNS:
        for match in pattern.finditer(bounded):
            name = _normalize_parameter_name(match.group(1))
            if name is None:
                continue
            if not attributor.accepts(bounded, match):
                continue
            result.parameters.append(name)
            _record(
                result,
                field="parameter",
                value=name,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    # Stage R14: bare "<name> parameter" adjacency ("id parameter of
    # view_each_faculty.php"). Generic adjacency words (input, request,
    # user, page, ...) are accepted only when the surrounding window
    # carries an explicit parameter label naming them, so ordinary
    # prose like "the input parameter was reflected" stays out.
    bare_rule_id, bare_pattern_str = PARAMETER_BARE_RULE
    bare_pattern = re.compile(bare_pattern_str, re.IGNORECASE)
    for match in bare_pattern.finditer(bounded):
        name = _normalize_parameter_name(match.group(1))
        if name is None:
            continue
        if name in _BARE_ADJACENCY_GENERIC_NAMES:
            window_start = max(0, match.start() - MAX_EVIDENCE_WINDOW_CHARS)
            window_end = min(len(bounded), match.end() + MAX_EVIDENCE_WINDOW_CHARS)
            window = bounded[window_start:window_end].lower()
            labeled = re.search(
                r"(?:vulnerable|affected)\s+(?:parameter|argument|field)s?\b|"
                r"(?:parameter|argument|field)\s+name\b",
                window,
                re.IGNORECASE,
            )
            if not labeled:
                continue
        if not attributor.accepts(bounded, match):
            continue
        result.parameters.append(name)
        _record(
            result,
            field="parameter",
            value=name,
            text=bounded,
            start=match.start(),
            end=match.end(),
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=source_type,
            rule_id=bare_rule_id,
        )
    # Stage R14: forward "parameter <name>" form ("parameter id",
    # "GET parameter id", 'parameter "id"'). Blocklist rejects the
    # sentence words that usually follow ("of", "is", "was", "name").
    for rule_id, pattern in _PARAMETER_FORWARD_PATTERNS:
        for match in pattern.finditer(bounded):
            name = _normalize_parameter_name(match.group(1))
            if name is None:
                continue
            if not attributor.accepts(bounded, match):
                continue
            result.parameters.append(name)
            _record(
                result,
                field="parameter",
                value=name,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )

    # Stage R14: vulnerable component / file / endpoint evidence.
    # Every candidate must sit inside a vulnerability-oriented context
    # window, so unrelated project-file listings yield nothing.
    _extract_components_from_text(
        result,
        bounded,
        attributor,
        source_artifact=source_artifact,
        source_url=source_url,
        source_type=source_type,
    )

    # Stage R15: deterministic exploitability prose rules (same attribution
    # gating, so a neighboring CVE's claims are never credited here).
    _extract_exploitability_from_text(
        result,
        bounded,
        attributor,
        source_artifact=source_artifact,
        source_url=source_url,
        source_type=source_type,
    )


def _extract_components_from_text(
    result: ExtractedIntelligence,
    bounded: str,
    attributor: _Attributor,
    *,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
) -> None:
    """Stage R14: deterministic vulnerable component/file/endpoint rules.

    Each candidate must (a) pass ``_validate_component_value``, (b) sit
    within a vulnerability-oriented context window, and (c) be accepted
    by the attribution engine, so unrelated filenames, CVE-silent pages
    without product linkage, and neighboring-CVE evidence are excluded
    exactly as in R12.
    """

    def _record_component(
        value: str, start: int, end: int, rule_id: str
    ) -> None:
        result.components.append(value)
        _record(
            result,
            field="component",
            value=value,
            text=bounded,
            start=start,
            end=end,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=source_type,
            rule_id=rule_id,
        )

    def _context_ok(match: re.Match[str]) -> bool:
        window_start = max(0, match.start() - MAX_EVIDENCE_WINDOW_CHARS)
        window_end = min(len(bounded), match.end() + MAX_EVIDENCE_WINDOW_CHARS)
        return bool(
            VULN_CONTEXT_PATTERN.search(bounded[window_start:window_end])
        )

    # Explicit vulnerable-file/component labels ("vulnerable file:
    # foo.php", "affected component is /admin/login.php").
    for rule_id, pattern_str in _COMPONENT_LABEL_RULES:
        pattern = re.compile(pattern_str, re.IGNORECASE)
        for match in pattern.finditer(bounded):
            value = _validate_component_value(match.group(1))
            if value is None or not _context_ok(match):
                continue
            if not attributor.accepts(bounded, match):
                continue
            _record_component(value, match.start(), match.end(), rule_id)

    # Explicitly labeled endpoints/paths ("endpoint /api/users",
    # "the affected endpoint is /api/foo", "url: /admin/login.php").
    for rule_id, pattern_str in _COMPONENT_ENDPOINT_RULES:
        pattern = re.compile(pattern_str, re.IGNORECASE)
        for match in pattern.finditer(bounded):
            value = _validate_component_value(match.group(1))
            if value is None or not _context_ok(match):
                continue
            if not attributor.accepts(bounded, match):
                continue
            _record_component(value, match.start(), match.end(), rule_id)

    # Bare source-file candidates ("id parameter of view_each_faculty.php",
    # "in the foo.php file"): extracted only when a vulnerability-
    # oriented word occurs in the bounded window around the candidate.
    # Exploit-tooling filenames shipped with PoC repositories ("poc.sh",
    # "exploit.py", "payload.py") describe the proof-of-concept, not the
    # vulnerable component, and are rejected on the bare path only.
    _exploit_tooling = re.compile(
        r"^(?:poc|exploit|payload)(?:[-_.][A-Za-z0-9_\-]+)*$"
    )
    for match in _COMPONENT_FILE_PATTERN.finditer(bounded):
        value = _validate_component_value(match.group(0))
        if value is None or not _context_ok(match):
            continue
        stem = value.rsplit(".", 1)[0].rsplit("/", 1)[-1]
        if _exploit_tooling.fullmatch(stem):
            continue
        if not attributor.accepts(bounded, match):
            continue
        _record_component(
            value, match.start(), match.end(), "component-file-context"
        )


def _dedupe_intelligence(result: ExtractedIntelligence) -> None:
    """Deterministic dedup of parameters and components.

    Equivalent forms converge ("id" / "'id'" / "\"id\""; "/foo.php" /
    "foo.php"). The first evidence record per normalized key survives;
    later duplicate records for the same value are removed so repeated
    ingestion stays byte-identical and first-seen ordering is stable.
    """

    def _dedupe(values: list[str], field: str, key_fn) -> list[str]:
        seen: set[str] = set()
        kept: list[str] = []
        for value in values:
            key = key_fn(value)
            if key in seen:
                continue
            seen.add(key)
            kept.append(value)
        allowed = {key_fn(value) for value in kept}
        first_by_key: set[str] = set()
        kept_evidence = []
        for item in result.evidence:
            if item.field == field:
                key = key_fn(item.value)
                if key not in allowed or key in first_by_key:
                    continue
                first_by_key.add(key)
            kept_evidence.append(item)
        result.evidence[:] = kept_evidence
        return kept

    result.parameters = _dedupe(
        result.parameters, "parameter", _normalize_parameter_key
    )
    result.components = _dedupe(
        result.components, "component", _normalize_component_key
    )


def _reference_sources(
    records: object,
) -> list[tuple[str, str | None, str]]:
    """Return deterministic (text, URL, type) reference evidence."""

    if not isinstance(records, list):
        return []
    sources: list[tuple[str, str | None, str]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        url = record.get("source_url")
        source_url = str(url).strip() if str(url or "").strip() else None
        source_type = str(record.get("source_type") or "reference").strip()
        parts: list[str] = []
        title = record.get("title")
        if isinstance(title, str) and title.strip():
            parts.append(title.strip())
        # Stage R13: normalized extracted body, when persisted, is
        # explicit reference evidence. R12 rules themselves are
        # untouched; this only widens the text the rules run over.
        body = record.get("body")
        if isinstance(body, str) and body.strip():
            parts.append(body.strip()[:MAX_INTELLIGENCE_TEXT_CHARS])
        chunks = record.get("context_chunks")
        if isinstance(chunks, list):
            for chunk in chunks:
                text = str(chunk or "").strip()
                if text:
                    parts.append(text)
        exact = record.get("exact_record")
        if isinstance(exact, str) and exact.strip():
            parts.append(exact.strip())
        text = "\n".join(parts).strip()
        if text:
            sources.append(
                (text[:MAX_INTELLIGENCE_TEXT_CHARS], source_url, source_type)
            )
    # Lexicographic source order keeps repeated runs deterministic when
    # callers pass the same records in any order.
    sources.sort(key=lambda item: ((item[1] or ""), item[2], item[0]))
    return sources


def product_terms_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Normalized vendor/product names stated by the CVE record itself."""

    cve = payload.get("cve")
    cve_map = cve if isinstance(cve, dict) else {}
    terms: list[str] = []
    for key in ("products", "product", "vendor"):
        value = cve_map.get(key)
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = " ".join(str(item or "").lower().split())
            if len(text) >= _MIN_PRODUCT_TERM_CHARS:
                terms.append(text)
    return tuple(sorted(set(terms)))


def extract_research_intelligence(
    cve_id: str,
    payload: dict[str, object],
    records: object,
    *,
    product_terms: tuple[str, ...] | None = None,
) -> ExtractedIntelligence:
    """Extract intelligence only from explicit persisted evidence."""

    result = ExtractedIntelligence()
    normalized_cve = (cve_id or "").strip()
    source_artifact = f"{normalized_cve or 'UNKNOWN'}.cli.json"
    payload_map = payload if isinstance(payload, dict) else {}
    terms = product_terms if product_terms is not None else product_terms_from_payload(
        payload_map
    )

    _extract_cwe_types(
        result,
        _cwes_from_research(payload_map),
        source_artifact=source_artifact,
        source_url=None,
        source_type="research",
    )
    # Stage R15: explicit structured CVSS metrics and research booleans.
    _extract_structured_cvss(result, payload_map, source_artifact)
    _extract_structured_research_flags(result, payload_map, source_artifact)
    if isinstance(payload, dict):
        payload_cve = payload_map.get("cve")
        payload_cve_id = (
            str(payload_cve.get("id") or "").strip().lower()
            if isinstance(payload_cve, dict)
            else ""
        )
        structural = bool(
            normalized_cve and payload_cve_id == normalized_cve.lower()
        )
        for _source, text in sorted(_texts_from_research(payload).items()):
            bounded = text[:MAX_INTELLIGENCE_TEXT_CHARS]
            _extract_types_from_text(
                result,
                bounded,
                _Attributor(
                    normalized_cve, bounded, product_terms=terms,
                    structural=structural,
                ),
                source_artifact=source_artifact,
                source_url=None,
                source_type="research",
            )

    for text, source_url, source_type in _reference_sources(records):
        bounded = text[:MAX_INTELLIGENCE_TEXT_CHARS]
        _extract_types_from_text(
            result,
            bounded,
            _Attributor(
                normalized_cve, bounded, product_terms=terms,
            ),
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=source_type,
        )

    result.vulnerability_types = _ordered_unique(result.vulnerability_types)
    result.cwes = _ordered_unique(result.cwes)
    result.xss_types = _ordered_unique(result.xss_types)
    result.contexts = _ordered_unique(result.contexts)
    result.parameters = _ordered_unique(result.parameters)
    result.components = _ordered_unique(result.components)
    # Stage R14: cross-source deterministic dedup for parameters and
    # components. First-seen source order wins; the surviving evidence
    # record per normalized key is deterministic because reference
    # sources are iterated in sorted order.
    _dedupe_intelligence(result)
    result.parameters = _ordered_unique(result.parameters)
    result.components = _ordered_unique(result.components)
    # Stage R15: exploitability evidence is deduped and aggregated into the
    # additive projection. The evidence stream remains the single source of
    # truth, so the projection is order-independent and recomputable.
    _dedupe_exploitability_evidence(result)
    result.exploitability = summarize_exploitability(result.evidence)
    result.evidence.sort(
        key=lambda item: (
            item.field,
            item.value,
            item.source_artifact,
            item.source_url or "",
            item.source_type,
            item.evidence,
            item.rule_id,
            item.rule_version,
        )
    )
    return result
