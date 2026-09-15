"""R69 deterministic, bounded Watch-native research skill selection.

The library selects at most a few research skills for one bounded research
context. Selection is a pure function of the supplied watch signals and
evidence items:

- category-aware: verified watch signals select their category skill;
- evidence-aware: deterministic structural patterns (object-reference routes,
  URL/host or redirect-shaped parameters, token/OAuth-shaped parameters,
  GraphQL paths, observed technology+version pairs) select the relevant
  methodology even without a signal;
- bounded: at most ``MAX_SKILLS`` skills, rendered within
  ``MAX_SKILL_TEXT_CHARS`` so the existing prompt budget is preserved;
- deterministic: ordering and rendering never depend on set/dict iteration
  order or randomness.

Skills are research methodology only. They never authorize execution, never
change the safety block, and never replace evidence resolution or the
R65/R66 validation gates.
"""

from __future__ import annotations

import re
from typing import Iterable, Mapping, Sequence

from ai.knowledge.security_skills.skills import SKILLS

RULE_VERSION = "r69-1"
MAX_SKILLS = 3
MAX_SKILL_TEXT_CHARS = 2100

SKILL_CATEGORY_ORDER: tuple[str, ...] = (
    "XSS",
    "SSRF",
    "SQLI",
    "IDOR",
    "JWT",
    "OAUTH",
    "RECON",
    "CVE_RESEARCH",
)

SIGNAL_SKILLS: dict[str, str] = {
    "XSS": "xss",
    "SSRF": "ssrf",
    "SQLI": "sqli",
    "IDOR": "idor-bola",
    "JWT": "jwt",
    "OAUTH": "oauth",
    "CVE_RESEARCH": "cve-research",
}

_OBJECT_REFERENCE_RE = re.compile(
    r"\{(id|uuid|hash)\}|:id(?:/|$)|/\d{2,}(?:/|$)", re.IGNORECASE
)
_GRAPHQL_PATH_RE = re.compile(
    r"(^|/)graphql(/|$)|(^|/)gql(/|$)", re.IGNORECASE
)
_REDIRECT_PARAM_RE = re.compile(
    r"^(url|uri|redirect|redirect_uri|redirect_url|next|return|returnurl|"
    r"return_url|continue|dest|destination|target|callback)$",
    re.IGNORECASE,
)
_FETCH_PARAM_RE = re.compile(
    r"^(url|uri|host|hostname|src|source|fetch|image|imageurl|image_url|"
    r"webhook|callback|endpoint|proxy|feed|link)$",
    re.IGNORECASE,
)
_TOKEN_PARAM_RE = re.compile(
    r"^(jwt|jws|token|access_token|id_token|bearer|jtoken)$", re.IGNORECASE
)
_OAUTH_PARAM_RE = re.compile(
    r"^(code|state|nonce|assertion|saml|samlresponse|redirect_uri|client_id|"
    r"scope|grant_type|id_token|access_token|response_type)$",
    re.IGNORECASE,
)
_LOGIC_PARAM_RE = re.compile(
    r"^(price|amount|quantity|qty|discount|coupon|total|role|plan|tier|"
    r"credit|balance|limit|step|status)$",
    re.IGNORECASE,
)


def all_skills() -> tuple[dict, ...]:
    """Every skill as a defensive copy (discovery entry point)."""

    return tuple(dict(skill) for skill in SKILLS)


def skill_by_id(skill_id: object) -> dict | None:
    """One skill copy by id, or ``None`` for unknown ids."""

    name = str(skill_id if skill_id is not None else "").strip()
    for skill in SKILLS:
        if skill["skill_id"] == name:
            return dict(skill)
    return None


def _evidence_items(evidence: object) -> list[Mapping]:
    if isinstance(evidence, Mapping):
        candidates: Iterable = evidence.values()
    elif isinstance(evidence, (list, tuple)):
        candidates = evidence
    else:
        return []
    return [item for item in candidates if isinstance(item, Mapping)]


def _evidence_kinds(items: Sequence[Mapping]) -> set[str]:
    return {
        str(item.get("kind") or "").strip().lower() for item in items
    }


def _recon_skill(items: Sequence[Mapping]) -> str:
    for item in items:
        kind = str(item.get("kind") or "").strip().lower()
        value = str(item.get("value") or "")
        if kind == "path" and _GRAPHQL_PATH_RE.search(value):
            return "graphql"
    for item in items:
        kind = str(item.get("kind") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if kind == "parameter" and _REDIRECT_PARAM_RE.match(value):
            return "open-redirect"
    for item in items:
        kind = str(item.get("kind") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if kind == "parameter" and _LOGIC_PARAM_RE.match(value):
            return "business-logic"
    return "api-security"


def _ordered(candidates: Iterable[str]) -> list[str]:
    by_id = {skill["skill_id"]: skill for skill in SKILLS}
    known = [name for name in candidates if name in by_id]
    return sorted(
        set(known),
        key=lambda name: (
            SKILL_CATEGORY_ORDER.index(by_id[name]["category"]),
            name,
        ),
    )


def select_skills(
    *,
    signals: object = None,
    evidence: object = None,
    limit: int = MAX_SKILLS,
) -> list[dict]:
    """Deterministically select the relevant bounded skill set."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if limit < 0:
        raise ValueError("limit must be >= 0")

    items = _evidence_items(evidence)
    candidates: set[str] = set()

    signal_map = signals if isinstance(signals, Mapping) else {}
    for category in signal_map:
        name = str(category).strip().upper()
        if name == "RECON":
            candidates.add(_recon_skill(items))
        elif name in SIGNAL_SKILLS:
            candidates.add(SIGNAL_SKILLS[name])

    for item in items:
        kind = str(item.get("kind") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if kind == "path":
            if _OBJECT_REFERENCE_RE.search(value):
                candidates.add("idor-bola")
            if _GRAPHQL_PATH_RE.search(value):
                candidates.add("graphql")
        elif kind == "parameter":
            if _FETCH_PARAM_RE.match(value):
                candidates.add("ssrf")
            if _REDIRECT_PARAM_RE.match(value):
                candidates.add("open-redirect")
            if _TOKEN_PARAM_RE.match(value):
                candidates.add("jwt")
            if _OAUTH_PARAM_RE.match(value):
                candidates.add("oauth")
            if _LOGIC_PARAM_RE.match(value):
                candidates.add("business-logic")
        elif kind == "derived_signal":
            name = str(item.get("signal") or "").strip().upper()
            if name in SIGNAL_SKILLS:
                candidates.add(SIGNAL_SKILLS[name])

    kinds = _evidence_kinds(items)
    if "technology" in kinds and "version" in kinds:
        candidates.add("cve-research")

    by_id = {skill["skill_id"]: skill for skill in SKILLS}
    return [dict(by_id[name]) for name in _ordered(candidates)[:limit]]


def render_skill(skill: Mapping) -> str:
    """Compact one-line rendering for the bounded LLM prompt."""

    return (
        f"{skill.get('skill_id')} [{skill.get('category')}] "
        f"when: {skill.get('applicability')} "
        f"need: {'; '.join(skill.get('required_evidence') or ())} "
        f"method: {'; '.join(skill.get('methodology') or ())} "
        f"avoid: {'; '.join(skill.get('false_positives') or ())} "
        f"reject: {'; '.join(skill.get('rejection_cases') or ())} "
        f"next: {'; '.join(skill.get('safe_next_actions') or ())} "
        f"cap: {skill.get('confidence_constraints')}"
    )


def render_skills(
    skills: Sequence[Mapping] | None,
    *,
    max_chars: int = MAX_SKILL_TEXT_CHARS,
) -> list[str]:
    """Render whole skills in order while staying within ``max_chars``."""

    rendered: list[str] = []
    total = 0
    for skill in skills or ():
        if not isinstance(skill, Mapping):
            continue
        line = render_skill(skill)
        extra = len(line) + (1 if rendered else 0)
        if total + extra > max_chars:
            break
        rendered.append(line)
        total += extra
    return rendered


__all__ = [
    "RULE_VERSION",
    "MAX_SKILLS",
    "MAX_SKILL_TEXT_CHARS",
    "SKILL_CATEGORY_ORDER",
    "SIGNAL_SKILLS",
    "all_skills",
    "skill_by_id",
    "select_skills",
    "render_skill",
    "render_skills",
]
