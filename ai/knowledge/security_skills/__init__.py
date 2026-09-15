"""R69 Watch-native security research skill library.

Bounded, deterministic, research-only methodology for the AI research pipeline
(R61 snapshot -> R62 bridge -> R68 evidence selection -> this library ->
OpenRouter -> R65 grounding -> R66 per-hypothesis validation).

Skills guide reasoning and false-positive control only. They are not evidence,
not authorization for any action, never grant execution permission, and never
prove a vulnerability. Evidence identity and resolution stay Watch-owned.
"""

from ai.knowledge.security_skills.library import (
    MAX_SKILLS,
    MAX_SKILL_TEXT_CHARS,
    RULE_VERSION,
    SIGNAL_SKILLS,
    SKILL_CATEGORY_ORDER,
    all_skills,
    render_skill,
    render_skills,
    select_skills,
    skill_by_id,
)
from ai.knowledge.security_skills.skills import SKILLS

__all__ = [
    "RULE_VERSION",
    "MAX_SKILLS",
    "MAX_SKILL_TEXT_CHARS",
    "SKILL_CATEGORY_ORDER",
    "SIGNAL_SKILLS",
    "SKILLS",
    "all_skills",
    "skill_by_id",
    "select_skills",
    "render_skill",
    "render_skills",
]
