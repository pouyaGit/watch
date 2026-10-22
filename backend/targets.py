"""Validation for target (program) input. Pure functions, no database access."""
import re

PROGRAM_NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
APEX_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


class ValidationError(ValueError):
    pass


def validate_program_name(raw) -> str:
    name = (raw or "").strip().lower()
    if not PROGRAM_NAME_RE.match(name):
        raise ValidationError("program_name must be 1-64 chars of a-z, 0-9, '_' or '-'.")
    return name


def split_list(raw) -> list:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = raw.replace(",", "\n").splitlines()
    return [str(item).strip() for item in raw if str(item).strip()]


def normalize_apex_list(items, label: str) -> list:
    out, seen = [], set()
    for item in split_list(items):
        value = item.lower()
        if "://" in value or "/" in value or ":" in value or " " in value:
            raise ValidationError(f"{label} must be bare domains, not URLs or paths: {item!r}")
        if not APEX_RE.match(value):
            raise ValidationError(f"{label} is not a valid domain: {item!r}")
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
