from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


def stringify_evidence(value: Any) -> str:
    """
    Normalize evidence from either:

        "CONFIRMED: ..."

    or:

        {
            "classification": "CONFIRMED",
            "detail": "..."
        }

    into one readable string.
    """

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        classification = (
            value.get("classification")
            or value.get("status")
            or value.get("type")
            or ""
        )

        detail = (
            value.get("detail")
            or value.get("description")
            or value.get("evidence")
            or value.get("reason")
            or ""
        )

        if classification and detail:
            return f"{classification}: {detail}"

        if detail:
            return str(detail)

        return str(value)

    return str(value)


def stringify_affected_version(value: Any) -> str:
    """
    Normalize affected-version entries.

    Examples:

        "12.2.1.4.0"

    or:

        {
            "version": "12.2.1.4.0",
            "less_than": "12.2.1.5.0",
            "status": "affected"
        }
    """

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        version = (
            value.get("version")
            or value.get("from")
            or value.get("min")
        )

        less_than = (
            value.get("less_than")
            or value.get("lessThan")
            or value.get("to")
            or value.get("max")
        )

        status = value.get("status")

        if version and less_than:
            result = f"{version} < {less_than}"
        elif version:
            result = str(version)
        elif less_than:
            result = f"< {less_than}"
        else:
            result = str(value)

        if status:
            result += f" ({status})"

        return result

    return str(value)


def stringify_affected_product(value: Any) -> str | None:
    """
    Normalize an affected-product entry to a canonical string.

    The LLM occasionally emits objects such as::

        {"name": "WP Responsive Images", "type": "WordPress Plugin"}

    instead of the schema-required plain string. This normalizer runs
    at the LLM-output boundary (``mode="before"`` validation), keeping
    the public schema strictly ``list[str]``:

    - string -> unchanged (existing behavior preserved verbatim)
    - dict with ``name`` -> the name
    - dict with ``name`` + ``type`` -> ``"name (type)"``
    - malformed/empty dict (no usable ``name``) -> ``None`` so the
      caller drops the item instead of inventing a product name
    - ``None`` -> ``None`` (dropped)
    - other scalars -> ``str(value)`` (dropped when empty)
    - other containers (list/tuple/set) -> ``None`` (dropped)
    """

    if value is None:
        return None

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        name = value.get("name")
        product_type = value.get("type")

        name_text = str(name).strip() if name is not None else ""
        type_text = (
            str(product_type).strip()
            if product_type is not None
            else ""
        )

        if name_text and type_text:
            return f"{name_text} ({type_text})"

        if name_text:
            return name_text

        return None

    if isinstance(value, (list, tuple, set)):
        return None

    text = str(value)

    return text if text.strip() else None


class ResearchResult(BaseModel):
    title: str
    summary: str

    vulnerability_type: str | None = None
    severity: str | None = None

    cve_ids: list[str] = Field(
        default_factory=list
    )

    affected_products: list[str] = Field(
        default_factory=list
    )

    affected_versions: list[str] = Field(
        default_factory=list
    )

    attack_requirements: list[str] = Field(
        default_factory=list
    )

    root_cause: str | None = None

    impact: list[str] = Field(
        default_factory=list
    )

    public_exploit: bool | None = None
    actively_exploited: bool | None = None

    bug_bounty_relevance: int = Field(
        default=0,
        ge=0,
        le=10,
    )

    detection_ideas: list[str] = Field(
        default_factory=list
    )

    nuclei_candidate: bool = False
    nuclei_reason: str | None = None

    references: list[str] = Field(
        default_factory=list
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    @field_validator(
        "affected_products",
        mode="before",
    )
    @classmethod
    def normalize_products(
        cls,
        value,
    ):
        if value is None:
            return []

        if not isinstance(value, list):
            value = [value]

        normalized: list[str] = []

        for item in value:
            text = stringify_affected_product(item)

            if text is None:
                continue

            normalized.append(text)

        return normalized

    @field_validator(
        "evidence",
        mode="before",
    )
    @classmethod
    def normalize_evidence(
        cls,
        value,
    ):
        if value is None:
            return []

        if not isinstance(value, list):
            value = [value]

        return [
            stringify_evidence(item)
            for item in value
        ]

    @field_validator(
        "affected_versions",
        mode="before",
    )
    @classmethod
    def normalize_versions(
        cls,
        value,
    ):
        if value is None:
            return []

        if not isinstance(value, list):
            value = [value]

        return [
            stringify_affected_version(item)
            for item in value
        ]