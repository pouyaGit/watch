from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import yaml

from ai.schemas.detection import DetectionSpec


class NucleiTemplateGenerator:
    """
    Generate a safe HTTP Nuclei template from DetectionSpec.

    This class only generates YAML.
    It never executes Nuclei.
    """

    def generate(
        self,
        detection: DetectionSpec,
        *,
        name: str,
        author: str = "watch-ai",
        severity: str = "high",
        description: str = "",
        tags: list[str] | None = None,
    ) -> str:

        if not detection.reliable_signature:
            raise ValueError(
                "Cannot generate a reliable Nuclei template "
                "without a deterministic detection signature."
            )

        if not detection.http_method:
            raise ValueError(
                "HTTP method is required."
            )

        if not detection.path:
            raise ValueError(
                "HTTP path is required."
            )

        if not detection.response_matchers:
            raise ValueError(
                "At least one response matcher is required."
            )

        if detection.destructive:
            raise ValueError(
                "Refusing to generate a template marked destructive."
            )

        protocols = {
            protocol.lower()
            for protocol in detection.protocol
        }

        if "http" not in protocols:
            raise ValueError(
                "This generator only supports HTTP templates."
            )

        # --------------------------------------------------
        # Build query string
        # --------------------------------------------------

        query_parts = []

        for parameter in detection.query_parameters:

            value = (
                detection.query_parameter_values.get(
                    parameter,
                    "",
                )
            )

            encoded_parameter = quote(
                str(parameter),
                safe="",
            )

            # Keep slash characters unescaped because
            # they are meaningful in path-like payloads.
            encoded_value = quote(
                str(value),
                safe="/:@-._~!$'()*+,;=",
            )

            query_parts.append(
                f"{encoded_parameter}="
                f"{encoded_value}"
            )

        query = "&".join(
            query_parts
        )

        target = detection.path

        if query:
            target = (
                f"{target}?{query}"
            )

        # --------------------------------------------------
        # Raw HTTP request
        # --------------------------------------------------

        raw_lines = [
            (
                f"{detection.http_method} "
                f"{target} HTTP/1.1"
            )
        ]

        for header, value in (
            detection.headers.items()
        ):
            raw_lines.append(
                f"{header}: {value}"
            )

        raw_request = "\n".join(
            raw_lines
        )

        # --------------------------------------------------
        # Tags
        # --------------------------------------------------

        final_tags = [
            "cve",
            "generated",
            "watch-ai",
        ]

        if tags:
            final_tags.extend(tags)

        # --------------------------------------------------
        # Template
        # --------------------------------------------------

        template = {
            "id": detection.cve_id,
            "info": {
                "name": name,
                "author": author,
                "severity": severity,
                "description": description,
                "tags": ",".join(
                    sorted(
                        set(final_tags)
                    )
                ),
            },
            "http": [
                {
                    "raw": [
                        raw_request,
                    ],
                    "matchers": [
                        {
                            "type": "dsl",
                            "dsl": (
                                detection.response_matchers
                            ),
                            "condition": "and",
                        }
                    ],
                }
            ],
        }

        return yaml.safe_dump(
            template,
            sort_keys=False,
            allow_unicode=True,
        )

    def write(
        self,
        detection: DetectionSpec,
        output_path: str | Path,
        *,
        name: str,
        author: str = "watch-ai",
        severity: str = "high",
        description: str = "",
        tags: list[str] | None = None,
    ) -> Path:

        content = self.generate(
            detection,
            name=name,
            author=author,
            severity=severity,
            description=description,
            tags=tags,
        )

        path = Path(
            output_path
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            content,
            encoding="utf-8",
        )

        return path