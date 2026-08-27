from __future__ import annotations

from urllib.parse import parse_qsl, quote, urlsplit

import yaml

from ai.schemas.detection import DetectionSpec


class NucleiTemplateParser:
    """
    Extract a DetectionSpec from an existing Nuclei template.

    This parser only reads YAML and never executes the template.
    """

    def parse(
        self,
        content: str,
        cve_id: str,
    ) -> DetectionSpec:

        data = yaml.safe_load(
            content
        ) or {}

        http_blocks = data.get(
            "http",
            [],
        )

        if not http_blocks:
            return DetectionSpec(
                cve_id=cve_id,
                protocol=[],
                reliable_signature=False,
                confidence=0.0,
                missing_requirements=[
                    "HTTP template block",
                ],
            )

        block = http_blocks[0]

        method = None
        path = None

        query_parameters = []
        query_parameter_values = {}

        headers = {}

        response_matchers = []
        response_status = []

        # ==================================================
        # RAW REQUEST
        # ==================================================

        raw_requests = block.get(
            "raw",
            [],
        )

        if raw_requests:

            raw = raw_requests[0]

            lines = [
                line.strip()
                for line in raw.splitlines()
                if line.strip()
            ]

            if lines:

                request_line = lines[0]
                parts = request_line.split()

                if len(parts) >= 2:

                    method = parts[0].upper()
                    target = parts[1]

                    parsed = urlsplit(
                        target
                    )

                    path = parsed.path

                    query_pairs = parse_qsl(
                        parsed.query,
                        keep_blank_values=True,
                    )

                    for key, value in query_pairs:
                        query_parameters.append(
                            key
                        )
                        query_parameter_values[key] = value

                    for line in lines[1:]:

                        if ":" not in line:
                            continue

                        name, value = line.split(
                            ":",
                            1,
                        )

                        headers[
                            name.strip()
                        ] = value.strip()

        # ==================================================
        # MATCHERS
        # ==================================================

        for matcher in block.get(
            "matchers",
            [],
        ):

            if matcher.get("type") != "dsl":
                continue

            dsl_values = matcher.get(
                "dsl",
                [],
            )

            if isinstance(
                dsl_values,
                str,
            ):
                dsl_values = [
                    dsl_values
                ]

            for expression in dsl_values:

                if not isinstance(
                    expression,
                    str,
                ):
                    continue

                expression = expression.strip()

                if not expression:
                    continue

                response_matchers.append(
                    expression
                )

                for code in (
                    200,
                    201,
                    204,
                    301,
                    302,
                    400,
                    401,
                    403,
                    404,
                    500,
                ):
                    if (
                        f"status_code=={code}"
                        in expression
                    ):
                        response_status.append(
                            code
                        )

        # ==================================================
        # SAFETY
        # ==================================================

        destructive = False

        if (
            method
            and method.upper() == "DELETE"
        ):
            destructive = True

        # ==================================================
        # RELIABILITY
        # ==================================================

        reliable = bool(
            method
            and path
            and response_matchers
        )

        missing = []

        if not method:
            missing.append(
                "HTTP method"
            )

        if not path:
            missing.append(
                "HTTP path"
            )

        if not response_matchers:
            missing.append(
                "Response matcher"
            )

        if not response_status:
            missing.append(
                "Response status condition"
            )

        # ==================================================
        # CONFIDENCE
        # ==================================================

        if reliable:
            confidence = 0.95
        elif method and path:
            confidence = 0.65
        elif method or path:
            confidence = 0.45
        else:
            confidence = 0.20

        return DetectionSpec(
            cve_id=cve_id,
            protocol=["http"],
            http_method=method,
            path=path,
            query_parameters=query_parameters,
            query_parameter_values=(
                query_parameter_values
            ),
            headers=headers,
            body_pattern=None,
            response_status=sorted(
                set(response_status)
            ),
            response_matchers=response_matchers,
            version_required=True,
            affected_versions=[],
            authentication_required=False,
            destructive=destructive,
            reliable_signature=reliable,
            confidence=confidence,
            evidence=[
                "Detection specification extracted "
                "from an existing Nuclei template."
            ],
            missing_requirements=missing,
        )