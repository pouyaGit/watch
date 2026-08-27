from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]
    warnings: list[str]


class NucleiSemanticValidator:
    """
    Validate a generated Nuclei template against the
    DetectionSpec that produced it.

    This is semantic validation, not textual diffing.
    """

    def validate(
        self,
        detection,
        generated_yaml: str,
    ) -> ValidationResult:

        from ai.collectors.nuclei_template import (
            NucleiTemplateParser,
        )

        parser = NucleiTemplateParser()

        generated = parser.parse(
            content=generated_yaml,
            cve_id=detection.cve_id,
        )

        errors = []
        warnings = []

        # --------------------------------------------------
        # Protocol
        # --------------------------------------------------

        expected_protocols = {
            p.lower()
            for p in detection.protocol
        }

        actual_protocols = {
            p.lower()
            for p in generated.protocol
        }

        if expected_protocols != actual_protocols:
            errors.append(
                "Protocol mismatch: "
                f"expected={sorted(expected_protocols)} "
                f"actual={sorted(actual_protocols)}"
            )

        # --------------------------------------------------
        # Method
        # --------------------------------------------------

        if (
            detection.http_method
            != generated.http_method
        ):
            errors.append(
                "HTTP method mismatch: "
                f"expected={detection.http_method!r} "
                f"actual={generated.http_method!r}"
            )

        # --------------------------------------------------
        # Path
        # --------------------------------------------------

        if (
            detection.path
            != generated.path
        ):
            errors.append(
                "HTTP path mismatch: "
                f"expected={detection.path!r} "
                f"actual={generated.path!r}"
            )

        # --------------------------------------------------
        # Query parameters
        # --------------------------------------------------

        expected_params = set(
            detection.query_parameters
        )

        actual_params = set(
            generated.query_parameters
        )

        if expected_params != actual_params:
            errors.append(
                "Query parameter mismatch: "
                f"expected={sorted(expected_params)} "
                f"actual={sorted(actual_params)}"
            )

        # --------------------------------------------------
        # Query values
        # --------------------------------------------------

        if (
            detection.query_parameter_values
            != generated.query_parameter_values
        ):
            errors.append(
                "Query parameter values mismatch: "
                f"expected={detection.query_parameter_values!r} "
                f"actual={generated.query_parameter_values!r}"
            )

        # --------------------------------------------------
        # Headers
        # --------------------------------------------------

        if (
            detection.headers
            != generated.headers
        ):
            errors.append(
                "Headers mismatch: "
                f"expected={detection.headers!r} "
                f"actual={generated.headers!r}"
            )

        # --------------------------------------------------
        # Response statuses
        # --------------------------------------------------

        expected_status = set(
            detection.response_status
        )

        actual_status = set(
            generated.response_status
        )

        if expected_status != actual_status:
            errors.append(
                "Response status mismatch: "
                f"expected={sorted(expected_status)} "
                f"actual={sorted(actual_status)}"
            )

        # --------------------------------------------------
        # Matchers
        # --------------------------------------------------

        expected_matchers = {
            matcher.strip()
            for matcher
            in detection.response_matchers
        }

        actual_matchers = {
            matcher.strip()
            for matcher
            in generated.response_matchers
        }

        if expected_matchers != actual_matchers:
            errors.append(
                "Response matcher mismatch: "
                f"expected={sorted(expected_matchers)} "
                f"actual={sorted(actual_matchers)}"
            )

        # --------------------------------------------------
        # Safety
        # --------------------------------------------------

        if generated.destructive:
            errors.append(
                "Generated template is marked destructive."
            )

        # --------------------------------------------------
        # Reliability
        # --------------------------------------------------

        if not generated.reliable_signature:
            errors.append(
                "Generated template does not contain "
                "a reliable detection signature."
            )

        # --------------------------------------------------
        # Authentication
        # --------------------------------------------------

        if (
            detection.authentication_required
            != generated.authentication_required
        ):
            warnings.append(
                "Authentication requirement differs "
                "from source DetectionSpec."
            )

        # --------------------------------------------------
        # Final result
        # --------------------------------------------------

        return ValidationResult(
            valid=not errors,
            errors=errors,
            warnings=warnings,
        )