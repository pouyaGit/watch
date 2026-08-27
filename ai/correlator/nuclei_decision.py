from __future__ import annotations

from ai.schemas.detection import DetectionSpec
from ai.schemas.nuclei import NucleiDecision


class NucleiDecisionEngine:

    NON_HTTP_PROTOCOLS = {
        "t3",
        "iiop",
        "rmi",
        "ldap",
        "smtp",
        "ftp",
        "ssh",
        "corba",
        "oracle net",
        "tcp",
        "udp",
    }

    def decide(
        self,
        cve,
        research,
        detection: DetectionSpec,
        exploit=None,
    ) -> NucleiDecision:

        exploit_evidence = "unknown"

        if exploit is not None:
            if exploit.public_exploit is True:
                exploit_evidence = "confirmed"
            elif exploit.public_exploit is None:
                exploit_evidence = "unknown"
            else:
                exploit_evidence = "not_confirmed"

        # --------------------------------------------------
        # Strongest rule:
        # no reliable HTTP signature -> no Nuclei
        # --------------------------------------------------

        if not detection.reliable_signature:

            reason = (
                "No reliable HTTP detection signature "
                "was established from the available evidence."
            )

            if detection.protocol:
                non_http = [
                    protocol
                    for protocol in detection.protocol
                    if protocol in self.NON_HTTP_PROTOCOLS
                ]

                if non_http:
                    reason = (
                        "The vulnerability uses "
                        + ", ".join(non_http)
                        + " and no reliable HTTP request/response "
                          "detection signature was established."
                    )

            return NucleiDecision(
                cve_id=cve.title,
                decision="NOT_APPLICABLE",
                confidence=max(
                    0.95,
                    1.0 - detection.confidence,
                ),
                reason=reason,
                protocol=detection.protocol,
                http_detectable=False,
                version_required=detection.version_required,
                exploit_evidence=exploit_evidence,
                detection_requirements=(
                    detection.missing_requirements
                    or [
                        "Reliable HTTP detection signature"
                    ]
                ),
            )

        # --------------------------------------------------
        # Safety rule:
        # destructive authenticated detection should not
        # automatically become a Nuclei candidate.
        # --------------------------------------------------

        if (
            detection.destructive
            and detection.authentication_required is True
        ):
            return NucleiDecision(
                cve_id=cve.title,
                decision="NOT_APPLICABLE",
                confidence=0.93,
                reason=(
                    "Detection appears to require authenticated "
                    "and potentially destructive interaction. "
                    "A safe Nuclei template cannot be established "
                    "from the supplied evidence."
                ),
                protocol=detection.protocol,
                http_detectable=True,
                version_required=detection.version_required,
                exploit_evidence=exploit_evidence,
                detection_requirements=(
                    detection.missing_requirements
                    + [
                        "Safe non-destructive detection method",
                        "Explicitly authorized authentication flow",
                    ]
                ),
            )

        # --------------------------------------------------
        # Good candidate:
        # deterministic HTTP method/path/signature exists.
        # --------------------------------------------------

        if (
            detection.reliable_signature
            and detection.http_method
            and detection.path
            and detection.response_matchers
        ):
            return NucleiDecision(
                cve_id=cve.title,
                decision="GOOD_CANDIDATE",
                confidence=min(
                    0.98,
                    max(
                        detection.confidence,
                        0.85,
                    ),
                ),
                reason=(
                    "A deterministic HTTP request and response "
                    "signature is available for safe automated "
                    "detection."
                ),
                protocol=detection.protocol,
                http_detectable=True,
                version_required=detection.version_required,
                exploit_evidence=exploit_evidence,
                detection_requirements=(
                    detection.missing_requirements
                ),
            )

        # --------------------------------------------------
        # Possible:
        # HTTP surface exists, but signature still incomplete.
        # --------------------------------------------------

        return NucleiDecision(
            cve_id=cve.title,
            decision="POSSIBLE",
            confidence=min(
                0.80,
                max(
                    detection.confidence,
                    0.50,
                ),
            ),
            reason=(
                "An HTTP-based surface was identified, "
                "but the detection specification is not "
                "complete enough for a reliable Nuclei template."
            ),
            protocol=detection.protocol,
            http_detectable=True,
            version_required=detection.version_required,
            exploit_evidence=exploit_evidence,
            detection_requirements=(
                detection.missing_requirements
                + [
                    "Deterministic response matcher"
                ]
            ),
        )     