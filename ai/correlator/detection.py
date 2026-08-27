from __future__ import annotations

import re

from ai.schemas.detection import DetectionSpec


class DetectionSpecExtractor:
    """
    Extract a structured HTTP detection specification from
    CVE research evidence.

    This stage does not execute any request.

    It is intentionally conservative:
    generic mentions of "HTTP" are not enough to establish
    an HTTP detection surface.
    """

    HTTP_METHODS = (
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    )

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

    HTTP_PROTOCOLS = {
        "http",
        "https",
        "http/1.1",
        "http/2",
        "http/3",
    }

    def _find_method(
        self,
        text: str,
    ) -> str | None:
        """
        Detect an explicit HTTP request method such as:

            GET /path
            POST /upload
        """

        upper = text.upper()

        for method in self.HTTP_METHODS:
            if re.search(
                rf"\b{method}\s+/",
                upper,
            ):
                return method

        return None

    def _find_path(
        self,
        text: str,
    ) -> str | None:
        """
        Detect an explicit HTTP path associated with a method.
        """

        match = re.search(
            r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)"
            r"\s+(/[^\s]+)",
            text,
            flags=re.IGNORECASE,
        )

        if not match:
            return None

        return match.group(1)

    def _find_status_codes(
        self,
        text: str,
    ) -> list[int]:
        """
        Detect HTTP status codes only when their context
        clearly indicates an HTTP status.

        This avoids interpreting values such as CWE-284
        as HTTP status 284.
        """

        found = set()

        patterns = (
            # HTTP/1.1 200
            r"\bHTTP/\d(?:\.\d)?\s+([1-5]\d{2})\b",

            # status 200
            r"\bstatus\s+([1-5]\d{2})\b",

            # status code: 404
            r"\bstatus\s+code\s*[:=]?\s*([1-5]\d{2})\b",

            # returns 403 / return 200
            r"\breturns?\s+([1-5]\d{2})\b",
        )

        for pattern in patterns:
            for match in re.finditer(
                pattern,
                text,
                flags=re.IGNORECASE,
            ):
                try:
                    found.add(
                        int(match.group(1))
                    )
                except ValueError:
                    pass

        return sorted(found)

    def _protocols(
        self,
        text: str,
    ) -> list[str]:
        """
        Extract protocol mentions using context-aware signals.

        A plain occurrence of the word "http" is not enough.
        """

        lowered = text.lower()

        protocol_patterns = {
            "http": (
                "http request",
                "http response",
                "http endpoint",
                "http method",
                "http header",
                "http protocol",
                "http(s)",
            ),
            "https": (
                "https request",
                "https response",
                "https endpoint",
                "https protocol",
            ),
            "http/1.1": (
                "http/1.1",
            ),
            "http/2": (
                "http/2",
            ),
            "http/3": (
                "http/3",
            ),
            "t3": (
                "t3 protocol",
                "via t3",
                "over t3",
                "t3/iiop",
            ),
            "iiop": (
                "iiop protocol",
                "via iiop",
                "over iiop",
                "t3/iiop",
            ),
            "rmi": (
                "rmi protocol",
                "via rmi",
                "over rmi",
            ),
            "ldap": (
                "ldap protocol",
                "via ldap",
                "over ldap",
            ),
            "smtp": (
                "smtp protocol",
                "via smtp",
                "over smtp",
            ),
            "ftp": (
                "ftp protocol",
                "via ftp",
                "over ftp",
            ),
            "ssh": (
                "ssh protocol",
                "via ssh",
                "over ssh",
            ),
            "corba": (
                "corba protocol",
                "via corba",
                "over corba",
            ),
            "oracle net": (
                "oracle net",
                "oracle net protocol",
            ),
            "tcp": (
                "tcp protocol",
                "tcp listener",
                "tcp port",
            ),
            "udp": (
                "udp protocol",
                "udp listener",
                "udp port",
            ),
        }

        found = []

        for protocol, signals in protocol_patterns.items():
            if any(
                signal in lowered
                for signal in signals
            ):
                found.append(protocol)

        return sorted(
            set(found)
        )

    def _has_http_detection_language(
        self,
        text: str,
    ) -> bool:
        """
        Detect explicit HTTP detection language.

        Negative statements such as:
            "no HTTP detection"
            "not HTTP based"

        are intentionally excluded.
        """

        lowered = text.lower()

        negative_patterns = (
            "no reliable http",
            "no http detection",
            "not http",
            "not an http",
            "non-http",
            "binary t3/iiop",
            "binary protocol",
            "rather than http",
        )

        if any(
            pattern in lowered
            for pattern in negative_patterns
        ):
            return False

        positive_patterns = (
            "http request",
            "http response",
            "http endpoint",
            "http method",
            "http parameter",
            "http header",
            "response matcher",
            "response body",
            "response header",
        )

        return any(
            pattern in lowered
            for pattern in positive_patterns
        )

    def _authentication_requirement(
        self,
        text: str,
    ) -> bool | None:
        lowered = text.lower()

        # Strong explicit unauthenticated signals first.
        unauthenticated_patterns = (
            "unauthenticated",
            "without authentication",
            "without auth",
            "no authentication required",
            "no auth required",
            "pre-authentication",
            "preauthentication",
        )

        if any(
            phrase in lowered
            for phrase in unauthenticated_patterns
        ):
            return False

        authenticated_patterns = (
            "requires authentication",
            "requires an authenticated",
            "authentication required",
            "authenticated attacker",
            "authenticated user",
            "valid credentials",
            "low-privileged credentials",
            "low privileged credentials",
        )

        if any(
            phrase in lowered
            for phrase in authenticated_patterns
        ):
            return True

        return None

    def _is_destructive(
        self,
        text: str,
    ) -> bool:
        lowered = text.lower()

        destructive_terms = (
            "destructive",
            "delete file",
            "delete files",
            "write file",
            "modify file",
            "upload file",
            "execute command",
            "execute arbitrary command",
            "execute code",
            "command execution",
            "drop database",
        )

        return any(
            term in lowered
            for term in destructive_terms
        )

    def extract(
        self,
        cve,
        research,
    ) -> DetectionSpec:
        """
        Build a DetectionSpec from CVE + ResearchResult.
        """

        parts = [
            cve.content or "",
            research.summary or "",
            research.root_cause or "",
            research.nuclei_reason or "",
            *research.detection_ideas,
            *research.evidence,
        ]

        text = "\n".join(
            parts
        )

        # --------------------------------------------------
        # Basic extraction
        # --------------------------------------------------

        protocols = self._protocols(
            text
        )

        http_method = self._find_method(
            text
        )

        path = self._find_path(
            text
        )

        statuses = self._find_status_codes(
            text
        )

        authentication_required = (
            self._authentication_requirement(
                text
            )
        )

        destructive = self._is_destructive(
            text
        )

        # --------------------------------------------------
        # HTTP protocol cleanup
        # --------------------------------------------------

        primary_non_http = any(
            protocol in protocols
            for protocol in self.NON_HTTP_PROTOCOLS
        )

        if (
            primary_non_http
            and http_method is None
            and path is None
        ):
            protocols = [
                protocol
                for protocol in protocols
                if protocol
                not in self.HTTP_PROTOCOLS
            ]

        # If an explicit HTTP method/path exists,
        # HTTP is a legitimate protocol signal.
        if (
            http_method is not None
            or path is not None
        ):
            protocols = sorted(
                set(
                    protocols
                    + ["http"]
                )
            )

        # --------------------------------------------------
        # Reliable HTTP signature
        # --------------------------------------------------

        explicit_http_language = (
            self._has_http_detection_language(
                text
            )
        )

        reliable_signature = bool(
            http_method
            and path
            and explicit_http_language
        )

        # --------------------------------------------------
        # Detection requirements
        # --------------------------------------------------

        missing_requirements = []

        if http_method is None:
            missing_requirements.append(
                "HTTP method"
            )

        if path is None:
            missing_requirements.append(
                "HTTP path"
            )

        if not (
            statuses
            or "response matcher" in text.lower()
            or "response body" in text.lower()
            or "response header" in text.lower()
        ):
            missing_requirements.append(
                "Response detection condition"
            )

        if not reliable_signature:
            missing_requirements.append(
                "Deterministic HTTP detection signature"
            )

        # Deduplicate while preserving order.
        missing_requirements = list(
            dict.fromkeys(
                missing_requirements
            )
        )

        # --------------------------------------------------
        # Evidence
        # --------------------------------------------------

        evidence = []

        if http_method:
            evidence.append(
                f"HTTP method detected: "
                f"{http_method}"
            )

        if path:
            evidence.append(
                f"HTTP path detected: "
                f"{path}"
            )

        if statuses:
            evidence.append(
                f"HTTP status codes detected: "
                f"{statuses}"
            )

        if protocols:
            evidence.append(
                "Protocols detected: "
                + ", ".join(protocols)
            )

        if reliable_signature:
            evidence.append(
                "A deterministic HTTP request signature "
                "was detected."
            )
        else:
            evidence.append(
                "No deterministic HTTP request signature "
                "was established."
            )

        # --------------------------------------------------
        # Confidence
        # --------------------------------------------------

        confidence = 0.20

        if http_method:
            confidence += 0.20

        if path:
            confidence += 0.30

        if statuses:
            confidence += 0.10

        if explicit_http_language:
            confidence += 0.10

        if reliable_signature:
            confidence += 0.20

        confidence = min(
            confidence,
            1.0,
        )

        return DetectionSpec(
            cve_id=cve.title,
            protocol=protocols,
            http_method=http_method,
            path=path,
            query_parameters=[],
            headers={},
            body_pattern=None,
            response_status=statuses,
            response_matchers=[],
            version_required=True,
            affected_versions=[
                version
                for version
                in research.affected_versions
                if isinstance(
                    version,
                    str,
                )
            ],
            authentication_required=(
                authentication_required
            ),
            destructive=destructive,
            reliable_signature=reliable_signature,
            confidence=confidence,
            evidence=evidence,
            missing_requirements=missing_requirements,
        )