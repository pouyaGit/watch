"""EPIC16 §4–§12 — deterministic per-class classifiers.

Pure functions over *observed material*.  Nothing here issues a request, and
nothing here can confirm a vulnerability: each classifier returns the exact
state the EPIC11 taxonomy can classify and the EPIC12 chain can evaluate, plus
the honest reason when the state is negative or unproven.

The classification rules are deliberately narrow.  §8 is the model for all of
them: "a redirect parameter exists" is not an open redirect, "HTTP 302" is not
an open redirect, and "ACAO: *" is not a CORS vulnerability.  Only the
appropriate deterministic state may satisfy confirmation.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

RULE_VERSION = "epic16-classify-1"

#: A deterministic, non-real origin/destination (§5/§7).  Nothing under
#: ``.invalid`` can resolve (RFC 2606), so it is safe to name as a controlled
#: marker and it can never be attacker infrastructure.
CONTROLLED_SUFFIX = ".hermes-verification.invalid"
CONTROLLED_ORIGIN_TOKEN = "controlled-hermes-origin"

#: The opaque origin representation browsers send from sandboxed contexts.
#: It resolves to nothing, is deterministic, and is a state §4 requires the
#: verifier to distinguish — but it is never attacker infrastructure.
NULL_ORIGIN = "null"

#: The representation a controlled destination marker uses when the transport
#: cannot safely test a real external host (§7).
CONTROLLED_DESTINATION_TOKEN = "hermes-controlled-destination"

# ---------------------------------------------------------------- CORS (§4–§6)

ACAO_ABSENT = "ACAO_ABSENT"
ACAO_WILDCARD = "ACAO_WILDCARD"
ACAO_EXACT_ORIGIN = "ACAO_EXACT_ORIGIN"
ACAO_REFLECTED_ARBITRARY = "ACAO_REFLECTED_ARBITRARY"
ACAO_NULL = "ACAO_NULL"
ACAO_ORIGIN_LIST = "ACAO_ORIGIN_LIST"
ACAO_MALFORMED = "ACAO_MALFORMED"

CORS_ORIGIN_CLASSES: tuple[str, ...] = (
    ACAO_ABSENT, ACAO_WILDCARD, ACAO_EXACT_ORIGIN, ACAO_REFLECTED_ARBITRARY,
    ACAO_NULL, ACAO_ORIGIN_LIST, ACAO_MALFORMED)

#: negative/terminal reasons (§6)
REASON_NO_ORIGIN_SUPPLIED = "no_controlled_origin_supplied"
REASON_INVALID_ORIGIN = "supplied_origin_not_controlled"
REASON_ACAO_ABSENT = "no_access_control_allow_origin"
REASON_ORIGIN_NOT_ACCEPTED = "origin_not_accepted"
REASON_WILDCARD_NOT_CREDENTIABLE = "wildcard_cannot_carry_credentials"
REASON_CREDENTIALS_NOT_ALLOWED = "credentials_not_allowed"
REASON_CREDENTIALS_NOT_RELEVANT = "credentials_not_relevant"
REASON_NO_SENSITIVE_RESPONSE = "no_sensitive_response_observed"
REASON_SENSITIVE_NOT_DECLARED = "sensitive_response_not_declared"


def controlled_origin(token: str = CONTROLLED_ORIGIN_TOKEN) -> str:
    """The deterministic controlled Origin this runtime may claim (§5)."""
    slug = re.sub(r"[^a-z0-9-]+", "-", str(token).strip().lower()).strip("-")
    return f"https://{slug or CONTROLLED_ORIGIN_TOKEN}{CONTROLLED_SUFFIX}"


def is_controlled_origin(origin: str) -> bool:
    """True only for a deterministic non-real arrival origin.

    Allowed: our own ``.invalid`` controlled origin, and the opaque ``null``
    origin (which resolves to nothing and is not attacker infrastructure).
    An arbitrary real origin is refused.
    """
    if str(origin).strip().lower() == NULL_ORIGIN:
        return True
    try:
        parts = urlsplit(str(origin))
    except ValueError:
        return False
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    return host.endswith(CONTROLLED_SUFFIX) and bool(host)


def _header(headers: Mapping[str, Any], name: str) -> str | None:
    lowered = str(name).lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == lowered:
            return None if value is None else str(value)
    return None


@dataclass(frozen=True)
class CorsAssessment:
    """The deterministic CORS state of ONE observed response (§4)."""

    supplied_origin: str = ""
    acao_class: str = ACAO_ABSENT
    acao: str | None = None
    acac: str | None = None
    origin_accepted: bool = False
    credentials_relevant: bool = False
    credentials_allowed: bool = False
    sensitive_response_declared: bool = False
    sensitive_accessible: bool = False
    terminal_reasons: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    stages_satisfied: tuple[str, ...] = ()
    refusal: str = ""
    rule_version: str = RULE_VERSION

    @property
    def confirmed_eligible(self) -> bool:
        """Never True here: confirmation belongs to the EPIC11 gate."""
        return False

    @property
    def exploitable_state(self) -> str:
        """The strongest honest CORS statement this assessment supports."""
        if self.refusal:
            return "NOT_TESTED"
        if self.acao_class == ACAO_ABSENT:
            return "NOT_CONFIRMED"
        if not self.origin_accepted:
            return "NOT_CONFIRMED"
        if self.credentials_relevant and not self.credentials_allowed:
            return "PENDING"
        if self.credentials_allowed and self.sensitive_accessible:
            return "PENDING"
        return "NOT_CONFIRMED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "supplied_origin": self.supplied_origin,
            "acao_class": self.acao_class,
            "acao": self.acao,
            "acac": self.acac,
            "origin_accepted": self.origin_accepted,
            "credentials_relevant": self.credentials_relevant,
            "credentials_allowed": self.credentials_allowed,
            "sensitive_response_declared": self.sensitive_response_declared,
            "sensitive_accessible": self.sensitive_accessible,
            "terminal_reasons": list(self.terminal_reasons),
            "signals": list(self.signals),
            "stages_satisfied": list(self.stages_satisfied),
            "refusal": self.refusal,
            "exploitable_state": self.exploitable_state,
            "rule_version": self.rule_version,
        }


def classify_cors(origin: str,
                  response_headers: Mapping[str, Any] | None = None,
                  *,
                  credentials_relevant: bool = False,
                  sensitive_response_declared: bool = False) -> CorsAssessment:
    """Classify a CORS response against a controlled Origin (§4–§6).

    The seven §4 distinctions are decided here: ACAO absent, wildcard, exact
    origin, reflected arbitrary origin, null origin, credentialed behaviour and
    sensitive-response availability.
    """
    headers = dict(response_headers or {})
    reasons: list[str] = []
    signals: list[str] = []
    stages: list[str] = []

    if not origin:
        return CorsAssessment(
            refusal=REASON_NO_ORIGIN_SUPPLIED,
            terminal_reasons=(REASON_NO_ORIGIN_SUPPLIED,))
    if not is_controlled_origin(origin):
        # §5: only our own deterministic non-real controlled origin is allowed;
        # an arbitrary attacker origin is refused outright.
        return CorsAssessment(
            supplied_origin=origin,
            refusal=REASON_INVALID_ORIGIN,
            terminal_reasons=(REASON_INVALID_ORIGIN,))

    signals.append("cors_origin_supplied")
    stages.append("origin_supplied")

    raw_acao = _header(headers, "Access-Control-Allow-Origin")
    raw_acac = _header(headers, "Access-Control-Allow-Credentials")
    supplied = origin.strip()
    acao_class = ACAO_ABSENT
    origin_accepted = False

    if raw_acao is None or not raw_acao.strip():
        acao_class = ACAO_ABSENT
        reasons.append(REASON_ACAO_ABSENT)
        signals.append("cors_acao_absent")
    else:
        value = raw_acao.strip()
        if "," in value:
            acao_class = ACAO_ORIGIN_LIST
        elif value == "*":
            acao_class = ACAO_WILDCARD
        elif value.lower() == NULL_ORIGIN:
            acao_class = ACAO_NULL
            origin_accepted = supplied.lower() == NULL_ORIGIN
        elif value == supplied:
            acao_class = ACAO_REFLECTED_ARBITRARY
            origin_accepted = True
        elif value.startswith("http://") or value.startswith("https://"):
            acao_class = ACAO_EXACT_ORIGIN
            origin_accepted = False
        else:
            acao_class = ACAO_MALFORMED
        signals.append("cors_acao_observed")
        if acao_class in (ACAO_REFLECTED_ARBITRARY, ACAO_NULL):
            signals.append("cors_arbitrary_origin_accepted")
            stages.append("acao_observed")
        if not origin_accepted and acao_class != ACAO_ABSENT:
            reasons.append(REASON_ORIGIN_NOT_ACCEPTED)

    credentials_allowed = False
    if credentials_relevant:
        if acao_class == ACAO_WILDCARD:
            # A browser will not attach credentials to a wildcard ACAO.
            reasons.append(REASON_WILDCARD_NOT_CREDENTIABLE)
            credentials_allowed = False
        elif origin_accepted and str(raw_acac or "").strip().lower() == "true":
            credentials_allowed = True
            signals.append("cors_credentials_allowed")
            stages.append("credentials_evaluated")
        else:
            reasons.append(REASON_CREDENTIALS_NOT_ALLOWED)
    else:
        reasons.append(REASON_CREDENTIALS_NOT_RELEVANT)

    sensitive_accessible = False
    if not sensitive_response_declared:
        reasons.append(REASON_SENSITIVE_NOT_DECLARED)
    elif credentials_allowed or (origin_accepted and acao_class
                                 == ACAO_REFLECTED_ARBITRARY):
        sensitive_accessible = True
        signals.append("cors_sensitive_response_available")
        stages.append("sensitive_response_accessible")
    else:
        reasons.append(REASON_NO_SENSITIVE_RESPONSE)

    if not any(reason in (REASON_ACAO_ABSENT, REASON_ORIGIN_NOT_ACCEPTED,
                          REASON_WILDCARD_NOT_CREDENTIABLE,
                          REASON_CREDENTIALS_NOT_ALLOWED,
                          REASON_NO_SENSITIVE_RESPONSE)
               for reason in reasons):
        stages.append("exploitability_established")

    return CorsAssessment(
        supplied_origin=supplied, acao_class=acao_class, acao=raw_acao,
        acac=raw_acac, origin_accepted=origin_accepted,
        credentials_relevant=bool(credentials_relevant),
        credentials_allowed=credentials_allowed,
        sensitive_response_declared=bool(sensitive_response_declared),
        sensitive_accessible=sensitive_accessible,
        terminal_reasons=tuple(dict.fromkeys(reasons)),
        signals=tuple(dict.fromkeys(signals)),
        stages_satisfied=tuple(dict.fromkeys(stages)))


# ------------------------------------------------------- OPEN REDIRECT (§7–§8)

REDIRECT_NO_LOCATION = "NO_LOCATION"
REDIRECT_PARAMETER_IGNORED = "PARAMETER_IGNORED"
REDIRECT_RELATIVE_ONLY = "RELATIVE_ONLY"
REDIRECT_SAME_ORIGIN = "SAME_ORIGIN"
REDIRECT_DESTINATION_NORMALIZED = "DESTINATION_NORMALIZED"
REDIRECT_EXTERNAL_ACCEPTED = "EXTERNAL_ACCEPTED"
REDIRECT_EXTERNAL_OUT_OF_SCOPE = "EXTERNAL_OUT_OF_SCOPE"
REDIRECT_UNSAFE_SCHEME = "UNSAFE_SCHEME"

REDIRECT_CLASSES: tuple[str, ...] = (
    REDIRECT_NO_LOCATION, REDIRECT_PARAMETER_IGNORED, REDIRECT_RELATIVE_ONLY,
    REDIRECT_SAME_ORIGIN, REDIRECT_DESTINATION_NORMALIZED,
    REDIRECT_EXTERNAL_ACCEPTED, REDIRECT_EXTERNAL_OUT_OF_SCOPE,
    REDIRECT_UNSAFE_SCHEME)

#: RFC1918 / loopback / link-local / metadata and unsafe schemes are NEVER a
#: controlled destination (§7/§10).
_UNSAFE_SCHEMES = ("file", "gopher", "ftp", "ftps", "dict", "ldap", "jar",
                   "tftp", "smb", "data", "javascript")
_METADATA_HOSTNAMES = ("metadata", "metadata.google.internal",
                       "metadata.goog", "instance-data",
                       "metadata.azure.com")
_METADATA_ADDRESSES = ("169.254.169.254", "169.254.170.2", "100.100.100.200",
                       "fd00:ec2::254")


@dataclass(frozen=True)
class DestinationPolicy:
    """The §10 destination decision — a policy result, never a probe."""

    destination: str = ""
    decision: str = ""
    reasons: tuple[str, ...] = ()
    resolved_kind: str = ""
    internal_target: bool = False
    unsafe_scheme: bool = False
    metadata_target: bool = False
    is_controlled: bool = False
    rule_version: str = RULE_VERSION

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOWED_CONTROLLED_DESTINATION"

    def to_dict(self) -> dict[str, Any]:
        return {
            "destination": self.destination,
            "decision": self.decision,
            "reasons": list(self.reasons),
            "resolved_kind": self.resolved_kind,
            "internal_target": self.internal_target,
            "unsafe_scheme": self.unsafe_scheme,
            "metadata_target": self.metadata_target,
            "is_controlled": self.is_controlled,
            "allowed": self.allowed,
            "rule_version": self.rule_version,
        }


def _address_kind(host: str) -> str:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    return "public"


def evaluate_destination(destination: str, *,
                         scope_hosts: Sequence[str] = (),
                         allow_controlled: bool = True) -> DestinationPolicy:
    """§10 destination policy.  Refuses internal/metadata/unsafe targets."""
    raw = str(destination or "").strip()
    reasons: list[str] = []
    if not raw:
        return DestinationPolicy(destination=raw, decision="REJECTED_EMPTY",
                                 reasons=("no_destination_supplied",))
    try:
        parts = urlsplit(raw)
    except ValueError:
        return DestinationPolicy(destination=raw, decision="REJECTED_MALFORMED",
                                 reasons=("destination_not_parseable",))

    scheme = (parts.scheme or "").lower()
    unsafe_scheme = scheme in _UNSAFE_SCHEMES
    if unsafe_scheme:
        reasons.append("unsafe_scheme")
    if not scheme:
        reasons.append("no_scheme")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        reasons.append("no_host")
    if not scheme or not host:
        # a destination must be absolute and named: a bare "host/path" string
        # is not a destination this runtime will ever consider
        return DestinationPolicy(
            destination=raw, decision="REJECTED_MALFORMED",
            reasons=tuple(reasons) + ("destination_not_absolute",),
            unsafe_scheme=unsafe_scheme,
            metadata_target=host in _METADATA_HOSTNAMES)

    kind = _address_kind(host)
    internal = bool(kind) and kind != "public"
    metadata = (host in _METADATA_HOSTNAMES
                or host in _METADATA_ADDRESSES
                or (kind and host in _METADATA_ADDRESSES))
    if internal:
        reasons.append(f"internal_{kind}")
    if metadata:
        reasons.append("metadata_target")
    if host in ("localhost", "localhost.localdomain") or host.endswith(
            ".localhost") or host.endswith(".internal") or host.endswith(
            ".local"):
        internal = True
        reasons.append("internal_name")
    if kind and host == "0.0.0.0":
        reasons.append("unspecified_address")

    port = parts.port
    if port is not None and port not in (80, 443) and not unsafe_scheme:
        reasons.append("non_standard_port")

    controlled = bool(host.endswith(CONTROLLED_SUFFIX)
                      or host.endswith(".invalid"))
    scope = {str(h).lower() for h in scope_hosts or ()}
    out_of_scope = bool(scope) and host not in scope

    if unsafe_scheme:
        return DestinationPolicy(
            destination=raw, decision="REJECTED_SCHEME", reasons=tuple(reasons),
            resolved_kind=kind or "named", unsafe_scheme=True,
            metadata_target=metadata, is_controlled=controlled)
    if metadata:
        return DestinationPolicy(
            destination=raw, decision="REJECTED_METADATA",
            reasons=tuple(reasons), resolved_kind=kind or "named",
            internal_target=True, metadata_target=True, is_controlled=controlled)
    if internal:
        return DestinationPolicy(
            destination=raw, decision="REJECTED_INTERNAL",
            reasons=tuple(reasons), resolved_kind=kind or "named",
            internal_target=True, is_controlled=controlled)
    if "non_standard_port" in reasons:
        return DestinationPolicy(
            destination=raw, decision="REJECTED_PORT", reasons=tuple(reasons),
            resolved_kind=kind or "named", is_controlled=controlled)
    if out_of_scope:
        return DestinationPolicy(
            destination=raw, decision="REJECTED_OUT_OF_SCOPE",
            reasons=tuple(reasons) + ("destination_out_of_scope",),
            resolved_kind=kind or "named", is_controlled=controlled)
    if allow_controlled and controlled:
        return DestinationPolicy(
            destination=raw, decision="ALLOWED_CONTROLLED_DESTINATION",
            reasons=tuple(reasons), resolved_kind=kind or "named",
            is_controlled=True)
    return DestinationPolicy(
        destination=raw, decision="ALLOWED_CONTROLLED_DESTINATION",
        reasons=tuple(reasons), resolved_kind=kind or "named",
        is_controlled=controlled)


@dataclass(frozen=True)
class RedirectAssessment:
    classification: str = REDIRECT_NO_LOCATION
    supplied_destination: str = ""
    location: str | None = None
    location_host: str = ""
    request_host: str = ""
    destination_controlled: bool = False
    external: bool = False
    terminal_reasons: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    stages_satisfied: tuple[str, ...] = ()
    policy: DestinationPolicy | None = None
    refusal: str = ""
    rule_version: str = RULE_VERSION

    @property
    def exploitable_state(self) -> str:
        if self.refusal:
            return "NOT_TESTED"
        if self.classification == REDIRECT_EXTERNAL_ACCEPTED:
            return "PENDING"
        return "NOT_CONFIRMED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "supplied_destination": self.supplied_destination,
            "location": self.location,
            "location_host": self.location_host,
            "request_host": self.request_host,
            "destination_controlled": self.destination_controlled,
            "external": self.external,
            "terminal_reasons": list(self.terminal_reasons),
            "signals": list(self.signals),
            "stages_satisfied": list(self.stages_satisfied),
            "policy": self.policy.to_dict() if self.policy else None,
            "refusal": self.refusal,
            "exploitable_state": self.exploitable_state,
            "rule_version": self.rule_version,
        }


def controlled_destination(token: str = CONTROLLED_DESTINATION_TOKEN) -> str:
    """The §7 controlled destination representation (non-real, non-sensitive)."""
    slug = re.sub(r"[^a-z0-9-]+", "-", str(token).strip().lower()).strip("-")
    return f"https://{slug or CONTROLLED_DESTINATION_TOKEN}{CONTROLLED_SUFFIX}/"


def classify_redirect(supplied_destination: str, location: str | None, *,
                      request_url: str = "",
                      scope_hosts: Sequence[str] = ()) -> RedirectAssessment:
    """Classify a redirect outcome against a controlled destination (§8)."""
    request_host = (urlsplit(request_url).hostname or "").lower() \
        if request_url else ""
    raw_location = None if location is None else str(location).strip()

    if not supplied_destination:
        return RedirectAssessment(
            refusal="no_controlled_destination_supplied",
            request_host=request_host,
            terminal_reasons=("no_controlled_destination_supplied",))

    policy = evaluate_destination(supplied_destination, scope_hosts=scope_hosts)
    if not policy.allowed:
        # §7: never test an unsafe destination, even as a marker.
        return RedirectAssessment(
            supplied_destination=supplied_destination,
            request_host=request_host, policy=policy,
            refusal=f"unsafe_supplied_destination:{policy.decision}",
            terminal_reasons=tuple(policy.reasons) or (policy.decision,))

    if raw_location is None or raw_location == "":
        return RedirectAssessment(
            supplied_destination=supplied_destination, location=None,
            request_host=request_host, policy=policy,
            terminal_reasons=("no_location_observed",),
            signals=("redirect_response_observed",))

    if raw_location.startswith("//"):
        target_host = (urlsplit("https:" + raw_location).hostname or "").lower()
        scheme = ""
    else:
        parts = urlsplit(raw_location)
        target_host = (parts.hostname or "").lower()
        scheme = (parts.scheme or "").lower()

    token = urlsplit(supplied_destination).hostname or ""
    token_slug = token.split(".")[0]
    controlled = bool(token_slug) and token_slug in raw_location.lower()

    request_path = (urlsplit(request_url).path or "") if request_url else ""
    location_path = (urlsplit(
        "https:" + raw_location if raw_location.startswith("//")
        else raw_location).path or "")

    if controlled:
        classification = REDIRECT_EXTERNAL_ACCEPTED
        reasons = ()
    elif scheme in _UNSAFE_SCHEMES:
        classification = REDIRECT_UNSAFE_SCHEME
        reasons = ("unsafe_redirect_scheme",)
    elif not scheme and not raw_location.startswith("//"):
        # a relative target: no attacker-controlled destination is reachable
        classification = (REDIRECT_RELATIVE_ONLY if raw_location.startswith("/")
                          else REDIRECT_DESTINATION_NORMALIZED)
        reasons = ("relative_or_normalized_target",)
    elif target_host and request_host and target_host == request_host:
        # same host: the parameter was ignored, dropped, or normalized away
        if raw_location.startswith("//") and location_path != request_path:
            classification = REDIRECT_SAME_ORIGIN
            reasons = ("same_origin_redirect",)
        elif request_url and raw_location.rstrip("/") == request_url.rstrip("/"):
            classification = REDIRECT_PARAMETER_IGNORED
            reasons = ("parameter_ignored",)
        elif request_path and location_path == request_path:
            classification = REDIRECT_PARAMETER_IGNORED
            reasons = ("parameter_ignored",)
        else:
            classification = REDIRECT_DESTINATION_NORMALIZED
            reasons = ("destination_normalized_to_same_origin",)
    else:
        classification = REDIRECT_EXTERNAL_OUT_OF_SCOPE
        reasons = ("redirect_target_not_controlled",)

    signals = ["redirect_response_observed"]
    stages = ["redirect_response_observed"]
    if classification == REDIRECT_EXTERNAL_ACCEPTED:
        signals.append("redirect_external_destination_accepted")
        stages.append("location_target_controlled")
        stages.append("external_destination_accepted")
    elif classification in (REDIRECT_SAME_ORIGIN, REDIRECT_DESTINATION_NORMALIZED,
                            REDIRECT_PARAMETER_IGNORED):
        signals.append("redirect_relative_only")
    elif classification == REDIRECT_EXTERNAL_OUT_OF_SCOPE:
        signals.append("redirect_external_destination_rejected")
    elif classification == REDIRECT_UNSAFE_SCHEME:
        signals.append("redirect_unsafe_scheme_rejected")

    return RedirectAssessment(
        classification=classification,
        supplied_destination=supplied_destination, location=raw_location,
        location_host=target_host, request_host=request_host,
        destination_controlled=controlled,
        external=classification in (REDIRECT_EXTERNAL_ACCEPTED,
                                    REDIRECT_EXTERNAL_OUT_OF_SCOPE,
                                    REDIRECT_UNSAFE_SCHEME),
        terminal_reasons=tuple(reasons), signals=tuple(signals),
        stages_satisfied=tuple(dict.fromkeys(stages)), policy=policy)


# ------------------------------------------------------------------ SSRF (§9–§10)

@dataclass(frozen=True)
class SsrfAssessment:
    """SSRF state: policy evaluation only — no probe is ever performed."""

    url_parameter_present: bool = False
    destination: str = ""
    server_request_observed: bool = False
    destination_interaction: bool = False
    security_relevant_response: bool = False
    policy: DestinationPolicy | None = None
    active_verification: str = "CAPABILITY_UNAVAILABLE"
    signals: tuple[str, ...] = ()
    terminal_reasons: tuple[str, ...] = ()
    rule_version: str = RULE_VERSION

    @property
    def exploitable_state(self) -> str:
        if self.active_verification == "CAPABILITY_UNAVAILABLE":
            return "CAPABILITY_UNAVAILABLE"
        if not self.server_request_observed:
            return "NOT_CONFIRMED"
        return "PENDING"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url_parameter_present": self.url_parameter_present,
            "destination": self.destination,
            "server_request_observed": self.server_request_observed,
            "destination_interaction": self.destination_interaction,
            "security_relevant_response": self.security_relevant_response,
            "policy": self.policy.to_dict() if self.policy else None,
            "active_verification": self.active_verification,
            "signals": list(self.signals),
            "terminal_reasons": list(self.terminal_reasons),
            "exploitable_state": self.exploitable_state,
            "rule_version": self.rule_version,
        }


def classify_ssrf(destination: str = "", *,
                  url_parameter_present: bool = False,
                  server_request_observed: bool = False,
                  destination_interaction: bool = False,
                  security_relevant_response: bool = False,
                  callback_capability_available: bool = False,
                  scope_hosts: Sequence[str] = ()) -> SsrfAssessment:
    """§9: establish server-side request behaviour, or say it is unavailable.

    Without a controlled callback capability there is no legal way to observe
    a server-side request, so active verification stays CAPABILITY_UNAVAILABLE
    and no SSRF claim is made — even if a callback-shaped observation claims
    otherwise.
    """
    policy = (evaluate_destination(destination, scope_hosts=scope_hosts)
              if destination else None)
    signals: list[str] = []
    reasons: list[str] = []
    if url_parameter_present:
        signals.append("ssrf_url_parameter")
    if policy is not None:
        signals.append("ssrf_destination_policy_evaluated")
        reasons.extend(policy.reasons)
        if not policy.allowed:
            reasons.append(f"destination_policy_rejected:{policy.decision}")

    if not callback_capability_available:
        return SsrfAssessment(
            url_parameter_present=bool(url_parameter_present),
            destination=destination, policy=policy,
            active_verification="CAPABILITY_UNAVAILABLE",
            signals=tuple(dict.fromkeys(signals)),
            terminal_reasons=tuple(dict.fromkeys(
                reasons + ["no_controlled_callback_capability"])))

    if not server_request_observed:
        return SsrfAssessment(
            url_parameter_present=bool(url_parameter_present),
            destination=destination, policy=policy,
            active_verification="AVAILABLE",
            signals=tuple(dict.fromkeys(signals)),
            terminal_reasons=tuple(dict.fromkeys(
                reasons + ["no_server_request_observed"])))

    return SsrfAssessment(
        url_parameter_present=bool(url_parameter_present),
        destination=destination, policy=policy,
        server_request_observed=True,
        destination_interaction=bool(destination_interaction),
        security_relevant_response=bool(security_relevant_response),
        active_verification="AVAILABLE",
        signals=tuple(dict.fromkeys(signals + ["ssrf_server_side_request_observed"])),
        terminal_reasons=tuple(dict.fromkeys(reasons)))


# ------------------------------------------------------------ IDOR/BOLA (§11)

@dataclass(frozen=True)
class IdorCapability:
    """The §11 identity/object capability answer — honest, never faked."""

    object_reference_present: bool = False
    authorized_identities: int = 0
    identity_switching: bool = False
    ownership_semantics: bool = False
    capability: str = "CAPABILITY_UNAVAILABLE"
    reason: str = ""
    signals: tuple[str, ...] = ()
    action: str = ""
    rule_version: str = RULE_VERSION

    @property
    def second_context_available(self) -> bool:
        return (self.authorized_identities >= 2 and self.identity_switching
                and self.ownership_semantics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_reference_present": self.object_reference_present,
            "authorized_identities": int(self.authorized_identities),
            "identity_switching": bool(self.identity_switching),
            "ownership_semantics": bool(self.ownership_semantics),
            "capability": self.capability,
            "reason": self.reason,
            "signals": list(self.signals),
            "action": self.action,
            "second_context_available": self.second_context_available,
            "rule_version": self.rule_version,
        }


def classify_idor(*, object_reference_present: bool = False,
                  authorized_identities: int = 0,
                  identity_switching: bool = False,
                  ownership_semantics: bool = False) -> IdorCapability:
    """IDOR verification without a second identity is fake — refuse (§11)."""
    signals = ("idor_object_reference_pattern",) if object_reference_present else ()
    missing: list[str] = []
    if int(authorized_identities) < 2:
        missing.append("second_authorized_identity")
    if not identity_switching:
        missing.append("controlled_identity_switching")
    if not ownership_semantics:
        missing.append("object_ownership_semantics")
    if missing:
        return IdorCapability(
            object_reference_present=bool(object_reference_present),
            authorized_identities=int(authorized_identities),
            identity_switching=bool(identity_switching),
            ownership_semantics=bool(ownership_semantics),
            capability="CAPABILITY_UNAVAILABLE",
            reason="missing_capability:" + ",".join(missing),
            signals=signals, action="CHECK_OBJECT_ACCESS")
    return IdorCapability(
        object_reference_present=bool(object_reference_present),
        authorized_identities=int(authorized_identities),
        identity_switching=True, ownership_semantics=True,
        capability="AVAILABLE", reason="", signals=signals,
        action="CHECK_OBJECT_ACCESS")


# ------------------------------------------------------- CVE research (§12)

CVE_PRODUCT_UNKNOWN = "PRODUCT_UNKNOWN"
CVE_VERSION_UNKNOWN = "VERSION_UNKNOWN"
CVE_VERSION_NOT_AFFECTED = "VERSION_NOT_AFFECTED"
CVE_APPLICABILITY_CONFIRMED = "APPLICABILITY_CONFIRMED"
CVE_APPLICABILITY_UNRESOLVED = "APPLICABILITY_UNRESOLVED"
CVE_VERSION_AMBIGUOUS = "VERSION_AMBIGUOUS"
CVE_WRONG_PRODUCT = "WRONG_PRODUCT"

CVE_STATES: tuple[str, ...] = (
    CVE_PRODUCT_UNKNOWN, CVE_VERSION_UNKNOWN, CVE_VERSION_NOT_AFFECTED,
    CVE_APPLICABILITY_CONFIRMED, CVE_APPLICABILITY_UNRESOLVED,
    CVE_VERSION_AMBIGUOUS, CVE_WRONG_PRODUCT)


def _version_tuple(value: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", str(value or ""))
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])


@dataclass(frozen=True)
class CveApplicability:
    state: str = CVE_APPLICABILITY_UNRESOLVED
    product_identified: bool = False
    version_identified: bool = False
    observed_product: str = ""
    observed_version: str = ""
    advisory_product: str = ""
    affected_range: tuple[str, str] = ("", "")
    signals: tuple[str, ...] = ()
    terminal_reasons: tuple[str, ...] = ()
    confirmatory: bool = False
    rule_version: str = RULE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "product_identified": self.product_identified,
            "version_identified": self.version_identified,
            "observed_product": self.observed_product,
            "observed_version": self.observed_version,
            "advisory_product": self.advisory_product,
            "affected_range": list(self.affected_range),
            "signals": list(self.signals),
            "terminal_reasons": list(self.terminal_reasons),
            "confirmatory": self.confirmatory,
            "rule_version": self.rule_version,
        }


def classify_cve_applicability(*, observable_product: str = "",
                               observable_version: str = "",
                               advisory_product: str = "",
                               affected_min: str = "",
                               affected_max: str = "") -> CveApplicability:
    """§12: applicability only.  A CVE is never a confirmed vulnerability."""
    observed_p = str(observable_product or "").strip().lower()
    observed_v = str(observable_version or "").strip()
    advisory_p = str(advisory_product or "").strip().lower()

    if not observed_p:
        return CveApplicability(state=CVE_PRODUCT_UNKNOWN,
                                signals=("cve_product_identified",),
                                terminal_reasons=("product_unidentified",))
    if advisory_p and observed_p != advisory_p:
        return CveApplicability(
            state=CVE_WRONG_PRODUCT, product_identified=True,
            observed_product=observed_p, advisory_product=advisory_p,
            signals=("cve_product_identified",),
            terminal_reasons=("advisory_is_for_another_product",))
    if not observed_v:
        return CveApplicability(
            state=CVE_VERSION_UNKNOWN, product_identified=True,
            observed_product=observed_p, advisory_product=advisory_p,
            signals=("cve_product_identified",),
            terminal_reasons=("version_unidentified",))

    signals = ["cve_product_identified", "cve_version_identified"]
    observed_t = _version_tuple(observed_v)
    if observed_t is None:
        return CveApplicability(
            state=CVE_VERSION_AMBIGUOUS, product_identified=True,
            version_identified=True, observed_product=observed_p,
            observed_version=observed_v, advisory_product=advisory_p,
            signals=tuple(signals),
            terminal_reasons=("version_not_comparable",))

    low = _version_tuple(affected_min)
    high = _version_tuple(affected_max)
    if low is None and high is None:
        return CveApplicability(
            state=CVE_APPLICABILITY_UNRESOLVED, product_identified=True,
            version_identified=True, observed_product=observed_p,
            observed_version=observed_v, advisory_product=advisory_p,
            signals=tuple(signals),
            terminal_reasons=("no_affected_range_declared",))

    if low is not None and observed_t < low:
        return CveApplicability(
            state=CVE_VERSION_NOT_AFFECTED, product_identified=True,
            version_identified=True, observed_product=observed_p,
            observed_version=observed_v, advisory_product=advisory_p,
            affected_range=(affected_min, affected_max),
            signals=tuple(signals),
            terminal_reasons=("version_below_affected_range",))
    if high is not None and observed_t > high:
        return CveApplicability(
            state=CVE_VERSION_NOT_AFFECTED, product_identified=True,
            version_identified=True, observed_product=observed_p,
            observed_version=observed_v, advisory_product=advisory_p,
            affected_range=(affected_min, affected_max),
            signals=tuple(signals),
            terminal_reasons=("version_above_affected_range",))

    return CveApplicability(
        state=CVE_APPLICABILITY_CONFIRMED, product_identified=True,
        version_identified=True, observed_product=observed_p,
        observed_version=observed_v, advisory_product=advisory_p,
        affected_range=(affected_min, affected_max),
        signals=tuple(signals) + ("cve_applicability_evidence",),
        terminal_reasons=(), confirmatory=False)


__all__ = [
    "ACAO_ABSENT", "ACAO_EXACT_ORIGIN", "ACAO_MALFORMED", "ACAO_NULL",
    "ACAO_ORIGIN_LIST", "ACAO_REFLECTED_ARBITRARY",
    "ACAO_WILDCARD", "CORS_ORIGIN_CLASSES", "CONTROLLED_DESTINATION_TOKEN",
    "CONTROLLED_ORIGIN_TOKEN", "CONTROLLED_SUFFIX",     "CVE_APPLICABILITY_CONFIRMED", "CVE_APPLICABILITY_UNRESOLVED",
    "CVE_PRODUCT_UNKNOWN", "CVE_STATES", "CVE_VERSION_AMBIGUOUS",
    "CVE_VERSION_NOT_AFFECTED", "CVE_VERSION_UNKNOWN", "CVE_WRONG_PRODUCT",
    "CorsAssessment", "CveApplicability", "DestinationPolicy", "IdorCapability",
    "REDIRECT_CLASSES", "REDIRECT_DESTINATION_NORMALIZED",
    "REDIRECT_EXTERNAL_ACCEPTED", "REDIRECT_EXTERNAL_OUT_OF_SCOPE",
    "REDIRECT_NO_LOCATION", "REDIRECT_PARAMETER_IGNORED", "REDIRECT_RELATIVE_ONLY",
    "REDIRECT_SAME_ORIGIN", "REDIRECT_UNSAFE_SCHEME", "RULE_VERSION",
    "RedirectAssessment", "SsrfAssessment", "classify_cors",
    "classify_cve_applicability", "classify_idor", "classify_redirect",
    "classify_ssrf", "controlled_destination", "controlled_origin",
    "evaluate_destination", "is_controlled_origin",
]
