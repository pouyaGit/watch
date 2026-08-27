from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class PresenceCheck:
    path: str
    purpose: str


@dataclass
class PluginPresenceResult:
    target: str
    ecosystem: str
    product: str

    status: str
    version: str | None

    checks: list[PresenceCheck]
    reason: str


class WordPressPluginPresenceVerifier:
    """
    Build non-destructive fingerprint checks for a WordPress plugin.

    This class does not send requests.
    """

    PLUGIN_SLUGS = {
        "wp responsive images": "wp-responsive-images",
    }

    def _normalize_base(
        self,
        target: str,
    ) -> str:

        target = target.strip().rstrip("/")

        if target.startswith("http://"):
            return target

        if target.startswith("https://"):
            return target

        return f"https://{target}"

    def plugin_slug(
        self,
        plugin_name: str,
    ) -> str | None:

        key = plugin_name.strip().lower()

        return self.PLUGIN_SLUGS.get(
            key
        )

    def build_checks(
        self,
        target: str,
        plugin_slug: str,
        plugin_name: str,
    ) -> PluginPresenceResult:

        base = self._normalize_base(
            target
        )

        plugin_base = (
            f"{base}/wp-content/plugins/"
            f"{plugin_slug}"
        )

        checks = [
            PresenceCheck(
                path=(
                    f"{plugin_base}/"
                    "readme.txt"
                ),
                purpose=(
                    "WordPress plugin readme; "
                    "may expose stable/version metadata."
                ),
            ),
            PresenceCheck(
                path=f"{plugin_base}/",
                purpose=(
                    "Plugin directory presence fingerprint."
                ),
            ),
            PresenceCheck(
                path=(
                    f"{plugin_base}/"
                    f"{plugin_slug}.php"
                ),
                purpose=(
                    "Plugin main-file presence fingerprint."
                ),
            ),
        ]

        return PluginPresenceResult(
            target=target,
            ecosystem="wordpress",
            product=plugin_name,
            status="UNKNOWN",
            version=None,
            checks=checks,
            reason=(
                "Plugin presence and version have not "
                "yet been verified."
            ),
        )

    def to_dict(
        self,
        result: PluginPresenceResult,
    ) -> dict:

        return {
            "target": result.target,
            "ecosystem": result.ecosystem,
            "product": result.product,
            "status": result.status,
            "version": result.version,
            "checks": [
                asdict(check)
                for check in result.checks
            ],
            "reason": result.reason,
        }