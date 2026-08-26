from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import time

import httpx

from ai.schemas.source import ResearchDocument


class CVECollector:
    BASE_URL = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )

    RETRYABLE_STATUS_CODES = {
        429,
        500,
        502,
        503,
        504,
    }

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 4,
        min_request_interval: float = 6.0,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_request_interval = (
            min_request_interval
        )

        self.api_key = os.getenv(
            "NVD_API_KEY"
        )

        self._last_request_at = 0.0

    # =========================================================
    # HTTP / NVD
    # =========================================================

    def _request(
        self,
        params: dict,
    ) -> dict:
        """
        Perform an NVD API request with:
        - minimum request interval
        - retry for transient errors
        - exponential backoff
        - Retry-After support
        """

        headers = {
            "User-Agent": (
                "Watch-Security-Researcher/1.0"
            ),
            "Accept": "application/json",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        last_error = None

        for attempt in range(
            self.max_retries + 1
        ):
            # -------------------------------------------------
            # Respect request interval
            # -------------------------------------------------

            elapsed = (
                time.monotonic()
                - self._last_request_at
            )

            if elapsed < self.min_request_interval:
                time.sleep(
                    self.min_request_interval
                    - elapsed
                )

            try:
                response = httpx.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )

                self._last_request_at = (
                    time.monotonic()
                )

                # -------------------------------------------------
                # Success
                # -------------------------------------------------

                if response.status_code == 200:
                    return response.json()

                # -------------------------------------------------
                # Non-retryable error
                # -------------------------------------------------

                if (
                    response.status_code
                    not in self.RETRYABLE_STATUS_CODES
                ):
                    response.raise_for_status()

                # -------------------------------------------------
                # Retry-After
                # -------------------------------------------------

                retry_after = response.headers.get(
                    "Retry-After"
                )

                if retry_after:
                    try:
                        delay = float(
                            retry_after
                        )
                    except ValueError:
                        delay = 0.0
                else:
                    delay = min(
                        5.0 * (2 ** attempt),
                        40.0,
                    )

                delay += random.uniform(
                    0.0,
                    1.0,
                )

                if attempt >= self.max_retries:
                    response.raise_for_status()

                print(
                    f"NVD HTTP "
                    f"{response.status_code}; "
                    f"retry "
                    f"{attempt + 1}/"
                    f"{self.max_retries} "
                    f"in {delay:.1f}s"
                )

                time.sleep(delay)

            except (
                httpx.ConnectError,
                httpx.ConnectTimeout,
                httpx.ReadTimeout,
                httpx.RemoteProtocolError,
            ) as exc:

                last_error = exc

                if attempt >= self.max_retries:
                    raise

                delay = min(
                    5.0 * (2 ** attempt),
                    40.0,
                )

                delay += random.uniform(
                    0.0,
                    1.0,
                )

                print(
                    f"NVD network error: "
                    f"{type(exc).__name__}; "
                    f"retry "
                    f"{attempt + 1}/"
                    f"{self.max_retries} "
                    f"in {delay:.1f}s"
                )

                time.sleep(delay)

        if last_error:
            raise last_error

        raise RuntimeError(
            "NVD request failed without a response."
        )

    # =========================================================
    # Sync state
    # =========================================================

    def _sync_state_path(self) -> Path:
        return Path(
            "ai_data/cve/sync_state.json"
        )

    def _load_sync_state(self) -> dict:
        path = self._sync_state_path()

        if not path.exists():
            return {}

        try:
            return json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            ValueError,
        ):
            return {}

    def _save_sync_state(
        self,
        state: dict,
    ) -> None:

        path = self._sync_state_path()

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temp_path = path.with_suffix(
            ".tmp"
        )

        temp_path.write_text(
            json.dumps(
                state,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        temp_path.replace(path)

    # =========================================================
    # CVE -> ResearchDocument
    # =========================================================

    def _document_from_cve(
        self,
        cve: dict,
    ) -> ResearchDocument | None:

        cve_id = cve.get("id")

        if not cve_id:
            return None

        # -----------------------------------------------------
        # Description
        # -----------------------------------------------------

        description = ""

        for desc in cve.get(
            "descriptions",
            [],
        ):
            if desc.get("lang") == "en":
                description = desc.get(
                    "value",
                    "",
                )
                break

        # -----------------------------------------------------
        # Affected products
        # -----------------------------------------------------

        vendors = set()
        products = set()
        cpes = set()
        affected_versions = []

        for affected in cve.get(
            "affected",
            [],
        ):
            for affected_data in affected.get(
                "affectedData",
                [],
            ):

                vendor = affected_data.get(
                    "vendor"
                )

                product = affected_data.get(
                    "product"
                )

                if vendor:
                    vendors.add(vendor)

                if product:
                    products.add(product)

                for cpe in affected_data.get(
                    "cpes",
                    [],
                ):
                    if cpe:
                        cpes.add(cpe)

                for version in affected_data.get(
                    "versions",
                    [],
                ):
                    affected_versions.append(
                        {
                            "version": version.get(
                                "version"
                            ),
                            "less_than": version.get(
                                "lessThan"
                            ),
                            "version_type": version.get(
                                "versionType"
                            ),
                            "status": version.get(
                                "status"
                            ),
                        }
                    )

        # -----------------------------------------------------
        # CWE
        # -----------------------------------------------------

        cwes = set()

        for weakness in cve.get(
            "weaknesses",
            [],
        ):
            for desc in weakness.get(
                "description",
                [],
            ):
                value = desc.get(
                    "value"
                )

                if value:
                    cwes.add(value)

        # -----------------------------------------------------
        # CVSS
        # -----------------------------------------------------

        cvss_score = None
        cvss_vector = None

        metrics = cve.get(
            "metrics",
            {},
        )

        for metric_name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
        ):
            metric_list = metrics.get(
                metric_name,
                [],
            )

            if not metric_list:
                continue

            metric = metric_list[0]

            cvss_data = metric.get(
                "cvssData",
                {},
            )

            cvss_score = cvss_data.get(
                "baseScore"
            )

            cvss_vector = cvss_data.get(
                "vectorString"
            )

            break

        # -----------------------------------------------------
        # References
        # -----------------------------------------------------

        references = []

        for reference in cve.get(
            "references",
            [],
        ):
            url = reference.get(
                "url"
            )

            if url:
                references.append(url)

        # -----------------------------------------------------
        # Document
        # -----------------------------------------------------

        return ResearchDocument(
            source_type="cve",
            title=cve_id,
            url=(
                "https://nvd.nist.gov/vuln/detail/"
                f"{cve_id}"
            ),
            published_at=cve.get(
                "published"
            ),
            content=description,
            vendor=sorted(vendors),
            products=sorted(products),
            cpes=sorted(cpes),
            cwes=sorted(cwes),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=references,
            tags=["cve"],
            affected_versions=affected_versions,
        )

    # =========================================================
    # Latest CVEs by publication date
    # =========================================================

    def latest(
        self,
        days: int = 1,
    ) -> list[ResearchDocument]:

        now = datetime.now(
            timezone.utc
        )

        start_dt = (
            now
            - timedelta(
                days=days
            )
        )

        params = {
            "pubStartDate": start_dt.strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            ),
            "pubEndDate": now.strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            ),
            "resultsPerPage": 2000,
        }

        print(
            "NVD latest query:"
        )

        print(
            "  Start:",
            params["pubStartDate"],
        )

        print(
            "  End:",
            params["pubEndDate"],
        )

        data = self._request(
            params
        )

        documents = []

        for item in data.get(
            "vulnerabilities",
            [],
        ):
            cve = item.get(
                "cve",
                {},
            )

            document = self._document_from_cve(
                cve
            )

            if document is not None:
                documents.append(
                    document
                )

        return documents

    # =========================================================
    # Specific CVEs by ID
    # =========================================================

    def get_by_ids(
        self,
        cve_ids: list[str],
    ) -> list[ResearchDocument]:

        documents = []

        for cve_id in cve_ids:

            data = self._request(
                params={
                    "cveId": cve_id,
                }
            )

            for item in data.get(
                "vulnerabilities",
                [],
            ):
                cve = item.get(
                    "cve",
                    {},
                )

                if cve.get("id") != cve_id:
                    continue

                document = (
                    self._document_from_cve(
                        cve
                    )
                )

                if document is not None:
                    documents.append(
                        document
                    )

                break

        return documents

    # =========================================================
    # Incremental sync
    # =========================================================

    def sync(
        self,
        lookback_hours: int = 2,
    ) -> list[ResearchDocument]:
        """
        Incrementally fetch CVEs modified since the
        previous successful sync.

        First run:
            last lookback_hours

        Later runs:
            previous successful sync timestamp
        """

        now = datetime.now(
            timezone.utc
        )

        state = self._load_sync_state()

        last_sync_raw = state.get(
            "last_successful_sync"
        )

        if last_sync_raw:
            try:
                last_sync = (
                    datetime.fromisoformat(
                        last_sync_raw
                    )
                )

                if last_sync.tzinfo is None:
                    last_sync = (
                        last_sync.replace(
                            tzinfo=timezone.utc
                        )
                    )

            except ValueError:
                last_sync = (
                    now
                    - timedelta(
                        hours=lookback_hours
                    )
                )
        else:
            last_sync = (
                now
                - timedelta(
                    hours=lookback_hours
                )
            )

        # Small overlap prevents boundary misses.
        start = (
            last_sync
            - timedelta(
                seconds=5
            )
        )

        params = {
            "lastModStartDate": start.strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            ),
            "lastModEndDate": now.strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            ),
            "resultsPerPage": 2000,
        }

        print(
            "NVD incremental sync:"
        )

        print(
            "  Start:",
            params["lastModStartDate"],
        )

        print(
            "  End:",
            params["lastModEndDate"],
        )

        data = self._request(
            params
        )

        documents = []

        for item in data.get(
            "vulnerabilities",
            [],
        ):
            cve = item.get(
                "cve",
                {},
            )

            document = self._document_from_cve(
                cve
            )

            if document is not None:
                documents.append(
                    document
                )

        # -----------------------------------------------------
        # Advance cursor only after successful fetch + parse.
        # -----------------------------------------------------

        self._save_sync_state(
            {
                "last_successful_sync": (
                    now.isoformat()
                ),
                "fetched_count": len(
                    documents
                ),
            }
        )

        return documents