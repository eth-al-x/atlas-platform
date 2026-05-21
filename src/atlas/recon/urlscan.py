"""
atlas.recon.urlscan
Recon: Behavioral analysis via urlscan.io's sandbox browser.

urlscan.io actually visits the URL in a sandboxed browser, capturing:
    - A screenshot of the rendered page
    - Every network request (IPs, domains, countries contacted)
    - JavaScript behavior and the final rendered DOM
    - urlscan's own verdict ("malicious" / "suspicious" / clean) plus a score

This is qualitatively different from reputation-based tiers — it captures
what the URL actually *does*, not what other people said about it. The
most useful tool in ATLAS for verifying suspected phishing pages, since
phishing kits often change behavior based on referrer/geolocation/UA
and only the actual rendered page reveals the deception.

Requires an API key (free with registration at urlscan.io). Submissions
default to "unlisted" visibility — not in the public search archive but
viewable via the direct report link.

API pattern is submit-then-poll: the submit returns a UUID immediately,
the actual browser scan runs asynchronously, results become available
~10-30 seconds later.
"""

from __future__ import annotations

import logging
import os
import time

import httpx
from dotenv import load_dotenv

from atlas.core.config import AtlasConfig
from atlas.core.domain import normalize_url
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)

# Load .env so URLSCAN_API_KEY is available
load_dotenv()


URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"

# Polling tuning — urlscan scans take 10-30 seconds typically
POLL_INTERVAL_SECONDS = 5
MAX_POLL_ATTEMPTS = 18  # 18 * 5 = 90 seconds max wait
INITIAL_WAIT_SECONDS = 8  # Wait before first poll; scans are never ready immediately


class URLScanReconTool(ReconTool):
    name = "urlscan"
    display_name = "urlscan.io"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.api_key = os.getenv("URLSCAN_API_KEY", "")
        self.timeout = config.analysis.request_timeout
        # Default to unlisted — not in public search but viewable via direct link
        self.visibility = "unlisted"

    def _run(self, target: str, **context: object) -> ReconResult:
        if not self.api_key:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error="No URLSCAN_API_KEY found in environment or .env file",
                data={},
            )

        url = normalize_url(target)

        # Step 1: Submit the URL for scanning
        uuid, submit_error = self._submit_scan(url)
        if uuid is None:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error=submit_error or "submission failed",
                data={},
            )

        logger.info("urlscan submission accepted, uuid=%s", uuid)

        # Step 2: Poll for completed results
        result_data, poll_error = self._poll_for_results(uuid)
        if result_data is None:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error=poll_error or "results not ready in time",
                data={
                    "uuid": uuid,
                    "report_url": f"https://urlscan.io/result/{uuid}/",
                    "note": "scan submitted but results not available yet",
                },
            )

        # Step 3: Extract the relevant summary
        return ReconResult(
            recon_type=self.name,
            domain=target,
            data=self._summarize(result_data),
        )

    # ── Submission ────────────────────────────────────────────

    def _submit_scan(self, url: str) -> tuple[str | None, str | None]:
        """
        Submit a URL to urlscan.io. Returns (uuid, error_message).
        Exactly one of the two will be None.
        """
        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "url": url,
            "visibility": self.visibility,
        }

        try:
            response = httpx.post(
                URLSCAN_SUBMIT_URL,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )

            # Handle the specific error codes urlscan returns
            if response.status_code == 401:
                return None, "invalid URLSCAN_API_KEY"
            if response.status_code == 400:
                # urlscan refused the URL — usually means it's invalid or unscannable
                msg = response.json().get("description", "URL rejected by urlscan")
                return None, f"urlscan rejected URL: {msg}"
            if response.status_code == 429:
                return None, "urlscan rate limit reached (try again later)"

            response.raise_for_status()
            data = response.json()
            uuid = data.get("uuid")
            if not uuid:
                return None, "submission succeeded but no UUID returned"

            return uuid, None

        except httpx.HTTPError as exc:
            logger.error("urlscan submission failed: %s", exc)
            return None, str(exc)
        except ValueError as exc:
            return None, f"invalid JSON in urlscan response: {exc}"

    # ── Polling ───────────────────────────────────────────────

    def _poll_for_results(self, uuid: str) -> tuple[dict | None, str | None]:
        """
        Poll the result endpoint until the scan completes.
        Returns (result_data, error_message). Exactly one will be None.
        """
        headers = {"API-Key": self.api_key}
        url = URLSCAN_RESULT_URL.format(uuid=uuid)

        # Initial wait — results are never ready immediately
        time.sleep(INITIAL_WAIT_SECONDS)

        for attempt in range(MAX_POLL_ATTEMPTS):
            try:
                response = httpx.get(url, headers=headers, timeout=self.timeout)

                # 404 = still processing, keep polling
                if response.status_code == 404:
                    logger.debug("urlscan results not ready, poll %d/%d",
                                 attempt + 1, MAX_POLL_ATTEMPTS)
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                response.raise_for_status()
                return response.json(), None

            except httpx.HTTPError as exc:
                logger.error("urlscan polling failed: %s", exc)
                return None, str(exc)

        return None, f"results still not ready after {MAX_POLL_ATTEMPTS} polls"

    # ── Result summarization ──────────────────────────────────

    def _summarize(self, data: dict) -> dict:
        """Extract the most useful fields from urlscan's verbose response."""
        task = data.get("task", {})
        page = data.get("page", {})
        verdicts = data.get("verdicts", {}).get("overall", {})
        stats = data.get("stats", {})
        lists = data.get("lists", {})

        return {
            # The scan identifiers and links
            "uuid": task.get("uuid"),
            "report_url": task.get("reportURL"),
            "screenshot_url": task.get("screenshotURL"),
            "scanned_url": task.get("url"),

            # urlscan's own verdict
            "malicious": verdicts.get("malicious", False),
            "score": verdicts.get("score", 0),
            "tags": verdicts.get("tags", []),

            # What the page actually was when loaded
            "page": {
                "ip": page.get("ip"),
                "country": page.get("country"),
                "server": page.get("server"),
                "domain": page.get("domain"),
                "umbrella_rank": page.get("umbrellaRank"),
            },

            # Behavioral stats from the browser visit
            "stats": {
                "unique_ips": stats.get("uniqIPs"),
                "unique_countries": stats.get("uniqCountries"),
                "unique_domains": stats.get("uniqDomains"),
                "total_requests": stats.get("requests"),
                "malicious_requests": stats.get("malicious", 0),
            },

            # The contacted infrastructure — useful for IoC extraction
            "contacted_ips": lists.get("ips", [])[:20],  # cap to keep summary readable
            "contacted_domains": lists.get("domains", [])[:30],
        }
