"""
atlas.tiers.virustotal
Tier 4: Submits URLs to VirusTotal's API for live multi-engine analysis.

This is the most expensive tier (requires an API key, makes multiple HTTP
calls, and can take 30+ seconds for a fresh scan). It only runs when earlier
tiers haven't already produced a definitive verdict.

Ported from URL Auditor's _check_tier4 method.
"""

from __future__ import annotations

import logging
import os
import time

import httpx
from dotenv import load_dotenv

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier

logger = logging.getLogger(__name__)

# Load .env once at module level so the key is available
load_dotenv()


class VirusTotalTier(Tier):
    name = "virustotal"
    display_name = "VirusTotal"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.danger_threshold = config.analysis.virustotal_danger_threshold
        self.max_retries = config.analysis.max_retries
        self.retry_wait = config.analysis.retry_wait_seconds
        self.timeout = config.analysis.request_timeout

    def _check(self, target: str, **context: object) -> TierResult:
        """
        Submit a URL to VirusTotal and retrieve the analysis report.
        The 'target' parameter is the domain (passed by the pipeline),
        but VirusTotal needs the full URL, so it is pulled from context.
        """

        # The pipeline passes the original URL as a keyword argument
        full_url = str(context.get("url", target))

        # Gate: no API key means we can't run this tier
        if not self.api_key:
            return TierResult(
                flagged=False,
                error="No VIRUSTOTAL_API_KEY found in environment or .env file",
            )

        # Step 1: Submit the URL for scanning
        analysis_id = self._submit_url(full_url)
        if analysis_id is None:
            return TierResult(
                flagged=False,
                error="Failed to submit URL to VirusTotal",
            )

        # Step 2: Poll for the completed report
        stats = self._poll_for_results(analysis_id)
        if stats is None:
            return TierResult(
                flagged=False,
                error="VirusTotal analysis did not complete in time",
            )

        # Step 3: Calculate the danger score
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        danger_pct = round((malicious / total) * 100, 1) if total > 0 else 0.0
        is_flagged = malicious > 0

        # Confidence scales with the danger score relative to the threshold
        if danger_pct >= self.danger_threshold:
            confidence = min(danger_pct / 100, 1.0)
        elif is_flagged:
            confidence = 0.4 # Flagged by some engines but below threshold
        else:
            confidence = 0.0

        return TierResult(
            flagged=is_flagged,
            confidence=confidence,
            details={
                "malicious_engines": malicious,
                "total_engines": total,
                "danger_score_percentage": danger_pct,
                "danger_threshold": self.danger_threshold,
                "stats": stats,
            },
        )

# ----Private Helpers ---------------------------------------------

    def _submit_url(self, url: str) -> str | None:
        """POST the URL to VirusTotal. Returns the analysis ID or None."""
        headers = {"x-apikey": self.api_key}

        for attempt in range(self.max_retries):
            try:
                response = httpx.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=self.timeout,
                )

                # Handle rate limiting with retry
                if response.status_code == 429:
                    if attempt < self.max_retries - 1:
                        logger.warning(
                            "VirusTotal rate limit hit (attempt %d/%d), waiting %ds",
                            attempt + 1, self.max_retries, self.retry_wait,
                        )
                        time.sleep(self.retry_wait)
                        continue
                    else:
                        logger.error("VirusTotal rate limit exceeded after %d retries",
                                     self.max_retries)
                        return None

                response.raise_for_status()
                return response.json()["data"]["id"]

            except httpx.TimeoutException:
                logger.error("VirusTotal submission timed out")
                return None
            except httpx.HTTPError as exc:
                logger.error("VirusTotal submission failed: %s", exc)
                return None

        return None

    def _poll_for_results(self, analysis_id: str) -> dict | None:
        """Poll the analysis endpoint until completion. Returns stats dict or None."""
        headers = {"x-apikey": self.api_key}
        max_polls = 10
        poll_interval = 10 # seconds

        for attempt in range(max_polls):
            time.sleep(poll_interval)

            try:
                response = httpx.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()

                data = response.json()["data"]
                status = data["attributes"].get("status")

                if status == "completed":
                    return data["attributes"]["stats"]

                logger.debug("VirusTotal analysis in progress (poll %d/%d)",
                             attempt + 1, max_polls)

            except httpx.HTTPError as exc:
                logger.error("VirusTotal poll failed: %s", exc)
                return None

        logger.error("VirusTotal analysis did not complete after %d polls", max_polls)
        return None