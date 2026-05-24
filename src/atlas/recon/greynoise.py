"""
atlas.recon.greynoise
Recon: GreyNoise IP classification and internet noise context.

Resolves the target to an IP, then queries the GreyNoise Community API
for three key signals:

    noise           — is this IP actively scanning the internet?
                      (mass opportunistic activity vs targeted)
    riot            — is this a known-benign service?
                      (Google, Cloudflare, AWS crawlers — important for
                      suppressing false positives on shared infra)
    classification  — benign | malicious | unknown

Why this matters: an IP that's both suspicious AND actively scanning
the internet is a different threat profile than one that isn't. And an
IP that's flagged by a heuristic tier but is actually a well-known CDN
is a false positive — riot=True is the suppression signal.

API: https://api.greynoise.io/v3/community/{ip}
Key: GREYNOISE_API_KEY in .env — optional but recommended.
     Without a key, requests go through the unauthenticated tier
     (100 req/day). With a key, the limit is 10,000/day.

404 means the IP is not in GreyNoise's dataset — normal for IPs that
don't generate interesting traffic. This is returned as a clean
not_seen result, not an error.
"""

from __future__ import annotations

import logging
import os
import socket

import httpx
from dotenv import load_dotenv

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool

logger = logging.getLogger(__name__)

load_dotenv()

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseReconTool(ReconTool):
    name = "greynoise"
    display_name = "GreyNoise"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.api_key = os.getenv("GREYNOISE_API_KEY", "")
        self.timeout = config.analysis.request_timeout

    def _run(self, target: str, **context: object) -> ReconResult:
        ip = self._resolve_ip(target)
        if ip is None:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error="could not resolve domain to IP",
                data={},
            )

        gn = self._query_greynoise(ip)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={"ip": ip, **gn},
        )

    # ── Private helpers ───────────────────────────────────────

    def _resolve_ip(self, domain: str) -> str | None:
        """Resolve a domain to its primary A record IP."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror as exc:
            logger.debug("IP resolution failed for %s: %s", domain, exc)
            return None

    def _query_greynoise(self, ip: str) -> dict:
        """
        Query the GreyNoise Community API for an IP.

        Returns a dict with keys:
            seen          (bool)   — whether GreyNoise has any data on this IP
            noise         (bool)   — IP is actively scanning the internet
            riot          (bool)   — IP belongs to a known-benign service
            classification (str)   — "benign" | "malicious" | "unknown" | "not_seen"
            name          (str)    — human-readable actor/service name (if known)
            link          (str)    — GreyNoise visualizer URL
            last_seen     (str)    — ISO date of last observed activity
        """
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key

        try:
            response = httpx.get(
                GREYNOISE_COMMUNITY_URL.format(ip=ip),
                headers=headers,
                timeout=self.timeout,
            )

            # 404 = IP not in GreyNoise dataset — normal, not an error
            if response.status_code == 404:
                return {
                    "seen": False,
                    "noise": False,
                    "riot": False,
                    "classification": "not_seen",
                    "name": None,
                    "link": None,
                    "last_seen": None,
                }

            # 401 = bad or missing API key
            if response.status_code == 401:
                return {"error": "invalid or missing GREYNOISE_API_KEY"}

            # 429 = rate limited
            if response.status_code == 429:
                return {"error": "rate limited — add GREYNOISE_API_KEY or wait"}

            response.raise_for_status()
            data = response.json()

            return {
                "seen": True,
                "noise": bool(data.get("noise", False)),
                "riot": bool(data.get("riot", False)),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name"),
                "link": data.get("link"),
                "last_seen": data.get("last_seen"),
            }

        except httpx.HTTPError as exc:
            return {"error": str(exc)}
