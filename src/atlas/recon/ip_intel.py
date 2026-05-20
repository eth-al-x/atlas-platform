"""
atlas.recon.ip_intel
Recon: IP address intelligence for a domain.

Resolves the domain to an IP, then queries free public reputation sources:
    - ip-api.com — geolocation, ISP, ASN, organization
    - Shodan InternetDB — open ports, hostnames, CVEs, software tags

Neither requires an API key. Both have generous free rate limits suitable
for interactive use. Useful for understanding *where* a domain lives and
*what's exposed* on it, beyond what DNS alone tells you.

Ported from the original ATLAS fetch.py functions, restructured under
the ReconTool interface.
"""

from __future__ import annotations

import logging
import socket

import httpx

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


# Free APIs, no keys required
IP_API_URL = "http://ip-api.com/json/{ip}"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


class IPIntelReconTool(ReconTool):
    name = "ip_intel"
    display_name = "IP Intelligence"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.timeout = config.analysis.request_timeout

    def _run(self, target: str, **context: object) -> ReconResult:
        # Step 1: resolve the domain to an IP
        ip = self._resolve_ip(target)
        if ip is None:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error="could not resolve domain to IP",
                data={},
            )

        # Step 2 & 3: query both intelligence sources (sequential is fine —
        # each is fast and we want clean error attribution per source)
        geo = self._query_ip_api(ip)
        exposure = self._query_shodan_internetdb(ip)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "ip": ip,
                "geolocation": geo,
                "exposure": exposure,
            },
        )

    # ── Private helpers ───────────────────────────────────────

    def _resolve_ip(self, domain: str) -> str | None:
        """Resolve a domain to its primary A record IP."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror as exc:
            logger.debug("IP resolution failed for %s: %s", domain, exc)
            return None

    def _query_ip_api(self, ip: str) -> dict:
        """Query ip-api.com for geolocation and ASN data."""
        try:
            response = httpx.get(
                IP_API_URL.format(ip=ip),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            # ip-api returns {"status": "fail", "message": "..."} on errors
            if data.get("status") == "fail":
                return {"error": data.get("message", "unknown error")}

            # Extract the fields we actually care about
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "isp": data.get("isp"),
                "organization": data.get("org"),
                "asn": data.get("as"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
            }
        except httpx.HTTPError as exc:
            return {"error": str(exc)}

    def _query_shodan_internetdb(self, ip: str) -> dict:
        """Query Shodan's free InternetDB for exposure data."""
        try:
            response = httpx.get(
                SHODAN_INTERNETDB_URL.format(ip=ip),
                timeout=self.timeout,
            )
            # InternetDB returns 404 when no data exists — that's not an error
            if response.status_code == 404:
                return {"note": "no exposure data on Shodan InternetDB"}

            response.raise_for_status()
            data = response.json()

            return {
                "open_ports": sorted(data.get("ports", [])),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),  # Software fingerprints
                "tags": data.get("tags", []),  # e.g. "cloud", "self-signed"
                "vulnerabilities": data.get("vulns", []),
            }
        except httpx.HTTPError as exc:
            return {"error": str(exc)}
