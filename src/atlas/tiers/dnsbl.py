"""
atlas.tiers.dnsbl
Tier 3: Queries DNS-based blocklists (Spamhaus DBL, SURBL) for domain reputation.

A listing on either blocklist is authoritative — if a domain appears here,
it's almost certainly malicious or compromised.

Ported from URL Auditor's dnsbl_checker.py with concurrent queries.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier


logger = logging.getLogger(__name__)


class DNSBLTier(Tier):
    name = "dnsbl"
    display_name = "DNS Blocklists"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.mirrors = config.dnsbl.mirrors
        self.timeout = config.dnsbl.timeout_seconds

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def _check(self, target: str, **context: object) -> TierResult:
        results = self._query_all_mirrors(target)

        is_flagged = any(r["status"] == "Blocked" for r in results.values())

        return TierResult(
            flagged=is_flagged,
            confidence=1.0 if is_flagged else 0.0,
            details={"mirrors": results},
        )

    # ── Mirror queries (concurrent) ──────────────────────────

    def _query_all_mirrors(self, domain: str) -> dict[str, dict]:
        """Query all DNSBL mirrors concurrently and collect results."""
        results: dict[str, dict] = {}

        with ThreadPoolExecutor(max_workers=len(self.mirrors)) as pool:
            futures = {
                pool.submit(self._query_single_mirror, domain, mirror): mirror
                for mirror in self.mirrors
            }
            for future in as_completed(futures):
                mirror = futures[future]
                results[mirror] = future.result()

        return results

    def _query_single_mirror(self, domain: str, mirror: str) -> dict:
        """Query a single DNSBL mirror for the given domain."""
        query = f"{domain}.{mirror}"

        try:
            answers = self.resolver.resolve(query, "A")
            returned_ips = [answer.to_text() for answer in answers]
            return {"status": "Blocked", "return_codes": returned_ips}

        except dns.resolver.NXDOMAIN:
            return {"status": "Clear"}

        except dns.resolver.Timeout:
            return {"status": "Error", "message": "Query timed out"}

        except Exception as exc:
            return {"status": "Error", "message": str(exc)}
