"""
atlas.recon.crtsh
Recon: Certificate Transparency log lookup via crt.sh.

Every TLS certificate ever issued is logged in public CT logs. crt.sh
provides a free, no-auth JSON API over those logs. Looking up a domain
returns every certificate ever issued for it — including for subdomains
the operator may have forgotten existed.

Two distinct use cases this enables:

1. SUBDOMAIN ENUMERATION
   Cert history reveals subdomains that DNS bruteforcing might miss
   (especially short-lived dev/staging hosts that had a cert briefly).

2. CERT LIFECYCLE ANALYSIS
   A young domain with 47 wildcard certs across 30 different subdomains
   is classic attacker infrastructure prep. Cert volume + issuance
   patterns are a meaningful signal.

No API key, no rate limits (within reason). crt.sh can be slow for
popular domains and is known to be intermittently unavailable
(502/503/504/transient 404 errors are common). The tool retries
with exponential backoff but cannot work around extended outages.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

import httpx

from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 30  # crt.sh can be slow under load; longer than default


class CrtShReconTool(ReconTool):
    name = "crtsh"
    display_name = "Certificate Transparency"

    def _run(self, target: str, **context: object) -> ReconResult:
        # Query for the domain itself; crt.sh returns certs where the domain
        # appears anywhere in the cert's names (subject CN or SAN entries)
        certs = self._fetch_certificates(target)

        if certs is None:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error="crt.sh query failed or returned no data",
                data={},
            )

        # Process the cert list into summary data
        summary = self._summarize_certificates(certs, target)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data=summary,
        )

    # ── Private helpers ───────────────────────────────────────

    def _fetch_certificates(self, domain: str) -> list[dict] | None:
        """Fetch the CT log entries for a domain. Returns list or None on error."""
        params = {
            "q": domain,
            "output": "json",
        }

        # Use a normal User-Agent — crt.sh sometimes blocks bare python-httpx requests
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; ATLAS-Security-Tool/2.0)",
            "Accept": "application/json",
        }

        # crt.sh frequently fails under load with 502/503/504 — and occasionally
        # returns 404 when the backend is overwhelmed. Retry all of these.
        transient_codes = (404, 502, 503, 504)
        max_attempts = 3
        last_error: Exception | None = None

        for attempt in range(max_attempts):
            try:
                response = httpx.get(
                    CRTSH_URL,
                    params=params,
                    headers=headers,
                    timeout=CRTSH_TIMEOUT,
                )

                if response.status_code in transient_codes:
                    if attempt < max_attempts - 1:
                        wait = 2**attempt
                        logger.warning(
                            "crt.sh returned %d, retrying in %ds (attempt %d/%d)",
                            response.status_code,
                            wait,
                            attempt + 1,
                            max_attempts,
                        )
                        import time

                        time.sleep(wait)
                        continue
                    else:
                        logger.error(
                            "crt.sh persistently returning %d after %d attempts",
                            response.status_code,
                            max_attempts,
                        )
                        return None

                response.raise_for_status()

                if not response.text.strip():
                    return []

                data = response.json()
                return data if isinstance(data, list) else []

            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < max_attempts - 1:
                    import time

                    time.sleep(2**attempt)
                    continue
                logger.error("crt.sh request failed after %d attempts: %s", max_attempts, exc)
                return None
            except ValueError as exc:
                logger.error("crt.sh returned invalid JSON: %s", exc)
                return None

        return None

    def _summarize_certificates(self, certs: list[dict], target: str) -> dict:
        """
        Process raw cert data into a usable summary.

        Returns:
            Subdomains discovered, cert volume metrics, issuer breakdown,
            recent-issuance counts, and lifecycle dates.
        """
        if not certs:
            return {
                "total_certs": 0,
                "unique_subdomains": [],
                "subdomain_count": 0,
                "wildcard_count": 0,
                "issuers": {},
                "recent_certs_30d": 0,
                "oldest_cert_date": None,
                "newest_cert_date": None,
            }

        all_names: set[str] = set()
        wildcard_count = 0
        issuer_counter: Counter[str] = Counter()

        oldest_date: datetime | None = None
        newest_date: datetime | None = None
        recent_threshold = datetime.now(timezone.utc) - timedelta(days=30)
        recent_count = 0

        target_lower = target.lower().lstrip(".")

        for cert in certs:
            # Each cert has a name_value field with one or more names,
            # typically newline-separated when there are SANs.
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if not name:
                    continue
                if name.startswith("*."):
                    wildcard_count += 1
                # Only keep names that are subdomains of the target or the apex
                if name == target_lower or name.endswith("." + target_lower):
                    all_names.add(name)

            # Count issuers (the CA that signed the cert)
            issuer = cert.get("issuer_name", "")
            if issuer:
                # Issuer strings are long — extract just the O= part for readability
                issuer_short = self._short_issuer(issuer)
                issuer_counter[issuer_short] += 1

            # Track cert age via the entry_timestamp (when it was added to the CT log)
            entry_date = self._parse_date(cert.get("entry_timestamp"))
            if entry_date:
                if oldest_date is None or entry_date < oldest_date:
                    oldest_date = entry_date
                if newest_date is None or entry_date > newest_date:
                    newest_date = entry_date
                if entry_date > recent_threshold:
                    recent_count += 1

        # Separate wildcards from regular subdomains for cleaner display
        regular_subdomains = sorted(n for n in all_names if not n.startswith("*."))
        wildcards = sorted(n for n in all_names if n.startswith("*."))

        return {
            "total_certs": len(certs),
            "unique_subdomains": regular_subdomains,
            "subdomain_count": len(regular_subdomains),
            "wildcard_subdomains": wildcards,
            "wildcard_count": len(wildcards),
            # Top 5 issuers by volume — full breakdown could be dozens
            "issuers": dict(issuer_counter.most_common(5)),
            "recent_certs_30d": recent_count,
            "oldest_cert_date": oldest_date.isoformat() if oldest_date else None,
            "newest_cert_date": newest_date.isoformat() if newest_date else None,
        }

    def _short_issuer(self, issuer_string: str) -> str:
        """Extract the Organization (O=) field from a full issuer DN."""
        # Issuer DN looks like:
        # "C=US, O=Let's Encrypt, CN=R3"
        for part in issuer_string.split(","):
            part = part.strip()
            if part.upper().startswith("O="):
                return part[2:].strip().strip('"')
        # Fallback: return the first 60 chars
        return issuer_string[:60]

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse a crt.sh ISO-like timestamp."""
        if not date_str:
            return None
        try:
            # crt.sh format: "2024-01-15T08:30:00.123"
            parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, AttributeError):
            return None
