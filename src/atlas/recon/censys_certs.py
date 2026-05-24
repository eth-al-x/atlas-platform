"""
atlas.recon.censys_certs
Recon: Certificate search via the Censys v2 API.

A complement to crtsh — Censys indexes the same CT logs but exposes a
structured search API with richer per-cert metadata:

    - Validation level (DV / OV / EV) for every cert
    - Full SAN list across pages, deduped into a unique-names set
    - Key algorithm per cert
    - Parsed issuer organization (cleaner than crt.sh raw DNs)

Where crt.sh is best for raw subdomain discovery and issuance history,
Censys is best for understanding the *quality* of the cert ecosystem
around a domain. A domain with exclusively DV certs is much more
consistent with attacker infrastructure — legitimate organizations
buy at least OV for their main domain.

Pagination: Censys uses cursor-based pagination. We walk up to
config.censys.max_pages pages (default 5 × 100 certs = 500 max).
The free tier is 250 queries/month — each paginated request costs one
query, so max_pages=5 costs up to 5 queries per domain.

Auth: CENSYS_API_ID + CENSYS_API_SECRET in .env (HTTP Basic Auth).
Gracefully skips (returns a no-credentials result) when absent.
"""

from __future__ import annotations

import logging
import os
from collections import Counter

import httpx
from dotenv import load_dotenv

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool

logger = logging.getLogger(__name__)

load_dotenv()

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/certificates/search"


class CensysCertsReconTool(ReconTool):
    name = "censys_certs"
    display_name = "Censys Certificates"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.api_id = os.getenv("CENSYS_API_ID", "")
        self.api_secret = os.getenv("CENSYS_API_SECRET", "")
        self.timeout = config.censys.timeout_seconds
        self.per_page = config.censys.per_page
        self.max_pages = config.censys.max_pages

    def _run(self, target: str, **context: object) -> ReconResult:
        if not (self.api_id and self.api_secret):
            return ReconResult(
                recon_type=self.name,
                domain=target,
                data={
                    "no_credentials": True,
                    "note": "Set CENSYS_API_ID and CENSYS_API_SECRET in .env to enable.",
                    "total_certs": 0,
                    "certs": [],
                    "unique_sans": [],
                    "unique_issuers": [],
                },
            )

        certs, total_reported, pages_fetched = self._fetch_all_pages(target)

        summary = self._summarize(certs, target)
        summary["total_reported"] = total_reported
        summary["pages_fetched"] = pages_fetched
        summary["truncated"] = pages_fetched >= self.max_pages and total_reported > len(certs)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data=summary,
        )

    # ── Fetching ──────────────────────────────────────────────

    def _fetch_all_pages(self, domain: str) -> tuple[list[dict], int, int]:
        """
        Walk cursor-paginated search results up to max_pages.

        Returns (hits, total_reported_by_api, pages_fetched).
        """
        hits: list[dict] = []
        total_reported = 0
        cursor: str | None = None
        auth = (self.api_id, self.api_secret)

        for page_num in range(self.max_pages):
            page_hits, total_reported, next_cursor = self._fetch_page(
                domain, auth, cursor
            )

            if page_hits is None:
                # Hard error — stop pagination but return what we have
                break

            hits.extend(page_hits)

            if not next_cursor:
                # No more pages
                return hits, total_reported, page_num + 1

            cursor = next_cursor

        return hits, total_reported, self.max_pages

    def _fetch_page(
        self,
        domain: str,
        auth: tuple[str, str],
        cursor: str | None,
    ) -> tuple[list[dict] | None, int, str | None]:
        """
        Fetch a single page of certificate search results.

        Returns (hits, total, next_cursor).
        hits is None on hard error.
        """
        body: dict = {
            "q": f"names: {domain}",
            "per_page": self.per_page,
        }
        if cursor:
            body["cursor"] = cursor

        try:
            response = httpx.post(
                CENSYS_SEARCH_URL,
                json=body,
                auth=auth,
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )

            if response.status_code == 401:
                logger.error("Censys: invalid credentials (401)")
                return None, 0, None

            if response.status_code == 429:
                logger.warning("Censys: rate limited (429)")
                return None, 0, None

            if response.status_code == 422:
                logger.warning("Censys: bad query (422) for domain %s", domain)
                return [], 0, None

            response.raise_for_status()
            data = response.json()

            result = data.get("result", {})
            hits = result.get("hits", [])
            total = result.get("total", 0)
            next_cursor = (result.get("links") or {}).get("next")

            return hits, total, next_cursor

        except httpx.HTTPError as exc:
            logger.error("Censys request failed: %s", exc)
            return None, 0, None

    # ── Summarization ─────────────────────────────────────────

    def _summarize(self, hits: list[dict], domain: str) -> dict:
        """Reduce raw cert hits to the analyst-relevant summary."""
        if not hits:
            return {
                "total_certs": 0,
                "certs": [],
                "unique_sans": [],
                "unique_issuers": [],
                "dv_only": False,
                "has_ov_ev": False,
            }

        certs = []
        all_names: set[str] = set()
        issuer_counter: Counter[str] = Counter()
        validation_levels: Counter[str] = Counter()

        domain_lower = domain.lower()

        for hit in hits:
            parsed = hit.get("parsed") or {}
            validity = parsed.get("validity") or {}
            issuer_info = parsed.get("issuer") or {}
            key_info = parsed.get("subject_key_info") or {}
            sig_alg = parsed.get("signature_algorithm") or {}

            # Validation level — prefer NSS, fall back to Apple, then unknown
            vtype = "unknown"
            for trust_store in ("nss", "apple", "microsoft", "android"):
                val = (hit.get("validation") or {}).get(trust_store) or {}
                if val.get("type"):
                    vtype = val["type"].upper()
                    break

            # Issuer org — take first entry from the list, fall back to DN
            issuer_orgs = issuer_info.get("organization") or []
            issuer = issuer_orgs[0] if issuer_orgs else (parsed.get("issuer_dn") or "Unknown")

            # Self-signed: subject DN == issuer DN
            subject_dn = parsed.get("subject_dn", "")
            issuer_dn = parsed.get("issuer_dn", "")
            self_signed = bool(subject_dn and subject_dn == issuer_dn)

            # All SANs for this cert, filtered to names within our domain
            cert_names: list[str] = hit.get("names") or parsed.get("names") or []
            cert_names = [n.lower() for n in cert_names]
            domain_names = [
                n for n in cert_names
                if n == domain_lower or n.endswith("." + domain_lower) or n.startswith("*.")
            ]
            all_names.update(domain_names)

            issuer_counter[issuer] += 1
            validation_levels[vtype] += 1

            certs.append({
                "fingerprint_sha256": hit.get("fingerprint_sha256", ""),
                "names": domain_names,
                "issuer": issuer,
                "validation_level": vtype,
                "key_algorithm": (
                    (key_info.get("key_algorithm") or {}).get("name")
                    or sig_alg.get("name")
                    or "unknown"
                ),
                "not_before": validity.get("start"),
                "not_after": validity.get("end"),
                "self_signed": self_signed,
            })

        has_ov_ev = any(vl in ("OV", "EV") for vl in validation_levels)
        dv_only = bool(certs) and not has_ov_ev and "DV" in validation_levels

        return {
            "total_certs": len(certs),
            "certs": certs,
            "unique_sans": sorted(all_names),
            "unique_issuers": [issuer for issuer, _ in issuer_counter.most_common()],
            "issuer_counts": dict(issuer_counter.most_common(10)),
            "validation_breakdown": dict(validation_levels),
            "dv_only": dv_only,
            "has_ov_ev": has_ov_ev,
        }
