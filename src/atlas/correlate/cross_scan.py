"""
atlas.correlate.cross_scan
Correlator: Cross-Scan Infrastructure Reuse.

Where the other correlators synthesize ONLY the current scan's data, this one
reaches back into the scan database to find other domains that share
infrastructure with the one being analyzed. The signals queried are:

    - Same resolved IP — strongest signal; multiple domains pointing at the
      same host almost always means a shared operator.
    - Same ASN — moderate signal; could be the same hosting provider (common
      with Cloudflare, AWS), or could indicate a campaign on bulletproof infra.
    - Same WHOIS registrar — weak signal in isolation, but useful when stacked
      with the others, especially for less-common registrars.

Unlike the other correlators in this package, this one DOES query the
database — that's the whole point. It only runs when a ScanRepository is
available; in lightweight or test contexts where the pipeline is created
without one, this correlator returns a no-op result.

This correlator is what turns ATLAS from a per-URL scanner into a campaign-
aware platform: a domain may look clean in isolation but become obviously
malicious when you see five other flagged domains on the same IP.
"""

from __future__ import annotations

import logging
from typing import Any

from atlas.core.config import AtlasConfig
from atlas.core.models import CorrelationContext, CorrelationResult
from atlas.correlate.base import Correlator

logger = logging.getLogger(__name__)


# ASNs and registrars where matches are basically meaningless (everyone uses
# them). Excluding these would cut noise — but we keep them in for now and
# annotate them, so the analyst can still see the match and judge for themselves.
COMMON_ASN_HINTS: set[str] = {
    "AS13335",  # Cloudflare
    "AS16509",  # Amazon AWS
    "AS15169",  # Google
    "AS8075",   # Microsoft
    "AS14618",  # Amazon AES
}


class CrossScanCorrelator(Correlator):
    name = "cross_scan"
    display_name = "Cross-Scan Infrastructure"

    def __init__(self, config: AtlasConfig, repo: Any = None) -> None:
        """
        Args:
            config: Atlas configuration.
            repo:   A ScanRepository instance (or any object exposing
                    `find_related_scans()`). Optional — if None, the
                    correlator returns a no-op result.
        """
        super().__init__(config)
        self.repo = repo

    def _correlate(self, context: CorrelationContext) -> CorrelationResult:
        # Without storage we can't look at other scans
        if self.repo is None:
            return CorrelationResult(
                summary="Cross-scan correlation skipped (no storage available)",
                findings=[],
                data={"skipped": True, "reason": "no_repo"},
            )

        # Need a scan id to exclude ourselves from results
        scan_id = context.scan.id
        if scan_id is None:
            return CorrelationResult(
                summary="Cross-scan correlation skipped (scan not yet persisted)",
                findings=[],
                data={"skipped": True, "reason": "no_scan_id"},
            )

        # Extract the attributes we want to pivot on from current recon data
        ip = self._current_ip(context)
        asn = self._current_asn(context)
        registrar = self._current_registrar(context)
        favicon_hash = self._current_favicon_hash(context)
        slash24 = self._slash24_prefix(ip) if ip else None

        if not any([ip, asn, registrar, favicon_hash is not None, slash24]):
            return CorrelationResult(
                summary="No pivot attributes available for cross-scan correlation",
                findings=[],
                data={"skipped": True, "reason": "no_pivots"},
            )

        related = self.repo.find_related_scans(
            exclude_scan_id=scan_id,
            ip=ip,
            asn=asn,
            registrar=registrar,
            favicon_hash=favicon_hash,
            slash24=slash24,
        )

        findings: list[dict[str, Any]] = []
        for category, label, matched_value in (
            ("ip", "Same IP", ip),
            ("asn", "Same ASN", asn),
            ("registrar", "Same registrar", registrar),
            ("favicon", "Same favicon", favicon_hash),
            ("slash24", "Same /24", slash24),
        ):
            for row in related.get(category, []):
                findings.append({
                    "category": category,
                    "label": label,
                    "matched_value": matched_value,
                    "scan_id": row["scan_id"],
                    "domain": row["domain"],
                    "verdict": row["verdict"],
                    "scanned_at": row["scanned_at"],
                    "is_common_infra": category == "asn" and matched_value in COMMON_ASN_HINTS,
                })

        # Build a campaign-style summary
        unique_domains = {f["domain"] for f in findings}
        risky_domains = [f for f in findings if f["verdict"] in ("High Risk", "Medium Risk")]

        if not findings:
            summary = "No related scans found"
        else:
            parts = []
            if related.get("ip"):
                parts.append(f"{len(related['ip'])} on same IP")
            if related.get("asn"):
                parts.append(f"{len(related['asn'])} on same ASN")
            if related.get("registrar"):
                parts.append(f"{len(related['registrar'])} via same registrar")
            if related.get("favicon"):
                parts.append(f"{len(related['favicon'])} sharing favicon")
            if related.get("slash24"):
                parts.append(f"{len(related['slash24'])} in same /24")
            summary = (
                f"{len(unique_domains)} related domain(s) found ({', '.join(parts)})"
            )
            if risky_domains:
                summary += f" — {len(risky_domains)} flagged"

        return CorrelationResult(
            summary=summary,
            findings=findings,
            data={
                "match_counts": {k: len(v) for k, v in related.items()},
                "unique_related_domains": len(unique_domains),
                "risky_related_domains": len(risky_domains),
                "pivots": {
                    "ip": ip,
                    "asn": asn,
                    "registrar": registrar,
                    "favicon_hash": favicon_hash,
                    "slash24": slash24,
                },
            },
        )

    # ── Pivot extraction ─────────────────────────────────────

    @staticmethod
    def _current_ip(context: CorrelationContext) -> str | None:
        ip_intel = context.recon.get("ip_intel")
        if not ip_intel or ip_intel.error:
            return None
        ip = ip_intel.data.get("ip")
        return ip if isinstance(ip, str) and ip else None

    @staticmethod
    def _current_asn(context: CorrelationContext) -> str | None:
        ip_intel = context.recon.get("ip_intel")
        if not ip_intel or ip_intel.error:
            return None
        geo = ip_intel.data.get("geolocation") or {}
        asn = geo.get("asn")
        return asn if isinstance(asn, str) and asn else None

    @staticmethod
    def _current_registrar(context: CorrelationContext) -> str | None:
        whois_data = context.recon.get("whois")
        if not whois_data or whois_data.error:
            return None
        registrar = whois_data.data.get("registrar")
        return registrar if isinstance(registrar, str) and registrar else None

    @staticmethod
    def _current_favicon_hash(context: CorrelationContext) -> int | None:
        """
        Pull the MMH3 favicon hash from the current scan's web_recon data.
        Returns None if web_recon didn't run, failed, or got no favicon —
        all of which are normal outcomes that should leave this pivot inactive.
        """
        web_data = context.recon.get("web_recon")
        if not web_data or web_data.error:
            return None
        favicon = web_data.data.get("favicon") or {}
        if not isinstance(favicon, dict) or favicon.get("error"):
            return None
        h = favicon.get("mmh3_hash")
        return h if isinstance(h, int) else None

    @staticmethod
    def _slash24_prefix(ip: str) -> str | None:
        """
        Reduce an IPv4 address to its /24 prefix string (e.g. '1.2.3').
        Returns None for IPv6 or malformed addresses — those can't be
        pivoted via the GLOB pattern this correlator uses.
        """
        if not ip:
            return None
        octets = ip.split(".")
        if len(octets) != 4:
            return None
        # Validate each octet to avoid pushing garbage into the GLOB query
        try:
            for octet in octets:
                n = int(octet)
                if not (0 <= n <= 255):
                    return None
        except ValueError:
            return None
        return ".".join(octets[:3])
