"""
atlas.recon.whois_lookup
Recon: WHOIS record lookup for a domain.

Extracts registration metadata — registrar, creation date, expiration date,
name servers, registrant organization (when available), and computes
human-readable age. WHOIS data quality varies wildly by TLD; this tool
gracefully degrades when fields are missing.

The heuristics tier uses WHOIS internally for age-based threat scoring;
this recon tool exposes the full record for human investigation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import whois

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


class WhoisReconTool(ReconTool):
    name = "whois"
    display_name = "WHOIS"

    def _run(self, target: str, **context: object) -> ReconResult:
        record = whois.whois(target)

        # WHOIS records can contain lists for some fields (multi-registrar
        # situations, multiple name servers, etc.). Normalize them.
        creation_date = self._normalize_date(record.creation_date)
        expiration_date = self._normalize_date(record.expiration_date)
        updated_date = self._normalize_date(record.updated_date)

        # Compute domain age and time to expiry in days
        age_days = self._days_since(creation_date)
        expires_in_days = self._days_until(expiration_date)

        # Status: "expired" / "expiring soon" / "active"
        status = self._compute_status(expires_in_days)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "registrar": self._normalize_str(record.registrar),
                "registrant_org": self._normalize_str(
                    getattr(record, "org", None) or getattr(record, "registrant", None)
                ),
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "age_days": age_days,
                "age_years": round(age_days / 365.25, 2) if age_days is not None else None,
                "expires_in_days": expires_in_days,
                "status": status,
                "name_servers": self._normalize_list(record.name_servers),
                "country": self._normalize_str(getattr(record, "country", None)),
                "raw_status": self._normalize_list(getattr(record, "status", None)),
            },
        )

    # ── Private helpers ───────────────────────────────────────

    def _normalize_date(self, value) -> datetime | None:
        """WHOIS dates can be datetime, list of datetimes, or None."""
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, datetime):
            # Make timezone-aware for consistent comparisons
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value
        return None

    def _normalize_str(self, value) -> str | None:
        """Normalize WHOIS string fields (sometimes lists, sometimes None)."""
        if value is None:
            return None
        if isinstance(value, list):
            return value[0] if value else None
        return str(value).strip()

    def _normalize_list(self, value) -> list[str]:
        """Normalize fields that should be lists (name servers, status flags)."""
        if value is None:
            return []
        if isinstance(value, list):
            # Lowercase and deduplicate
            return sorted({str(v).strip().lower() for v in value if v})
        return [str(value).strip().lower()]

    def _days_since(self, date: datetime | None) -> int | None:
        """Days from the given date until now."""
        if date is None:
            return None
        return (datetime.now(timezone.utc) - date).days

    def _days_until(self, date: datetime | None) -> int | None:
        """Days from now until the given date."""
        if date is None:
            return None
        return (date - datetime.now(timezone.utc)).days

    def _compute_status(self, days_until_expiry: int | None) -> str:
        """Derive a friendly status from expiry date."""
        if days_until_expiry is None:
            return "unknown"
        if days_until_expiry < 0:
            return "expired"
        if days_until_expiry < 30:
            return "expiring soon"
        return "active"
