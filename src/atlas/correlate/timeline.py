"""
atlas.correlate.timeline
Correlator: Domain Timeline Reconstruction.

Builds a chronological story of a domain's life by combining temporal
signals scattered across recon tools:

    - WHOIS creation/expiry dates
    - Oldest crt.sh certificate (earliest known TLS appearance)
    - Newest crt.sh certificate (most recent operational activity)
    - urlscan.io scan history (if available)

The synthesis surfaces patterns no individual tool can: a domain registered
yesterday with cert history going back 6 months is probably reused/parked
infrastructure, not a fresh attacker setup. A domain registered last year
with no TLS history is likely dormant or never deployed publicly.

Output is a list of dated events sorted oldest-first plus an "interpretation"
that highlights the most notable patterns.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from atlas.core.models import CorrelationContext, CorrelationResult
from atlas.correlate.base import Correlator


class TimelineCorrelator(Correlator):
    name = "timeline"
    display_name = "Domain Timeline"

    def _correlate(self, context: CorrelationContext) -> CorrelationResult:
        events: list[dict[str, Any]] = []

        # ── WHOIS dates ───────────────────────────────────────
        whois = context.recon.get("whois")
        if whois and not whois.error:
            created = self._parse_date(
                whois.data.get("creation_date") or whois.data.get("created")
            )
            if created:
                events.append({
                    "date": created.isoformat(),
                    "source": "whois",
                    "event": "Domain registered",
                    "details": {
                        "registrar": whois.data.get("registrar"),
                    },
                })

            expires = self._parse_date(
                whois.data.get("expiration_date") or whois.data.get("expires")
            )
            if expires:
                events.append({
                    "date": expires.isoformat(),
                    "source": "whois",
                    "event": "Registration expires",
                    "details": {},
                })

        # ── Certificate Transparency events ───────────────────
        crtsh = context.recon.get("crtsh")
        oldest_cert: datetime | None = None
        newest_cert: datetime | None = None
        if crtsh and not crtsh.error:
            certs = crtsh.data.get("recent_certs") or crtsh.data.get("certificates") or []
            cert_dates = []
            for cert in certs:
                issued = self._parse_date(
                    cert.get("not_before") or cert.get("issued_at")
                )
                if issued:
                    cert_dates.append(issued)

            if cert_dates:
                oldest_cert = min(cert_dates)
                newest_cert = max(cert_dates)
                events.append({
                    "date": oldest_cert.isoformat(),
                    "source": "crtsh",
                    "event": "First known TLS certificate",
                    "details": {"total_certs": len(cert_dates)},
                })
                if (newest_cert - oldest_cert).days > 1:
                    events.append({
                        "date": newest_cert.isoformat(),
                        "source": "crtsh",
                        "event": "Most recent TLS certificate",
                        "details": {},
                    })

        # ── urlscan history ──────────────────────────────────
        urlscan = context.recon.get("urlscan")
        if urlscan and not urlscan.error:
            scan_date = self._parse_date(urlscan.data.get("scan_date"))
            if scan_date:
                events.append({
                    "date": scan_date.isoformat(),
                    "source": "urlscan",
                    "event": "Last urlscan.io sandbox visit",
                    "details": {
                        "verdict": urlscan.data.get("verdict"),
                    },
                })

        # Sort oldest-first
        events.sort(key=lambda e: e["date"])

        # ── Interpretation ────────────────────────────────────
        observations = self._interpret(context, events, oldest_cert, newest_cert)

        if not events:
            summary = "No temporal data available"
        else:
            summary = f"{len(events)} timeline event(s) reconstructed"
            if observations:
                summary += f" — {observations[0]}"

        return CorrelationResult(
            summary=summary,
            findings=events,
            data={
                "event_count": len(events),
                "observations": observations,
            },
        )

    # ── Helpers ───────────────────────────────────────────────

    def _interpret(
        self,
        context: CorrelationContext,
        events: list[dict],
        oldest_cert: datetime | None,
        newest_cert: datetime | None,
    ) -> list[str]:
        """Look for notable patterns across the timeline."""
        observations: list[str] = []

        whois = context.recon.get("whois")
        whois_created = None
        if whois and not whois.error:
            whois_created = self._parse_date(
                whois.data.get("creation_date") or whois.data.get("created")
            )

        # Cert history predating WHOIS registration (suggests reused infrastructure)
        if whois_created and oldest_cert:
            diff = (whois_created - oldest_cert).days
            if diff > 30:
                observations.append(
                    f"TLS certificate history predates WHOIS registration by {diff} days "
                    f"(possible domain reuse or registration data discrepancy)"
                )

        # Very new domain
        if whois_created:
            age = (datetime.now(timezone.utc) - whois_created).days
            if age < 7:
                observations.append(f"Domain is only {age} days old")
            elif age < 30:
                observations.append(f"Domain is {age} days old (new)")

        # Long-lived domain
        if whois_created:
            age = (datetime.now(timezone.utc) - whois_created).days
            if age > 365 * 5:
                years = age // 365
                observations.append(f"Domain is {years}+ years old (well-established)")

        # Recent cert activity
        if newest_cert:
            since_newest = (datetime.now(timezone.utc) - newest_cert).days
            if since_newest <= 7:
                observations.append("Active certificate issuance in last 7 days")
            elif since_newest > 365:
                observations.append(f"No new certificates in {since_newest} days (may be dormant)")

        return observations

    @staticmethod
    def _parse_date(value: Any) -> datetime | None:
        """Best-effort parse of a date from various formats."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None
