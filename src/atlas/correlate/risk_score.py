"""
atlas.correlate.risk_score
Correlator: Composite Risk Score (0-100).

Aggregates signals from tier results and selected recon outputs into a
single composite score with a contribution breakdown. Right now each tier
returns its own confidence in isolation — this correlator unifies them.

The score is a weighted sum of contributions from:
    - Tier flags (weighted by tier reliability)
    - WHOIS age (young domains are riskier)
    - HTTP security header grade (weak headers slightly increase risk)
    - urlscan.io verdict (if available)
    - crt.sh cert velocity (burst of new certs is suspicious)

The output shows what contributed and by how much, so the score is
explainable rather than a black box.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from atlas.core.models import CorrelationContext, CorrelationResult
from atlas.correlate.base import Correlator


# ── Tier weights ──────────────────────────────────────────────
# How much each tier contributes when it flags (out of 100).
# Reliable, high-signal tiers contribute more.
TIER_WEIGHTS: dict[str, float] = {
    "virustotal": 40.0,       # Multi-engine consensus - very reliable
    "local_blocklist": 35.0,  # Curated lists - reliable but binary
    "dnsbl": 30.0,            # Multiple reputable sources
    "typosquat": 25.0,        # Strong signal when distance is small
    "heuristics": 15.0,       # Weaker on its own
}


class RiskScoreCorrelator(Correlator):
    name = "risk_score"
    display_name = "Composite Risk Score"

    def _correlate(self, context: CorrelationContext) -> CorrelationResult:
        contributions: list[dict[str, Any]] = []
        score = 0.0

        # ── Tier signals ──────────────────────────────────────
        for tier in context.scan.tier_results:
            if not tier.flagged or tier.error:
                continue
            base_weight = TIER_WEIGHTS.get(tier.tier_name, 10.0)
            # Scale contribution by the tier's own confidence
            contribution = base_weight * tier.confidence
            score += contribution
            contributions.append({
                "source": tier.tier_name,
                "category": "tier",
                "points": round(contribution, 1),
                "reason": f"{tier.display_name or tier.tier_name} flagged (confidence={tier.confidence:.2f})",
            })

        # ── WHOIS age signal ──────────────────────────────────
        whois = context.recon.get("whois")
        if whois and not whois.error:
            age_days = self._domain_age_days(whois.data)
            if age_days is not None:
                if age_days < 7:
                    contribution = 15.0
                    reason = f"Domain registered {age_days} days ago (very new)"
                elif age_days < 30:
                    contribution = 8.0
                    reason = f"Domain registered {age_days} days ago (new)"
                elif age_days < 90:
                    contribution = 3.0
                    reason = f"Domain registered {age_days} days ago (recent)"
                else:
                    contribution = 0.0
                    reason = None

                if contribution > 0:
                    score += contribution
                    contributions.append({
                        "source": "whois",
                        "category": "recon",
                        "points": contribution,
                        "reason": reason,
                    })

        # ── HTTP headers signal ───────────────────────────────
        headers = context.recon.get("http_headers")
        if headers and not headers.error:
            grade = headers.data.get("security_grade", "").lower()
            if grade == "weak":
                contribution = 4.0
                score += contribution
                contributions.append({
                    "source": "http_headers",
                    "category": "recon",
                    "points": contribution,
                    "reason": "Weak HTTP security headers",
                })

        # ── urlscan signal ────────────────────────────────────
        urlscan = context.recon.get("urlscan")
        if urlscan and not urlscan.error:
            if urlscan.data.get("malicious"):
                contribution = 25.0
                score += contribution
                contributions.append({
                    "source": "urlscan",
                    "category": "recon",
                    "points": contribution,
                    "reason": "urlscan.io flagged as malicious",
                })
            score_val = urlscan.data.get("score", 0)
            if isinstance(score_val, (int, float)) and score_val >= 50:
                contribution = (score_val / 100.0) * 15.0
                score += contribution
                contributions.append({
                    "source": "urlscan",
                    "category": "recon",
                    "points": round(contribution, 1),
                    "reason": f"urlscan.io score {score_val}/100",
                })

        # ── crt.sh velocity signal ────────────────────────────
        crtsh = context.recon.get("crtsh")
        if crtsh and not crtsh.error:
            recent_count = self._certs_in_last_n_days(crtsh.data, 7)
            if recent_count >= 10:
                contribution = 8.0
                score += contribution
                contributions.append({
                    "source": "crtsh",
                    "category": "recon",
                    "points": contribution,
                    "reason": f"{recent_count} TLS certs issued in last 7 days (high velocity)",
                })

        # ── Clamp to 0-100 ────────────────────────────────────
        score = max(0.0, min(100.0, score))
        risk_band = self._band(score)

        return CorrelationResult(
            summary=f"Risk Score: {score:.0f}/100 ({risk_band})",
            findings=contributions,
            data={
                "score": round(score, 1),
                "band": risk_band,
                "contribution_count": len(contributions),
            },
        )

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _band(score: float) -> str:
        if score >= 70:
            return "High"
        if score >= 40:
            return "Medium"
        if score >= 15:
            return "Low"
        return "Minimal"

    @staticmethod
    def _domain_age_days(whois_data: dict) -> int | None:
        """Extract domain age in days from WHOIS data."""
        created = whois_data.get("creation_date") or whois_data.get("created")
        if not created:
            return None
        try:
            if isinstance(created, str):
                # Try ISO format first, then fall back to common formats
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            elif isinstance(created, datetime):
                created_dt = created
            else:
                return None

            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - created_dt
            return max(0, delta.days)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _certs_in_last_n_days(crtsh_data: dict, days: int) -> int:
        """Count certificates issued in the last N days."""
        certs = crtsh_data.get("recent_certs") or crtsh_data.get("certificates") or []
        if not certs:
            return 0
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
        count = 0
        for cert in certs:
            issued = cert.get("not_before") or cert.get("issued_at")
            if not issued:
                continue
            try:
                if isinstance(issued, str):
                    ts = datetime.fromisoformat(issued.replace("Z", "+00:00")).timestamp()
                else:
                    ts = float(issued)
                if ts >= cutoff:
                    count += 1
            except (ValueError, TypeError):
                continue
        return count
