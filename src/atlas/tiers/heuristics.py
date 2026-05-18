"""
atlas.tiers.heuristics
Tier 2: Evaluates structural signals that suggest a domain may be malicious.

Two checks:
    1. Shannon entropy of the domain name — high randomness suggests DGA generation.
    2. WHOIS registration age — very new domains are disproportionately used for attacks.

Ported from URL Auditor's heuristics.py with config-driven thresholds.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from datetime import datetime, timezone

import whois

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier


logger = logging.getLogger(__name__)


class HeuristicsTier(Tier):
    name = "heuristics"
    display_name = "Heuristic Analysis"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.entropy_threshold = config.analysis.entropy_threshold
        self.age_threshold_hours = config.analysis.age_threshold_hours

    def _check(self, target: str, **context: object) -> TierResult:
        entropy_result = self._calculate_entropy(target)
        age_result = self._check_domain_age(target)

        is_suspicious = entropy_result["is_dga_suspected"] or age_result["is_new_domain"]

        # Confidence is higher when both checks agree
        signals = [entropy_result["is_dga_suspected"], age_result["is_new_domain"]]
        confidence = sum(signals) / len(signals) if is_suspicious else 0.0

        return TierResult(
            flagged=is_suspicious,
            confidence=confidence,
            details={
                "entropy": entropy_result,
                "age": age_result,
            },
        )

    # ── Entropy calculation ───────────────────────────────────

    def _calculate_entropy(self, domain: str) -> dict:
        """
        Calculate Shannon entropy of the domain's core name (before the TLD).
        High entropy (> threshold) suggests the name was algorithmically generated.
        """
        core = domain.split(".")[0]

        if not core:
            return {"entropy_score": 0.0, "is_dga_suspected": False}

        counts = Counter(core)
        length = len(core)
        probabilities = [count / length for count in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probabilities)

        is_suspected = entropy > self.entropy_threshold
        return {
            "entropy_score": round(entropy, 4),
            "threshold": self.entropy_threshold,
            "is_dga_suspected": is_suspected,
        }

    # ── WHOIS age check ──────────────────────────────────────

    def _check_domain_age(self, domain: str) -> dict:
        """
        Look up WHOIS registration date. Domains younger than the
        configured threshold (default 48 hours) are flagged.
        """
        try:
            info = whois.whois(domain)
            creation_date = info.creation_date

            # WHOIS sometimes returns a list of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                return {"age_hours": None, "is_new_domain": False,
                        "note": "No creation date in WHOIS record"}

            # Ensure timezone-aware comparison
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            age_hours = (datetime.now(timezone.utc) - creation_date).total_seconds() / 3600
            is_new = age_hours < self.age_threshold_hours

            return {
                "age_hours": round(age_hours, 2),
                "threshold_hours": self.age_threshold_hours,
                "is_new_domain": is_new,
            }
        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
            return {"age_hours": None, "is_new_domain": False, "error": str(exc)}
