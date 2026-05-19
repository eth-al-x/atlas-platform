"""
atlas.tiers.typosquat
Tier: Detects domains that are visually or textually similar to high-value brands or TLDs.

Catches typosquatting attacks (e.g. paypa1.com, g00gle.com, microsof.com) where
attackers register lookalike domains to harvest credentials from users of legitimate domains
who mistype the real address.

Uses Levenshtein edit distance via rapidfuzz - distance 1 means one character change,
distance 2 means two changes, and so on. Tunable per-brand threshold via config.
"""

from __future__ import annotations

import logging

from rapidfuzz.distance import Levenshtein

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier


logger = logging.getLogger(__name__)


# High-value brands frequently impersonated in phishing campaigns.
# Stored as the core name (no TLD) for comparison after stripping the input's TLD.
# Keep this list reasonably small - every entry is checked on every scan.
DEFAULT_PROTECTED_BRANDS: tuple[str, ...] = (
    # Tech giants
    "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "linkedin", "twitter", "netflix", "youtube",
    # Cloud / Dev Tools
    "github", "gitlab", "atlassian", "dropbox", "slack", "zoom",
    # Financial
    "paypal", "venmo", "chase", "wellsfargo", "bankofamerica", "citibank",
    "coinbase", "binance",
    # Email / Productivity
    "outlook", "gmail", "office365",
    # Shopping
    "ebay", "walmart", "target", "bestbuy",
)


class TyposquatTier(Tier):
    name = "typosquat"
    display_name = "Typosquat Detection"

    # Max edit distance to consider "suspiciously similar" to a brand
    MAX_DISTANCE = 2

    # Domains shorter than this can't be reliably checked - too many false
    # positives when the brand name itself is short (e.g., "ebay is 4 chars,
    # any 4-char domain is within distance 4 of it by default)
    MIN_CORE_LENGTH = 4

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        # Future: pull brand list from config.typosquat.brands
        self.brands = DEFAULT_PROTECTED_BRANDS

    def _check(self, target: str, **context: object) -> TierResult:
        core = self._extract_core(target)

        # Skip very short domains - too noisy
        if len(core) < self.MIN_CORE_LENGTH:
            return TierResult(
                flagged=False,
                details={"core": core, "skipped": "domain too short"},
            )

        # Exact match to a brand is not typosquatting - it's the real domain
        if core in self.brands:
            return TierResult(
                flagged=False,
                details={"core": core, "matched_brand": core, "exact_match": True},
            )

        # Find the closest brand by edit distance
        closest_brand, distance = self._closest_brand(core)

        if distance <= self.MAX_DISTANCE:
            # Confidence is higher when distance is smaller (1 char off = stronger signal)
            confidence = 1.0 - (distance / (self.MAX_DISTANCE + 1))
            return TierResult(
                flagged=True,
                confidence=confidence,
                details={
                    "core": core,
                    "closest_brand": closest_brand,
                    "edit_distance": distance,
                    "max_distance": self.MAX_DISTANCE,
                }
            )

        return TierResult(
            flagged=False,
            details={
                "core": core,
                "closest_brand": closest_brand,
                "edit_distance": distance,
            }
        )

    # -- Private Helpers ------------------------------------

    def _extract_core(self, domain: str) -> str:
        """Strip the TLD(s) and return the core domain name in lowercase."""
        # Take everything before the first dot - "google.com" -> "google",
        # "mail.papypal.co.uk" -> "mail" (subdomain already stripped by extract_domain)
        return domain.lower().split(".")[0]

    def _closest_brand(self, core: str) -> tuple[str, int]:
        """Find teh brand with the smallest edit distance from the input."""
        best_brand = ""
        best_distance = float("inf")

        for brand in self.brands:
            distance = Levenshtein.distance(core, brand)
            if distance < best_distance:
                best_distance = distance
                best_brand = brand

        return best_brand, int(best_distance)