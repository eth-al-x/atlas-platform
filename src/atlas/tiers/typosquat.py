"""
atlas.tiers.typosquat
Tier: Detects domains that are visually or textually similar to high-value brands or TLDs.

Catches typosquatting attacks (e.g. paypa1.com, g00gle.com, microsof.com) where
attackers register lookalike domains to harvest credentials from users of legitimate domains
who mistype the real address.

Also catches Unicode homoglyph attacks (e.g. рaypal.com using Cyrillic 'р') by
normalizing confusable characters before comparison.

Uses Levenshtein edit distance via rapidfuzz - distance 1 means one character change,
distance 2 means two changes, and so on. Tunable per-brand threshold via config.
"""

from __future__ import annotations

import logging
import unicodedata

from rapidfuzz.distance import Levenshtein

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier


logger = logging.getLogger(__name__)


# ── Unicode confusable mapping ────────────────────────────────
# Maps visually similar Unicode characters to their ASCII equivalents.
# Covers the most common homoglyph substitutions used in phishing.
# Sourced from Unicode TR39 confusables + observed attack patterns.

CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0443": "y",  # у → y
    "\u0445": "x",  # х → x
    "\u043a": "k",  # к → k
    "\u0456": "i",  # і → i  (Ukrainian)
    "\u0458": "j",  # ј → j  (Serbian)
    "\u04bb": "h",  # һ → h  (Bashkir)
    "\u0455": "s",  # ѕ → s  (Macedonian)
    "\u0475": "v",  # ѵ → v
    "\u043d": "h",  # н (visually similar in some fonts)
    "\u0442": "t",  # т → t  (italic Cyrillic т looks like t)
    # Greek → Latin
    "\u03b1": "a",  # α → a
    "\u03bf": "o",  # ο → o
    "\u03c1": "p",  # ρ → p
    "\u03c4": "t",  # τ → t
    "\u03b5": "e",  # ε → e
    "\u03b9": "i",  # ι → i
    "\u03ba": "k",  # κ → k
    "\u03bd": "v",  # ν → v
    # Common substitutions
    "\u0131": "i",  # ı (dotless i) → i
    "\u1d00": "a",  # ᴀ (small cap A)
    "\u0261": "g",  # ɡ → g
    "\u029c": "h",  # ʜ → h
    "\u1e41": "m",  # ṁ → m  (Latin m with dot above)
    "\u1e43": "m",  # ṃ → m
    "\u1e45": "n",  # ṅ → n
    "\u1e63": "s",  # ṣ → s
    "\u1e6d": "t",  # ṭ → t
    "\u0127": "h",  # ħ → h
    "\u0111": "d",  # đ → d
    "\u0142": "l",  # ł → l
    "\u00f8": "o",  # ø → o
    "\u00e6": "ae", # æ → ae
    "\u00df": "ss", # ß → ss
    # Digit lookalikes
    "\u01c3": "!",  # ǃ (click) → !
    "\uff11": "1",  # １ (fullwidth 1)
    "\uff10": "0",  # ０ (fullwidth 0)
}


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
        normalized = self._normalize_homoglyphs(core)
        is_homoglyph = normalized != core

        # Skip very short domains - too noisy
        if len(normalized) < self.MIN_CORE_LENGTH:
            return TierResult(
                flagged=False,
                details={"core": core, "normalized": normalized, "skipped": "domain too short"},
            )

        # Exact match to a brand is not typosquatting - it's the real domain
        # BUT: if the original core differs from normalized, it's a homoglyph attack
        if normalized in self.brands:
            if is_homoglyph:
                # This is a homoglyph attack — e.g. "рaypal" (Cyrillic р) normalizes to "paypal"
                return TierResult(
                    flagged=True,
                    confidence=1.0,
                    details={
                        "core": core,
                        "normalized": normalized,
                        "closest_brand": normalized,
                        "edit_distance": 0,
                        "max_distance": self.MAX_DISTANCE,
                        "homoglyph_attack": True,
                    },
                )
            return TierResult(
                flagged=False,
                details={
                    "core": core,
                    "normalized": normalized,
                    "matched_brand": normalized,
                    "exact_match": True,
                    "homoglyph_attack": False,
                },
            )

        # Find the closest brand by edit distance (using normalized form)
        closest_brand, distance = self._closest_brand(normalized)

        if distance <= self.MAX_DISTANCE:
            # Confidence is higher when distance is smaller (1 char off = stronger signal)
            confidence = 1.0 - (distance / (self.MAX_DISTANCE + 1))
            # Homoglyph attacks that normalize to exact match are highest confidence
            if is_homoglyph and distance == 0:
                confidence = 1.0
            return TierResult(
                flagged=True,
                confidence=confidence,
                details={
                    "core": core,
                    "normalized": normalized,
                    "closest_brand": closest_brand,
                    "edit_distance": distance,
                    "max_distance": self.MAX_DISTANCE,
                    "homoglyph_attack": is_homoglyph,
                }
            )

        return TierResult(
            flagged=False,
            details={
                "core": core,
                "normalized": normalized,
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

    @staticmethod
    def _normalize_homoglyphs(core: str) -> str:
        """
        Normalize Unicode homoglyphs to their ASCII equivalents.

        Three-step process:
        1. NFKD decomposition (catches accented characters like ṁ → m + combining dot)
        2. Explicit confusable mapping (catches Cyrillic/Greek lookalikes)
        3. Strip any remaining non-ASCII characters

        This lets 'рaypal' (Cyrillic р) normalize to 'paypal' for accurate
        edit-distance comparison against brand names.
        """
        # Step 1: NFKD normalization — decomposes characters like ṁ → m + ◌̇
        decomposed = unicodedata.normalize("NFKD", core)

        # Step 2: Apply confusable mapping char by char
        mapped = []
        for char in decomposed:
            if char in CONFUSABLE_MAP:
                mapped.append(CONFUSABLE_MAP[char])
            elif unicodedata.category(char).startswith("M"):
                # Skip combining marks (diacritics left from NFKD decomposition)
                continue
            else:
                mapped.append(char)
        result = "".join(mapped)

        # Step 3: Strip anything still non-ASCII (safety net)
        result = result.encode("ascii", errors="ignore").decode("ascii")

        return result.lower()

    def _closest_brand(self, core: str) -> tuple[str, int]:
        """Find the brand with the smallest edit distance from the input."""
        best_brand = ""
        best_distance = float("inf")

        for brand in self.brands:
            distance = Levenshtein.distance(core, brand)
            if distance < best_distance:
                best_distance = distance
                best_brand = brand

        return best_brand, int(best_distance)