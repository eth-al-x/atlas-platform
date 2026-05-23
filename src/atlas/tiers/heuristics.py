"""
atlas.tiers.heuristics
Tier 2: Evaluates structural signals that suggest a domain may be malicious.

Six checks (all pure local computation, no network except WHOIS):
    1. Shannon entropy of the domain name — high randomness suggests DGA generation.
    2. WHOIS registration age — very new domains are disproportionately used for attacks.
    3. Subdomain depth — many labels suggests DGA-based subdomain bursting.
    4. Consonant/vowel ratio — abnormal ratios suggest algorithmically-generated names.
    5. Numeric character ratio — high digit density in the core domain is unusual.
    6. Known DGA pattern matching — regex against fingerprints of historical malware
       families (Conficker, hex-strings, hyphen chains).

Confidence is a weighted sum of signal contributions rather than a simple
fraction — strong signals (entropy, age, DGA pattern) outweigh weak ones
(subdomain depth, vowel ratio). The score is clamped at 1.0.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier


logger = logging.getLogger(__name__)


# ── Signal weights ────────────────────────────────────────────
# Each signal's contribution to the overall confidence when it fires.
# Sum of all weights can exceed 1.0; the final confidence is clamped.
# Strong signals (entropy, age, exact DGA pattern) carry more weight
# than soft heuristics (vowel ratio, subdomain depth).

SIGNAL_WEIGHTS: dict[str, float] = {
    "is_dga_suspected":   0.40,   # Shannon entropy over the threshold
    "is_new_domain":      0.40,   # WHOIS age under the threshold
    "is_dga_pattern":     0.50,   # Matches a known DGA regex
    "vowel_unusual":      0.20,   # Abnormal consonant/vowel ratio
    "numeric_high":       0.15,   # >30% digits in the core
    "is_deep":            0.15,   # 5+ labels in the hostname
}


# ── DGA fingerprints ─────────────────────────────────────────
# Regex patterns matching the core name (TLD stripped) of known malware
# families' domain-generation algorithms.

DGA_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Conficker.C / .D — 10–16 lowercase letters, no digits, no hyphens
    (re.compile(r"^[a-z]{10,16}$"), "conficker_like"),
    # Long hex strings (16+ chars of 0-9a-f) — many ransomware C2 generators
    (re.compile(r"^[0-9a-f]{16,}$"), "long_hex_string"),
    # Excessive hyphen chains — 4+ hyphen-separated segments
    (re.compile(r"^([a-z0-9]+-){4,}[a-z0-9]+$"), "hyphen_chain"),
    # Pure-alpha 20+ char — Cryptolocker-style very long random names
    (re.compile(r"^[a-z]{20,}$"), "long_random_alpha"),
]


class HeuristicsTier(Tier):
    name = "heuristics"
    display_name = "Heuristic Analysis"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.entropy_threshold = config.analysis.entropy_threshold
        self.age_threshold_hours = config.analysis.age_threshold_hours

    def _check(self, target: str, **context: object) -> TierResult:
        raw_url = context.get("url")
        url = raw_url if isinstance(raw_url, str) else None

        entropy_result = self._calculate_entropy(target)
        age_result = self._check_domain_age(target)
        depth_result = self._check_subdomain_depth(target, url)
        vowel_result = self._check_consonant_vowel_ratio(target)
        numeric_result = self._check_numeric_ratio(target)
        dga_result = self._check_dga_patterns(target)

        # Collect which signals fired and compute weighted confidence
        signals_fired: dict[str, bool] = {
            "is_dga_suspected": entropy_result["is_dga_suspected"],
            "is_new_domain":    age_result["is_new_domain"],
            "is_dga_pattern":   dga_result["is_dga_pattern"],
            "vowel_unusual":    vowel_result["is_unusual"],
            "numeric_high":     numeric_result["is_high"],
            "is_deep":          depth_result["is_deep"],
        }

        is_suspicious = any(signals_fired.values())
        confidence = 0.0
        if is_suspicious:
            confidence = sum(
                SIGNAL_WEIGHTS[signal] for signal, fired in signals_fired.items() if fired
            )
            confidence = min(1.0, confidence)

        return TierResult(
            flagged=is_suspicious,
            confidence=round(confidence, 3),
            details={
                "entropy":          entropy_result,
                "age":              age_result,
                "subdomain_depth":  depth_result,
                "consonant_vowel":  vowel_result,
                "numeric":          numeric_result,
                "dga_pattern":      dga_result,
                "signals_fired":    [s for s, fired in signals_fired.items() if fired],
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

    # ── Subdomain depth ──────────────────────────────────────

    def _check_subdomain_depth(self, target: str, url: str | None) -> dict:
        """
        Count hostname labels. DGA-based malware and fast-flux infrastructure
        often use many sub-labels (a.b.c.d.example.com) to evade simple regex
        blocklists and to host short-lived C2 channels.

        Prefers the raw URL's hostname over the post-extracted domain since
        extract_domain() strips common subdomains like 'www' and 'mail'.
        """
        hostname = target
        if url:
            try:
                # urlparse needs a scheme to populate hostname reliably
                parsed = urlparse(url if "//" in url else "//" + url, scheme="http")
                if parsed.hostname:
                    hostname = parsed.hostname
            except Exception:
                pass

        labels = [lab for lab in hostname.split(".") if lab]
        label_count = len(labels)

        # 2 labels = apex (example.com). 3 = typical subdomain (api.example.com).
        # 5+ labels in the hostname is genuinely unusual for legitimate sites.
        is_deep = label_count >= 5
        return {
            "label_count": label_count,
            "hostname": hostname,
            "is_deep": is_deep,
        }

    # ── Consonant/vowel ratio ────────────────────────────────

    def _check_consonant_vowel_ratio(self, domain: str) -> dict:
        """
        English-derived domain names tend to have roughly 1.5–2x more consonants
        than vowels. DGA strings often have far higher consonant ratios or no
        vowels at all (compressed pseudo-random output).
        """
        core = domain.split(".")[0].lower()
        letters = [c for c in core if c.isalpha()]

        if len(letters) < 4:
            # Too short to meaningfully analyze
            return {"vowels": 0, "consonants": 0, "ratio": None, "is_unusual": False}

        vowels = sum(1 for c in letters if c in "aeiou")
        consonants = len(letters) - vowels

        # Two failure modes: ratio is huge, or there are no vowels at all
        if vowels == 0:
            return {
                "vowels": 0,
                "consonants": consonants,
                "ratio": None,
                "is_unusual": True,
                "reason": "no vowels in core",
            }

        ratio = consonants / vowels
        # >4:1 consonants-to-vowels is well outside English-language norms
        is_unusual = ratio > 4.0
        return {
            "vowels": vowels,
            "consonants": consonants,
            "ratio": round(ratio, 2),
            "is_unusual": is_unusual,
        }

    # ── Numeric ratio ────────────────────────────────────────

    def _check_numeric_ratio(self, domain: str) -> dict:
        """
        Heavy digit usage in the core domain is unusual for legitimate sites.
        Shop24.com and 7eleven.com have a few digits — DGA outputs often have
        the majority of characters be digits.
        """
        core = domain.split(".")[0]
        if not core:
            return {"digit_count": 0, "total_length": 0, "ratio": 0.0, "is_high": False}

        digits = sum(1 for c in core if c.isdigit())
        ratio = digits / len(core)

        # >30% digits in the core is the threshold — matches the cutoff used
        # by several published DGA classifiers.
        is_high = ratio > 0.30 and len(core) >= 5
        return {
            "digit_count": digits,
            "total_length": len(core),
            "ratio": round(ratio, 2),
            "is_high": is_high,
        }

    # ── DGA pattern matching ─────────────────────────────────

    def _check_dga_patterns(self, domain: str) -> dict:
        """
        Match the core domain against known DGA fingerprints.
        Each entry produces a labeled finding so analysts can identify which
        malware family the structure resembles.
        """
        core = domain.split(".")[0].lower()
        matched_patterns = [name for pat, name in DGA_PATTERNS if pat.match(core)]
        return {
            "matched_patterns": matched_patterns,
            "is_dga_pattern": bool(matched_patterns),
        }
