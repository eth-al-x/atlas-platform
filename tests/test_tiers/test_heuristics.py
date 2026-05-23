"""
Tests for the richer heuristics tier.

Covers each of the six signals individually plus interactions:
    1. Entropy (preserved)
    2. WHOIS age (preserved, mocked)
    3. Subdomain depth
    4. Consonant/vowel ratio
    5. Numeric ratio
    6. DGA pattern matching

Confidence is a weighted sum, so multiple signals firing should compound.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

import pytest

from atlas.core.config import AtlasConfig
from atlas.tiers.heuristics import HeuristicsTier, SIGNAL_WEIGHTS, DGA_PATTERNS


@pytest.fixture
def config():
    return AtlasConfig()


@pytest.fixture
def tier(config):
    return HeuristicsTier(config)


def _mock_whois(age_hours: float | None = None):
    """Build a context manager that mocks whois.whois to return a domain of given age."""
    info = MagicMock()
    if age_hours is None:
        info.creation_date = None
    else:
        info.creation_date = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    return patch("atlas.tiers.heuristics.whois.whois", return_value=info)


# ═══════════════════════════════════════════════════════════════
# Subdomain Depth
# ═══════════════════════════════════════════════════════════════


class TestSubdomainDepth:

    def test_apex_domain_not_deep(self, tier):
        result = tier._check_subdomain_depth("example.com", None)
        assert result["label_count"] == 2
        assert result["is_deep"] is False

    def test_typical_subdomain_not_deep(self, tier):
        result = tier._check_subdomain_depth("api.example.com", None)
        assert result["label_count"] == 3
        assert result["is_deep"] is False

    def test_four_labels_not_deep(self, tier):
        result = tier._check_subdomain_depth("a.b.example.com", None)
        assert result["label_count"] == 4
        assert result["is_deep"] is False

    def test_five_labels_is_deep(self, tier):
        result = tier._check_subdomain_depth("a.b.c.example.com", None)
        assert result["label_count"] == 5
        assert result["is_deep"] is True

    def test_uses_url_hostname_when_provided(self, tier):
        """If URL is given, use its hostname (not the post-extracted target)."""
        result = tier._check_subdomain_depth(
            "example.com",
            "https://a.b.c.d.example.com/path",
        )
        assert result["hostname"] == "a.b.c.d.example.com"
        assert result["label_count"] == 6
        assert result["is_deep"] is True

    def test_handles_url_without_scheme(self, tier):
        result = tier._check_subdomain_depth(
            "example.com",
            "a.b.c.d.example.com",
        )
        # urlparse needs scheme — code prepends "//" if missing
        assert result["label_count"] >= 5


# ═══════════════════════════════════════════════════════════════
# Consonant/Vowel Ratio
# ═══════════════════════════════════════════════════════════════


class TestConsonantVowelRatio:

    def test_normal_english_word_not_unusual(self, tier):
        result = tier._check_consonant_vowel_ratio("google.com")
        assert result["is_unusual"] is False

    def test_balanced_word_not_unusual(self, tier):
        result = tier._check_consonant_vowel_ratio("paypal.com")
        assert result["is_unusual"] is False

    def test_no_vowels_is_unusual(self, tier):
        """Core with all consonants is highly unusual."""
        result = tier._check_consonant_vowel_ratio("xkpqr.com")
        assert result["is_unusual"] is True
        assert result["vowels"] == 0

    def test_too_short_skipped(self, tier):
        """Short cores skip the check to avoid false positives."""
        result = tier._check_consonant_vowel_ratio("ibm.com")
        assert result["is_unusual"] is False

    def test_high_consonant_ratio_unusual(self, tier):
        """5:1+ consonant-to-vowel ratio is flagged."""
        # "bcdfgr" has 0 vowels = handled by no_vowels branch
        # "bcdfgra" has 6 consonants : 1 vowel = 6.0 ratio
        result = tier._check_consonant_vowel_ratio("bcdfgra.com")
        assert result["ratio"] == 6.0
        assert result["is_unusual"] is True


# ═══════════════════════════════════════════════════════════════
# Numeric Ratio
# ═══════════════════════════════════════════════════════════════


class TestNumericRatio:

    def test_no_digits_low_ratio(self, tier):
        result = tier._check_numeric_ratio("google.com")
        assert result["ratio"] == 0.0
        assert result["is_high"] is False

    def test_a_few_digits_not_high(self, tier):
        result = tier._check_numeric_ratio("shop24.com")
        # 2 digits out of 6 = 0.33 — right at threshold
        # The threshold is > 0.30 so 0.33 will trigger; let's test slightly less
        result = tier._check_numeric_ratio("shopxx7.com")
        assert result["is_high"] is False

    def test_mostly_digits_high(self, tier):
        result = tier._check_numeric_ratio("12345abc.com")
        # 5 digits out of 8 = 0.625
        assert result["is_high"] is True

    def test_all_digits_high(self, tier):
        result = tier._check_numeric_ratio("123456.com")
        assert result["ratio"] == 1.0
        assert result["is_high"] is True

    def test_short_high_ratio_not_flagged(self, tier):
        """A core too short to be meaningful won't be flagged even if mostly digits."""
        result = tier._check_numeric_ratio("12a.com")  # 3 chars
        assert result["is_high"] is False


# ═══════════════════════════════════════════════════════════════
# DGA Pattern Matching
# ═══════════════════════════════════════════════════════════════


class TestDGAPatterns:

    def test_normal_domain_no_matches(self, tier):
        result = tier._check_dga_patterns("google.com")
        assert result["is_dga_pattern"] is False
        assert result["matched_patterns"] == []

    def test_conficker_pattern_matched(self, tier):
        """12 lowercase letters with no digits matches conficker-style DGA."""
        result = tier._check_dga_patterns("xkpqrtnvmlwj.com")
        assert "conficker_like" in result["matched_patterns"]
        assert result["is_dga_pattern"] is True

    def test_long_hex_string_matched(self, tier):
        result = tier._check_dga_patterns("abcdef0123456789.com")
        assert "long_hex_string" in result["matched_patterns"]

    def test_hyphen_chain_matched(self, tier):
        result = tier._check_dga_patterns("a-b-c-d-e.com")
        assert "hyphen_chain" in result["matched_patterns"]

    def test_long_random_alpha_matched(self, tier):
        result = tier._check_dga_patterns("aaaabbbbccccddddxxxx.com")
        assert "long_random_alpha" in result["matched_patterns"]

    def test_short_domain_no_match(self, tier):
        """Conficker pattern requires 10+ chars."""
        result = tier._check_dga_patterns("short.com")
        assert result["is_dga_pattern"] is False


# ═══════════════════════════════════════════════════════════════
# Integration: weighted confidence
# ═══════════════════════════════════════════════════════════════


class TestWeightedConfidence:

    def test_clean_domain_not_flagged(self, tier):
        with _mock_whois(age_hours=365 * 24 * 5):  # 5 years old
            result = tier.check("google.com")
        assert result.flagged is False
        assert result.confidence == 0.0

    def test_single_weak_signal_low_confidence(self, tier):
        """A single weak signal (subdomain depth) gives low confidence."""
        with _mock_whois(age_hours=365 * 24 * 5):
            result = tier.check("example.com", url="https://a.b.c.d.example.com/")
        assert result.flagged is True
        # Only is_deep fires — weight 0.15
        assert result.confidence == pytest.approx(0.15, abs=0.001)

    def test_single_strong_signal_medium_confidence(self, tier):
        """Just a DGA pattern fires — weight 0.50."""
        with _mock_whois(age_hours=365 * 24 * 5):
            result = tier.check("xkpqrtnvmlwj.com")
        assert result.flagged is True
        # DGA pattern (0.50) + likely entropy (0.40) since 12 unique-ish chars
        assert result.confidence >= 0.50

    def test_multiple_signals_compound(self, tier):
        """Several signals firing together pushes toward high confidence."""
        # Mock as a brand new domain
        with _mock_whois(age_hours=12):  # very new
            result = tier.check(
                "xkpqrtnvmlwj.com",
                url="https://a.b.c.d.xkpqrtnvmlwj.com/",  # deep
            )
        assert result.flagged is True
        # is_new_domain (0.40) + is_dga_pattern (0.50) + is_deep (0.15) + likely entropy & vowel_unusual
        assert result.confidence >= 0.80

    def test_confidence_capped_at_1(self, tier):
        """When all signals fire, confidence should clamp to 1.0."""
        with _mock_whois(age_hours=1):
            # 16-char hex string covering hex pattern AND high entropy
            # with deep subdomain
            result = tier.check(
                "abcdef0123456789.com",
                url="https://a.b.c.d.e.abcdef0123456789.com/",
            )
        assert result.flagged is True
        assert result.confidence <= 1.0

    def test_signals_fired_list_populated(self, tier):
        with _mock_whois(age_hours=12):
            result = tier.check("xkpqrtnvmlwj.com")
        signals = result.details["signals_fired"]
        assert "is_new_domain" in signals
        assert isinstance(signals, list)

    def test_details_contain_all_six_subchecks(self, tier):
        """Every check should produce its detail block, even on a clean domain."""
        with _mock_whois(age_hours=365 * 24 * 5):
            result = tier.check("google.com")
        assert set(result.details.keys()) >= {
            "entropy", "age", "subdomain_depth",
            "consonant_vowel", "numeric", "dga_pattern", "signals_fired",
        }

    def test_signal_weights_sum_above_one(self):
        """Sanity: weights sum > 1 to allow single-signal verdicts but clamp on stacking."""
        assert sum(SIGNAL_WEIGHTS.values()) > 1.0

    def test_six_signals_defined(self):
        """All six signal weights should be present in the weights map."""
        assert len(SIGNAL_WEIGHTS) == 6


# ═══════════════════════════════════════════════════════════════
# Verdict integration with the new LOW_RISK band
# ═══════════════════════════════════════════════════════════════


class TestHeuristicsVerdictWiring:
    """The richer heuristics should slot into LOW/MEDIUM/HIGH_RISK cleanly."""

    def test_weak_signal_only_yields_low_risk_at_pipeline(self, tier):
        """A single subdomain-depth flag (0.15 confidence) should map to LOW_RISK."""
        from atlas.core.pipeline import _determine_verdict
        from atlas.core.models import Verdict

        with _mock_whois(age_hours=365 * 24 * 5):
            result = tier.check("example.com", url="https://a.b.c.d.example.com/")

        verdict = _determine_verdict([result])
        assert verdict == Verdict.LOW_RISK

    def test_two_strong_signals_yield_high_risk(self, tier):
        """Age + DGA pattern (0.40 + 0.50 = 0.90) should map to HIGH_RISK."""
        from atlas.core.pipeline import _determine_verdict
        from atlas.core.models import Verdict

        with _mock_whois(age_hours=12):  # new
            result = tier.check("xkpqrtnvmlwj.com")

        verdict = _determine_verdict([result])
        assert verdict == Verdict.HIGH_RISK
