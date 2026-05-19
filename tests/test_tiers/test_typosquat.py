"""
Tests for the typosquat tier.
Pure computation, no mocking needed - just feed in domains and check verdicts.
"""

import pytest

from atlas.core.config import AtlasConfig
from atlas.tiers.typosquat import TyposquatTier

@pytest.fixture
def tier():
    """Create a typosquat tier with the default brand list."""
    return TyposquatTier(AtlasConfig())

class TestTyposquatTier:

    # --- Exact matches should pass ----------------------
    def test_exact_brand_not_flagged(self, tier):
        """The real google.com shouldn't be flagged as a Google typosquat."""
        result = tier.check("google.com")
        assert result.flagged is False
        assert result.details.get("exact_match") is True

    def test_real_paypal_not_flagged(self, tier):
        result = tier.check("paypal.com")
        assert result.flagged is False

    # --- Common typosquats should be flagged -------------

    def test_off_by_one_typo_flagged(self, tier):
        """gogle.com (missing one 'o') should be flagged as Google typosquat."""
        result = tier.check("gogle.com")
        assert result.flagged is True
        assert result.details["closest_brand"] == "google"
        assert result.details["edit_distance"] == 1

    def test_character_swap_flagged(self, tier):
        """paypa1 (digit 1 instead of letter l) should be flagged."""
        result = tier.check("paypa1.com")
        assert result.flagged is True
        assert result.details["closest_brand"] == "paypal"

    def test_double_letter_attack_flagged(self, tier):
        """gooogle.com (extra '0') should be flagged."""
        result = tier.check("gooogle.com")
        assert result.flagged is True
        assert result.details["closest_brand"] == "google"

    # --- Unrelated domains should pass ------------------

    def test_unrelated_domain_not_flagged(self, tier):
        """A random unrelated domain shouldn't trigger any brand match."""
        result = tier.check("xyznetworkservices.com")
        assert result.flagged is False

    def test_long_domain_not_flagged(self, tier):
        """A long unrelated domain shouldn't false-positive."""
        result = tier.check("mybusinesswebsite.com")
        assert result.flagged is False

    # --- Edge Cases ----------------------------------

    def test_short_domain_skipped(self, tier):
        """Very short domains are skipped to avoid noise."""
        result = tier.check("ab.com")
        assert result.flagged is False
        assert "too short" in result.details.get("skipped", "")

    def test_confidence_higher_for_closer_match(self, tier):
        """A distance-1 match should have higher confidence than distance 2."""
        # Distance 1
        result_close = tier.check("gogle.com")
        # Distance 2
        result_far = tier.check("googel.com") # 'el' swapped for 'le' - distance 2

        assert result_close.confidence > result_far.confidence

    def test_details_include_closest_brand_even_when_clean(self, tier):
        """Even clean verdicts should report what the closest brand was."""
        result = tier.check("unrelatedsite.com")
        assert "closest_brand" in result.details
        assert "edit_distance" in result.details