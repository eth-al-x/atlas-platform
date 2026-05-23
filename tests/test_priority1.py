"""
Tests for Priority 1 features:
    1. Recon result persistence (save + load from DB)
    2. Homoglyph detection in typosquat tier
    3. LOW_RISK verdict wiring

Run with: pytest tests/test_priority1.py -v
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone

import pytest

from atlas.core.config import AtlasConfig
from atlas.core.models import (
    CorrelationContext,
    ReconResult,
    ScanReport,
    ScanSource,
    TierResult,
    Verdict,
)
from atlas.core.pipeline import _determine_verdict
from atlas.storage.db import ScanRepository
from atlas.tiers.typosquat import TyposquatTier


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def config():
    return AtlasConfig()


@pytest.fixture
def db_repo(tmp_path):
    """Create a ScanRepository backed by a temp database."""
    db_path = str(tmp_path / "test_atlas.db")
    return ScanRepository(db_path=db_path)


@pytest.fixture
def sample_report():
    return ScanReport(
        url="https://example.com",
        domain="example.com",
        final_verdict=Verdict.CLEAN,
        tier_results=[
            TierResult(
                tier_name="local_blocklist",
                display_name="Local Blocklist",
                flagged=False,
                confidence=0.0,
            )
        ],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=100,
        source=ScanSource.CLI,
    )


@pytest.fixture
def sample_recon():
    return {
        "dns": ReconResult(
            recon_type="dns",
            domain="example.com",
            data={"records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]}},
        ),
        "whois": ReconResult(
            recon_type="whois",
            domain="example.com",
            data={
                "registrar": "Example Registrar",
                "creation_date": "2020-01-15T00:00:00+00:00",
                "age_days": 1950,
            },
        ),
        "http_headers": ReconResult(
            recon_type="http_headers",
            domain="example.com",
            data={"security_grade": "strong", "status_code": 200},
        ),
    }


# ═══════════════════════════════════════════════════════════════
# Feature 1: Recon Result Persistence
# ═══════════════════════════════════════════════════════════════


class TestReconPersistence:
    """Recon results should round-trip through the database."""

    def test_save_and_retrieve_recon_results(self, db_repo, sample_report, sample_recon):
        scan_id = db_repo.save_scan(sample_report)
        db_repo.save_recon_results(scan_id, sample_recon)

        loaded = db_repo.get_recon_results(scan_id)
        assert set(loaded.keys()) == {"dns", "whois", "http_headers"}

    def test_recon_data_preserved(self, db_repo, sample_report, sample_recon):
        scan_id = db_repo.save_scan(sample_report)
        db_repo.save_recon_results(scan_id, sample_recon)

        loaded = db_repo.get_recon_results(scan_id)
        assert loaded["dns"].data["records"]["A"] == ["93.184.216.34"]
        assert loaded["whois"].data["registrar"] == "Example Registrar"
        assert loaded["http_headers"].data["security_grade"] == "strong"

    def test_recon_domain_preserved(self, db_repo, sample_report, sample_recon):
        scan_id = db_repo.save_scan(sample_report)
        db_repo.save_recon_results(scan_id, sample_recon)

        loaded = db_repo.get_recon_results(scan_id)
        for rr in loaded.values():
            assert rr.domain == "example.com"

    def test_recon_error_preserved(self, db_repo, sample_report):
        recon = {
            "urlscan": ReconResult(
                recon_type="urlscan",
                domain="example.com",
                data={},
                error="API key missing",
            ),
        }
        scan_id = db_repo.save_scan(sample_report)
        db_repo.save_recon_results(scan_id, recon)

        loaded = db_repo.get_recon_results(scan_id)
        assert loaded["urlscan"].error == "API key missing"

    def test_empty_recon_returns_empty_dict(self, db_repo, sample_report):
        scan_id = db_repo.save_scan(sample_report)
        loaded = db_repo.get_recon_results(scan_id)
        assert loaded == {}

    def test_nonexistent_scan_returns_empty_dict(self, db_repo):
        loaded = db_repo.get_recon_results(99999)
        assert loaded == {}

    def test_correlate_uses_stored_recon(self, db_repo, sample_report, sample_recon):
        """After persisting recon, loading it into a CorrelationContext should work."""
        scan_id = db_repo.save_scan(sample_report)
        db_repo.save_recon_results(scan_id, sample_recon)

        loaded_report = db_repo.get_scan(scan_id)
        loaded_recon = db_repo.get_recon_results(scan_id)
        context = CorrelationContext(scan=loaded_report, recon=loaded_recon)

        assert context.recon.get("whois") is not None
        assert context.recon["whois"].data["registrar"] == "Example Registrar"


# ═══════════════════════════════════════════════════════════════
# Feature 2: Homoglyph Detection in Typosquat Tier
# ═══════════════════════════════════════════════════════════════


class TestHomoglyphDetection:
    """Typosquat tier should catch Unicode lookalike attacks."""

    def test_cyrillic_p_in_paypal_detected(self, config):
        """'рaypal.com' with Cyrillic р should be flagged."""
        tier = TyposquatTier(config)
        result = tier.check("\u0440aypal.com")  # Cyrillic р + aypal
        assert result.flagged is True
        assert result.details.get("homoglyph_attack") is True

    def test_cyrillic_paypal_max_confidence(self, config):
        """A homoglyph that normalizes to an exact brand match should have confidence 1.0."""
        tier = TyposquatTier(config)
        result = tier.check("\u0440aypal.com")
        assert result.confidence == 1.0

    def test_cyrillic_a_in_apple_detected(self, config):
        """'аpple.com' with Cyrillic а should be flagged."""
        tier = TyposquatTier(config)
        result = tier.check("\u0430pple.com")  # Cyrillic а + pple
        assert result.flagged is True
        assert result.details.get("homoglyph_attack") is True

    def test_greek_omicron_in_google_detected(self, config):
        """'gοοgle.com' with Greek omicrons should be flagged."""
        tier = TyposquatTier(config)
        result = tier.check("g\u03bf\u03bfgle.com")  # Greek ο ο
        assert result.flagged is True
        assert result.details.get("homoglyph_attack") is True

    def test_normalized_form_in_details(self, config):
        """The normalized form should appear in result details for transparency."""
        tier = TyposquatTier(config)
        result = tier.check("\u0440aypal.com")
        assert result.details.get("normalized") == "paypal"

    def test_pure_ascii_not_marked_as_homoglyph(self, config):
        """Standard ASCII typosquats should not be marked as homoglyph attacks."""
        tier = TyposquatTier(config)
        result = tier.check("paypall.com")  # ASCII double-l
        assert result.flagged is True
        assert result.details.get("homoglyph_attack") is False

    def test_real_brand_with_unicode_not_flagged(self, config):
        """If normalization produces exact match to brand, it flags as homoglyph."""
        tier = TyposquatTier(config)
        # Full Cyrillic "google" — normalizes to "google" exactly
        result = tier.check("g\u03bf\u03bfgle.com")
        # This should be flagged (it's a homoglyph attack, not the real google)
        assert result.flagged is True

    def test_normalize_handles_combining_marks(self, config):
        """Characters with diacritics (ṁ = m + combining dot) should normalize to base."""
        tier = TyposquatTier(config)
        normalized = tier._normalize_homoglyphs("ṁicrosoft")
        assert normalized == "microsoft"

    def test_normalize_idempotent_on_ascii(self, config):
        """Pure ASCII input should pass through unchanged."""
        tier = TyposquatTier(config)
        assert tier._normalize_homoglyphs("google") == "google"
        assert tier._normalize_homoglyphs("paypal") == "paypal"


# ═══════════════════════════════════════════════════════════════
# Feature 3: LOW_RISK Verdict Wiring
# ═══════════════════════════════════════════════════════════════


class TestLowRiskVerdict:
    """_determine_verdict should produce LOW_RISK for low-confidence flags."""

    def test_no_flags_returns_clean(self):
        results = [TierResult(tier_name="test", flagged=False)]
        assert _determine_verdict(results) == Verdict.CLEAN

    def test_high_confidence_flag_returns_high_risk(self):
        results = [TierResult(tier_name="vt", flagged=True, confidence=0.9)]
        assert _determine_verdict(results) == Verdict.HIGH_RISK

    def test_medium_confidence_flag_returns_medium_risk(self):
        results = [TierResult(tier_name="dnsbl", flagged=True, confidence=0.5)]
        assert _determine_verdict(results) == Verdict.MEDIUM_RISK

    def test_low_confidence_flag_returns_low_risk(self):
        """A flag with confidence < 0.4 should produce LOW_RISK, not MEDIUM_RISK."""
        results = [TierResult(tier_name="heuristics", flagged=True, confidence=0.3)]
        assert _determine_verdict(results) == Verdict.LOW_RISK

    def test_very_low_confidence_flag_returns_low_risk(self):
        results = [TierResult(tier_name="heuristics", flagged=True, confidence=0.1)]
        assert _determine_verdict(results) == Verdict.LOW_RISK

    def test_boundary_at_0_4_is_medium(self):
        """Confidence exactly 0.4 should be MEDIUM_RISK (>= 0.4)."""
        results = [TierResult(tier_name="test", flagged=True, confidence=0.4)]
        assert _determine_verdict(results) == Verdict.MEDIUM_RISK

    def test_boundary_at_0_8_is_high(self):
        """Confidence exactly 0.8 should be HIGH_RISK (>= 0.8)."""
        results = [TierResult(tier_name="test", flagged=True, confidence=0.8)]
        assert _determine_verdict(results) == Verdict.HIGH_RISK

    def test_mixed_confidences_highest_wins(self):
        """When multiple tiers flag, the highest-confidence tier determines verdict."""
        results = [
            TierResult(tier_name="heuristics", flagged=True, confidence=0.2),
            TierResult(tier_name="dnsbl", flagged=True, confidence=0.6),
        ]
        assert _determine_verdict(results) == Verdict.MEDIUM_RISK

    def test_empty_results_returns_clean(self):
        assert _determine_verdict([]) == Verdict.CLEAN

    def test_low_risk_stats_field_exists(self):
        """ScanStats model should have a low_risk field."""
        from atlas.core.models import ScanStats
        s = ScanStats(low_risk=5)
        assert s.low_risk == 5

    def test_low_risk_stored_and_retrieved(self, db_repo):
        """A LOW_RISK scan should persist and be retrievable."""
        report = ScanReport(
            url="https://sketchy.com",
            domain="sketchy.com",
            final_verdict=Verdict.LOW_RISK,
            tier_results=[
                TierResult(tier_name="heuristics", flagged=True, confidence=0.3)
            ],
            source=ScanSource.CLI,
        )
        scan_id = db_repo.save_scan(report)
        loaded = db_repo.get_scan(scan_id)
        assert loaded.final_verdict == Verdict.LOW_RISK
