"""
Tests for the WHOIS recon tool.
Uses unittest.mock to patch the whois module so tests don't hit real registries.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from atlas.core.config import AtlasConfig
from atlas.recon.whois_lookup import WhoisReconTool


@pytest.fixture
def tool():
    """Create a WHOIS recon tool with default config."""
    return WhoisReconTool(AtlasConfig())


def _fake_whois_record(**fields) -> SimpleNamespace:
    """Build a fake WHOIS record with the given fields."""
    # Sensible defaults so most tests don't need to set every field
    defaults = {
        "registrar": "Test Registrar Inc.",
        "creation_date": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "expiration_date": datetime(2030, 1, 1, tzinfo=timezone.utc),
        "updated_date": datetime(2023, 6, 1, tzinfo=timezone.utc),
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "org": "Example Org",
        "country": "US",
        "status": ["clientTransferProhibited"],
    }
    defaults.update(fields)
    return SimpleNamespace(**defaults)


class TestWhoisReconTool:

    # ── Basic field extraction ───────────────────────────────

    def test_extracts_registrar(self, tool):
        """Registrar should be in the result data."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record()):
            result = tool.run("example.com")

        assert result.data["registrar"] == "Test Registrar Inc."

    def test_extracts_registrant_org(self, tool):
        """Registrant organization should appear when present."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(org="Specific Company LLC")):
            result = tool.run("example.com")

        assert result.data["registrant_org"] == "Specific Company LLC"

    def test_extracts_name_servers_sorted_lowercase(self, tool):
        """Name servers should be normalized to lowercase and deduplicated."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(
                       name_servers=["NS2.EXAMPLE.COM", "ns1.example.com", "NS1.EXAMPLE.COM"]
                   )):
            result = tool.run("example.com")

        assert result.data["name_servers"] == ["ns1.example.com", "ns2.example.com"]

    # ── Date handling ────────────────────────────────────────

    def test_creation_date_as_iso(self, tool):
        """Creation date should be serialized as ISO format string."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record()):
            result = tool.run("example.com")

        assert result.data["creation_date"].startswith("2020-01-01")

    def test_handles_list_of_dates(self, tool):
        """When WHOIS returns a list of dates (some TLDs do), use the first one."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(
                       creation_date=[
                           datetime(2018, 5, 1, tzinfo=timezone.utc),
                           datetime(2019, 5, 1, tzinfo=timezone.utc),
                       ]
                   )):
            result = tool.run("example.com")

        assert result.data["creation_date"].startswith("2018-05-01")

    def test_naive_datetime_made_timezone_aware(self, tool):
        """Dates without timezone should be treated as UTC, not crash."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(
                       creation_date=datetime(2020, 1, 1)  # No tzinfo
                   )):
            result = tool.run("example.com")

        # Should not crash and should produce a sensible age
        assert result.data["age_days"] is not None
        assert result.data["age_days"] > 0

    # ── Age and expiry computation ───────────────────────────

    def test_age_days_computed(self, tool):
        """Age in days should be a positive integer for domains in the past."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record()):
            result = tool.run("example.com")

        # Created 2020-01-01, should be at least a few years old
        assert result.data["age_days"] is not None
        assert result.data["age_days"] > 365 * 3

    def test_age_years_computed(self, tool):
        """Age in years should be a sensible float."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record()):
            result = tool.run("example.com")

        assert result.data["age_years"] is not None
        assert result.data["age_years"] > 3

    # ── Status computation ───────────────────────────────────

    def test_status_active_for_future_expiry(self, tool):
        """Future expiration far away should be 'active'."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record()):
            result = tool.run("example.com")

        assert result.data["status"] == "active"

    def test_status_expiring_soon(self, tool):
        """Expiration within 30 days should be 'expiring soon'."""
        soon = datetime.now(timezone.utc) + timedelta(days=15)
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(expiration_date=soon)):
            result = tool.run("example.com")

        assert result.data["status"] == "expiring soon"

    def test_status_expired_for_past_expiry(self, tool):
        """Expiration in the past should be 'expired'."""
        past = datetime.now(timezone.utc) - timedelta(days=10)
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(expiration_date=past)):
            result = tool.run("example.com")

        assert result.data["status"] == "expired"

    def test_status_unknown_when_no_expiry(self, tool):
        """No expiry date should produce 'unknown' status."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   return_value=_fake_whois_record(expiration_date=None)):
            result = tool.run("example.com")

        assert result.data["status"] == "unknown"

    # ── Error handling ──────────────────────────────────────

    def test_whois_failure_captured(self, tool):
        """If python-whois raises, the result should have an error message."""
        with patch("atlas.recon.whois_lookup.whois.whois",
                   side_effect=Exception("WHOIS server unreachable")):
            result = tool.run("example.com")

        assert result.error is not None
        assert "unreachable" in result.error
