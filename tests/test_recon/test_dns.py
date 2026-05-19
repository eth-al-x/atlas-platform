"""
Tests for the DNS recon tool.

Uses unittest.mock to patch the dnspython resolver so tests don't
hit real DNS servers (faster, deterministic, works offline).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from atlas.core.config import AtlasConfig
from atlas.recon.dns import DNSReconTool

@pytest.fixture
def tool():
    """Create a DNS recon tool with default config."""
    return DNSReconTool(AtlasConfig())


def _make_a_answer(ip: str):
    """Build a fake dnspython answer object for an A record."""
    answer = MagicMock()
    answer.to_text.return_value = ip
    return answer


def _make_mx_answer(preference: int, exchange: str):
    """Build a fake MX answer."""
    answer = MagicMock()
    answer.preference = preference
    answer.exchange.to_text.return_value = exchange
    return answer


def _make_txt_answer(text: str):
    """Build a fake TXT answer (TXT records have .strings as list of bytes)."""
    answer = MagicMock()
    answer.strings = [text.encode()]
    return answer


class TestDNSReconTool:

    # --- Successful queries --------------------------------------
    def test_resolves_a_record(self, tool):
        """A successful A-record lookup should return the IP in the records dict."""
        def fake_resolve(domain, rtype):
            if rtype == "A":
                return [_make_a_answer("93.184.216.34")]
            raise dns.resolver.NoAnswer()

        with patch.object(tool.resolver, "resolve", side_effect=fake_resolve):
            result = tool.run("example.com")

        assert result.error is None
        assert result.data["records"]["A"] == ["93.184.216.34"]

    def test_resolves_mx_records_with_preference(self, tool):
        """MX records should be formatted as 'preference exchange'."""
        def fake_resolve(domain, rtype):
            if rtype == "MX":
                return [
                    _make_mx_answer(10, "mail1.example.com."),
                    _make_mx_answer(20, "mail2.example.com."),
                ]
            raise dns.resolver.NoAnswer()

        with patch.object(tool.resolver, "resolve", side_effect=fake_resolve):
            result = tool.run("example.com")

        mx_records = result.data["records"]["MX"]
        assert "10 mail1.example.com." in mx_records
        assert "20 mail2.example.com." in mx_records

    def test_resolves_txt_records(self, tool):
        """TXT records should be decoded from bytes to strings."""
        def fake_resolve(domain, rtype):
            if rtype == "TXT":
                return [_make_txt_answer("v=spf1 -all")]
            raise dns.resolver.NoAnswer()

        with patch.object(tool.resolver, "resolve", side_effect=fake_resolve):
            result = tool.run("example.com")

        assert "v=spf1 -all" in result.data["records"]["TXT"]

    def test_total_records_counts_correctly(self, tool):
        """The total_records summary should sum across all record types."""
        def fake_resolve(domain, rtype):
            if rtype == "A":
                return [_make_a_answer("1.2.3.4"), _make_a_answer("5.6.7.8")]
            if rtype == "MX":
                return [_make_mx_answer(10, "mx.example.com")]
            raise dns.resolver.NoAnswer()

        with patch.object(tool.resolver, "resolve", side_effect=fake_resolve):
            result = tool.run("example.com")

        # 2 A records + 1 MX = 3
        assert result.data["total_records"] == 3

    # --- Failure Handling ----------------------------------------

    def test_nxdomain_marked_per_record_type(self, tool):
        """NXDOMAIN should be captured as an error per record type."""
        with patch.object(tool.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = tool.run("nonexistent-domain-xyz.invalid")

        # Each record type should report the domain doesn't exist
        for rtype in ("A", "MX", "TXT"):
            entry = result.data["records"][rtype]
            assert isinstance(entry, dict)
            assert "error" in entry

    def test_no_answer_returns_empty_list(self, tool):
        """A NoAnswer (domain exists but no record of this type) returns empty list."""
        with patch.object(tool.resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = tool.run("example.com")

        assert result.data["records"]["A"] == []

    def test_timeout_captured_as_error(self, tool):
        """A timeout on one record type shouldn't crash the entire lookup."""
        with patch.object(tool.resolver, "resolve", side_effect=dns.resolver.Timeout()):
            result = tool.run("example.com")

        entry = result.data["records"]["A"]
        assert isinstance(entry, dict)
        assert entry["error"] == "query timed out"

    # --- Result Metadata --------------------------------------------

    def test_result_has_recon_type_set(self, tool):
        """The base class should set recon_type on the result automatically."""
        with patch.object(tool.resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = tool.run("example.com")

        assert result.recon_type == "dns"

    def test_result_has_domain_set(self, tool):
        """The base class should set domain on the result automatically."""
        with patch.object(tool.resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = tool.run("example.com")

        assert result.domain == "example.com"

    def test_result_has_duration(self, tool):
        """The base class should record execution time."""
        with patch.object(tool.resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = tool.run("example.com")

        assert "_duration_ms" in result.data
        assert result.data["_duration_ms"] >= 0