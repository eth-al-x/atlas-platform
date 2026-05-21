"""
Tests for the subdomain enumeration recon tool.

Mocks the DNS resolver to simulate which hostnames resolve and which don't.
Monkeypatches the rate limiter's sleep so tests run instantly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from atlas.core.config import AtlasConfig
from atlas.recon.subdomains import SubdomainReconTool


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Don't actually wait for rate limiting during tests."""
    monkeypatch.setattr("atlas.recon.subdomains.time.sleep", lambda x: None)


@pytest.fixture
def tool():
    """Create a subdomain tool with default config."""
    return SubdomainReconTool(AtlasConfig())


@pytest.fixture
def small_wordlist(tmp_path):
    """Write a tiny wordlist for testing and return its path."""
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_text("www\napi\ndev\nstaging\n# this is a comment\n\nadmin\n")
    return wordlist


def _make_resolver_with_known_hosts(known_hosts: dict[str, list[str]]):
    """
    Build a fake resolver that returns IPs for hosts in known_hosts,
    raises NXDOMAIN for everything else.
    """
    def resolve(hostname, rtype):
        if hostname in known_hosts:
            answers = []
            for ip in known_hosts[hostname]:
                answer = MagicMock()
                answer.__str__ = lambda self, val=ip: val
                answers.append(answer)
            return answers
        raise dns.resolver.NXDOMAIN()

    fake_resolver = MagicMock()
    fake_resolver.resolve = MagicMock(side_effect=resolve)
    fake_resolver.timeout = 2.0
    fake_resolver.lifetime = 2.0
    return fake_resolver


class TestSubdomainReconTool:

    # ── Wordlist handling ────────────────────────────────────

    def test_wordlist_loaded(self, tool, small_wordlist):
        """The wordlist size should be reflected in the result data."""
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts({})):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        # 5 words after stripping the comment line and the blank
        assert result.data["wordlist_size"] == 5

    def test_wordlist_not_found(self, tool):
        """A missing wordlist should produce a clean error."""
        result = tool.run("example.com",
                          wordlist_path=Path("/nonexistent/wordlist.txt"))
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_default_wordlist_used_when_not_specified(self, tool):
        """Without an explicit wordlist, the built-in default is used."""
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts({})):
            result = tool.run("example.com")

        # Default wordlist should be loaded
        assert result.data["wordlist_size"] > 100
        assert "subdomains_top500.txt" in result.data["wordlist_path"]

    def test_wordlist_comments_skipped(self, tool, tmp_path):
        """Lines starting with # or blank should be ignored."""
        wl = tmp_path / "wl.txt"
        wl.write_text("# comment\n\nwww\n  \napi\n# another\n")

        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts({})):
            result = tool.run("example.com", wordlist_path=wl)

        # Only 'www' and 'api' should be loaded
        assert result.data["wordlist_size"] == 2

    # ── Discovery ────────────────────────────────────────────

    def test_resolving_subdomain_discovered(self, tool, small_wordlist):
        """A subdomain that resolves should be in the discovered list."""
        known = {
            "www.example.com": ["93.184.216.34"],
            "api.example.com": ["1.2.3.4"],
        }
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts(known)):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        hostnames = [d["hostname"] for d in result.data["discovered_subdomains"]]
        assert "www.example.com" in hostnames
        assert "api.example.com" in hostnames

    def test_nonexistent_subdomain_not_discovered(self, tool, small_wordlist):
        """NXDOMAIN responses should not produce false positives."""
        known = {"www.example.com": ["1.2.3.4"]}
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts(known)):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        hostnames = [d["hostname"] for d in result.data["discovered_subdomains"]]
        # api/dev/staging/admin should NOT be there
        assert "dev.example.com" not in hostnames
        assert "admin.example.com" not in hostnames
        # Only www resolved
        assert len(hostnames) == 1

    def test_ips_captured_per_subdomain(self, tool, small_wordlist):
        """Resolved IPs should be captured in the result."""
        known = {
            "www.example.com": ["93.184.216.34", "93.184.216.35"],
        }
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts(known)):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        www = next(d for d in result.data["discovered_subdomains"]
                   if d["hostname"] == "www.example.com")
        assert "93.184.216.34" in www["ips"]
        assert "93.184.216.35" in www["ips"]

    # ── Result metadata ──────────────────────────────────────

    def test_attempts_counted(self, tool, small_wordlist):
        """Total attempts should match the wordlist size."""
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts({})):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        assert result.data["attempts"] == 5  # wordlist has 5 entries

    def test_discovered_count_matches_list_length(self, tool, small_wordlist):
        """discovered_count should match the length of discovered_subdomains."""
        known = {
            "www.example.com": ["1.1.1.1"],
            "api.example.com": ["2.2.2.2"],
        }
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts(known)):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        assert result.data["discovered_count"] == \
               len(result.data["discovered_subdomains"]) == 2

    def test_results_sorted_alphabetically(self, tool, small_wordlist):
        """Discovered subdomains should come back sorted for stable output."""
        known = {
            "www.example.com": ["1.1.1.1"],
            "api.example.com": ["2.2.2.2"],
            "admin.example.com": ["3.3.3.3"],
        }
        with patch("atlas.recon.subdomains.dns.resolver.Resolver",
                   return_value=_make_resolver_with_known_hosts(known)):
            result = tool.run("example.com", wordlist_path=small_wordlist)

        hostnames = [d["hostname"] for d in result.data["discovered_subdomains"]]
        assert hostnames == sorted(hostnames)


class TestAcknowledgement:
    """Tests for the one-time warning marker file logic."""

    def test_ack_check_returns_false_when_missing(self, tmp_path, monkeypatch):
        """When the marker file doesn't exist, ensure_acknowledged returns False."""
        from atlas.recon import subdomains

        monkeypatch.setattr(subdomains, "ACK_FILE", tmp_path / "marker")
        assert subdomains.ensure_acknowledged() is False

    def test_ack_check_returns_true_after_marking(self, tmp_path, monkeypatch):
        """After mark_acknowledged() is called, ensure_acknowledged returns True."""
        from atlas.recon import subdomains

        marker = tmp_path / "marker"
        monkeypatch.setattr(subdomains, "ACK_FILE", marker)

        assert subdomains.ensure_acknowledged() is False
        subdomains.mark_acknowledged()
        assert subdomains.ensure_acknowledged() is True

    def test_ack_creates_parent_directory(self, tmp_path, monkeypatch):
        """mark_acknowledged should create the parent directory if missing."""
        from atlas.recon import subdomains

        marker = tmp_path / "nonexistent_dir" / "marker"
        monkeypatch.setattr(subdomains, "ACK_FILE", marker)

        subdomains.mark_acknowledged()
        assert marker.exists()
