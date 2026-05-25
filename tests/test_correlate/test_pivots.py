"""
Tests for the shared pivot extraction module.

Locks in the contract that both the cross-scan correlator and the graph
endpoint rely on — these are the canonical extractions for ATLAS's
infrastructure-pivot signals.
"""

from __future__ import annotations

import pytest

from atlas.correlate import pivots
from atlas.core.models import ReconResult


# ── Builders ──────────────────────────────────────────────────


def _recon(**kwargs) -> dict[str, ReconResult]:
    """Build a recon dict from per-tool data."""
    out: dict[str, ReconResult] = {}
    if "ip_intel" in kwargs:
        out["ip_intel"] = ReconResult(
            recon_type="ip_intel", domain="x", data=kwargs["ip_intel"],
        )
    if "ip_intel_error" in kwargs:
        out["ip_intel"] = ReconResult(
            recon_type="ip_intel", domain="x", data={}, error=kwargs["ip_intel_error"],
        )
    if "whois" in kwargs:
        out["whois"] = ReconResult(
            recon_type="whois", domain="x", data=kwargs["whois"],
        )
    if "web_recon" in kwargs:
        out["web_recon"] = ReconResult(
            recon_type="web_recon", domain="x", data=kwargs["web_recon"],
        )
    return out


# ── extract_ip ────────────────────────────────────────────────


class TestExtractIP:

    def test_extracts_valid_ipv4(self):
        recon = _recon(ip_intel={"ip": "1.2.3.4"})
        assert pivots.extract_ip(recon) == "1.2.3.4"

    def test_returns_none_when_ip_intel_missing(self):
        assert pivots.extract_ip({}) is None

    def test_returns_none_when_ip_intel_errored(self):
        recon = _recon(ip_intel_error="resolution failed")
        assert pivots.extract_ip(recon) is None

    def test_returns_none_for_empty_string(self):
        recon = _recon(ip_intel={"ip": ""})
        assert pivots.extract_ip(recon) is None

    def test_returns_none_for_non_string_value(self):
        recon = _recon(ip_intel={"ip": 12345})
        assert pivots.extract_ip(recon) is None


# ── extract_asn ───────────────────────────────────────────────


class TestExtractASN:

    def test_extracts_asn_from_geolocation(self):
        recon = _recon(ip_intel={
            "ip": "1.2.3.4",
            "geolocation": {"asn": "AS12345"},
        })
        assert pivots.extract_asn(recon) == "AS12345"

    def test_returns_none_when_no_geolocation(self):
        recon = _recon(ip_intel={"ip": "1.2.3.4"})
        assert pivots.extract_asn(recon) is None

    def test_returns_none_for_empty_asn(self):
        recon = _recon(ip_intel={"geolocation": {"asn": ""}})
        assert pivots.extract_asn(recon) is None

    def test_returns_none_when_ip_intel_errored(self):
        recon = _recon(ip_intel_error="failed")
        assert pivots.extract_asn(recon) is None


# ── extract_registrar ─────────────────────────────────────────


class TestExtractRegistrar:

    def test_extracts_registrar(self):
        recon = _recon(whois={"registrar": "Example Registrar LLC"})
        assert pivots.extract_registrar(recon) == "Example Registrar LLC"

    def test_returns_none_when_no_whois(self):
        assert pivots.extract_registrar({}) is None

    def test_returns_none_for_empty_registrar(self):
        recon = _recon(whois={"registrar": ""})
        assert pivots.extract_registrar(recon) is None


# ── extract_favicon_hash ──────────────────────────────────────


class TestExtractFaviconHash:

    def test_extracts_int_hash(self):
        recon = _recon(web_recon={"favicon": {"mmh3_hash": 1234567890}})
        assert pivots.extract_favicon_hash(recon) == 1234567890

    def test_returns_none_when_no_web_recon(self):
        assert pivots.extract_favicon_hash({}) is None

    def test_returns_none_when_favicon_errored(self):
        recon = _recon(web_recon={"favicon": {"error": "404"}})
        assert pivots.extract_favicon_hash(recon) is None

    def test_returns_none_when_favicon_missing(self):
        recon = _recon(web_recon={"title": "example"})
        assert pivots.extract_favicon_hash(recon) is None

    def test_returns_none_for_non_int_hash(self):
        recon = _recon(web_recon={"favicon": {"mmh3_hash": "not an int"}})
        assert pivots.extract_favicon_hash(recon) is None

    def test_returns_none_when_favicon_is_not_a_dict(self):
        recon = _recon(web_recon={"favicon": None})
        assert pivots.extract_favicon_hash(recon) is None


# ── slash24_prefix ────────────────────────────────────────────


class TestSlash24:

    @pytest.mark.parametrize("ip,expected", [
        ("1.2.3.4", "1.2.3"),
        ("10.0.0.1", "10.0.0"),
        ("192.168.1.255", "192.168.1"),
    ])
    def test_valid_ipv4_addresses(self, ip, expected):
        assert pivots.slash24_prefix(ip) == expected

    @pytest.mark.parametrize("ip", [
        None,
        "",
        "not an ip",
        "1.2.3",          # too short
        "1.2.3.4.5",      # too long
        "1.2.3.256",      # invalid octet
        "-1.2.3.4",       # negative
        "2001:db8::1",    # IPv6
        "1.2.3.a",        # non-numeric
    ])
    def test_invalid_inputs_return_none(self, ip):
        assert pivots.slash24_prefix(ip) is None


# ── extract_all ───────────────────────────────────────────────


class TestExtractAll:

    def test_returns_full_dict_when_everything_present(self):
        recon = _recon(
            ip_intel={
                "ip": "1.2.3.4",
                "geolocation": {"asn": "AS12345"},
            },
            whois={"registrar": "Example"},
            web_recon={"favicon": {"mmh3_hash": 42}},
        )
        result = pivots.extract_all(recon)
        assert result == {
            "ip": "1.2.3.4",
            "asn": "AS12345",
            "registrar": "Example",
            "favicon_hash": 42,
            "slash24": "1.2.3",
        }

    def test_returns_all_none_for_empty_recon(self):
        result = pivots.extract_all({})
        assert all(v is None for v in result.values())

    def test_slash24_follows_ip(self):
        """If IP is None, slash24 should be None too."""
        recon = _recon(whois={"registrar": "Example"})
        result = pivots.extract_all(recon)
        assert result["ip"] is None
        assert result["slash24"] is None
        assert result["registrar"] == "Example"
