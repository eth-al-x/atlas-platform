"""
Tests for the JARM recon tool.

The JARM library does real TLS handshakes, so all tests mock
`Scanner.scan` at the boundary. No live network in the test suite.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from atlas.core.config import AtlasConfig
from atlas.recon.jarm import JARM_NO_TLS_HASH, JarmReconTool


@pytest.fixture
def tool():
    return JarmReconTool(AtlasConfig())


# Realistic-looking JARM hashes for tests. JARM hashes are exactly 62 chars.
JARM_HASH_A = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b093f91533"
JARM_HASH_B = "29d29d20d29d29d21c41d20d41d20d6b3b7e3a9c8a8e1f5d0e8e4d4f3c2b1a"


# ── Successful scans ──────────────────────────────────────────


class TestJarmScanSuccess:

    def test_returns_jarm_hash_on_success(self, tool):
        """A successful scan should return the hash in data."""
        with patch(
            "jarm.scanner.scanner.Scanner.scan",
            return_value=(JARM_HASH_A, "example.com", 443),
        ):
            result = tool.run("example.com")

        assert result.error is None
        assert result.data["jarm_hash"] == JARM_HASH_A
        assert result.data["tls_available"] is True
        assert result.data["host"] == "example.com"
        assert result.data["port"] == 443

    def test_recon_type_set(self, tool):
        with patch(
            "jarm.scanner.scanner.Scanner.scan",
            return_value=(JARM_HASH_A, "example.com", 443),
        ):
            result = tool.run("example.com")
        assert result.recon_type == "jarm"

    def test_duration_recorded(self, tool):
        with patch(
            "jarm.scanner.scanner.Scanner.scan",
            return_value=(JARM_HASH_A, "example.com", 443),
        ):
            result = tool.run("example.com")
        assert "_duration_ms" in result.data


# ── No-TLS / handshake-failure handling ───────────────────────


class TestJarmNoTls:

    def test_all_zeros_hash_marked_as_no_tls(self, tool):
        """The all-zeros sentinel should not be stored as a valid pivot."""
        with patch(
            "jarm.scanner.scanner.Scanner.scan",
            return_value=(JARM_NO_TLS_HASH, "example.com", 443),
        ):
            result = tool.run("example.com")

        assert result.error is None
        assert result.data["jarm_hash"] is None
        assert result.data["tls_available"] is False
        assert "note" in result.data
        assert "no tls" in result.data["note"].lower()

    def test_no_tls_does_not_set_jarm_hash(self, tool):
        """Confirm we never write the zero-hash to the jarm_hash field."""
        with patch(
            "jarm.scanner.scanner.Scanner.scan",
            return_value=(JARM_NO_TLS_HASH, "example.com", 443),
        ):
            result = tool.run("example.com")
        assert result.data.get("jarm_hash") != JARM_NO_TLS_HASH


# ── Error handling ────────────────────────────────────────────


class TestJarmErrors:

    def test_library_exception_is_captured(self, tool):
        """An exception from Scanner.scan should not propagate."""
        with patch(
            "jarm.scanner.scanner.Scanner.scan",
            side_effect=OSError("network unreachable"),
        ):
            result = tool.run("example.com")

        # The base class also has try/except, so the result might land
        # in either result.error or data["jarm_hash"] = None
        assert result.data["jarm_hash"] is None
        assert result.data["tls_available"] is False

    def test_import_error_returns_error_status(self, tool):
        """If jarm package is missing, we should report it cleanly."""
        # Simulate ImportError by patching the lazy import path.
        # We can't easily patch the import statement itself, so we patch
        # sys.modules to make the import fail.
        import sys
        original = sys.modules.get("jarm.scanner.scanner")
        sys.modules["jarm.scanner.scanner"] = None
        try:
            result = tool.run("example.com")
            assert result.data["tls_available"] is False
            assert result.data["jarm_hash"] is None
        finally:
            if original is not None:
                sys.modules["jarm.scanner.scanner"] = original
            else:
                sys.modules.pop("jarm.scanner.scanner", None)


# ── Configuration ─────────────────────────────────────────────


class TestJarmConfig:

    def test_default_port_is_443(self, tool):
        assert tool.port == 443

    def test_custom_port_used_in_scan(self, tool):
        tool.port = 8443
        captured: dict = {}

        def capture(**kwargs):
            captured.update(kwargs)
            return (JARM_HASH_A, kwargs["dest_host"], kwargs["dest_port"])

        with patch("jarm.scanner.scanner.Scanner.scan", side_effect=capture):
            tool.run("example.com")

        assert captured["dest_port"] == 8443
        assert captured["dest_host"] == "example.com"

    def test_timeout_passed_through(self, tool):
        tool.timeout = 5
        captured: dict = {}

        def capture(**kwargs):
            captured.update(kwargs)
            return (JARM_HASH_A, kwargs["dest_host"], kwargs["dest_port"])

        with patch("jarm.scanner.scanner.Scanner.scan", side_effect=capture):
            tool.run("example.com")

        assert captured["timeout"] == 5
