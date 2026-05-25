"""
atlas.recon.jarm
Recon: JARM TLS fingerprinting.

JARM is a TLS server fingerprinting technique developed by Salesforce.
It sends 10 carefully crafted TLS Client Hello packets with different
cipher/version/extension combinations, captures the server's response
to each, and hashes the aggregated responses into a deterministic
62-character fingerprint.

Why this matters for campaign attribution: two servers with the same
JARM almost certainly run the same TLS library at the same version
with the same configuration (cipher preferences, ALPN support, supported
extensions, etc.). Phishing operators who spin up dozens of identical
hosts produce identical JARM hashes across them. Even if they rotate
domains, IPs, registrars, and ASNs, the underlying server stack
fingerprint is hard to change without effort the operator usually
doesn't make.

JARM is a pivot signal, not a verdict signal. A JARM match doesn't
make a host malicious — it places it in a cluster with other hosts
running an identical TLS stack. That cluster might be benign (every
nginx default deployment shares a JARM with every other one), or it
might be a campaign. Cross-referencing JARM with verdict signals is
where the real value emerges.

Implementation note: the actual TLS handshake / hash computation is
delegated to the `jarm` package (pyjarm on PyPI), which is the
maintained Python reference. We wrap it in our recon tool shape and
add error handling, timeout handling, and an "is this a real JARM
or the all-zeros total-failure sentinel" check.

The 62-char hash `0000…0000` is what the library returns when the host
has no TLS, refused all 10 handshakes, or was unreachable. That's
treated as "JARM not available" — not stored as a pivot value, since
matching on it would correlate every dead host together.
"""

from __future__ import annotations

import logging
from typing import Any

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool

logger = logging.getLogger(__name__)


# The 62-character all-zeros hash the jarm library returns when every
# handshake failed (no TLS server, all rejections, host unreachable).
JARM_NO_TLS_HASH = "0" * 62


class JarmReconTool(ReconTool):
    name = "jarm"
    display_name = "JARM TLS Fingerprint"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.port = config.jarm.port
        self.timeout = config.jarm.timeout_seconds

    def _run(self, target: str, **context: Any) -> ReconResult:
        # The target here is a domain; the JARM scanner takes (host, port).
        # We don't strip a trailing port from the domain — config.jarm.port
        # is the source of truth (default 443).
        hash_value, status = self._scan(target)

        data: dict[str, Any] = {
            "host": target,
            "port": self.port,
            "tls_available": status == "ok",
            "jarm_hash": hash_value if status == "ok" else None,
        }

        if status == "no_tls":
            data["note"] = "All 10 TLS handshakes failed — host likely has no TLS on this port."
        elif status == "error":
            data["note"] = "JARM scan errored; see logs."

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data=data,
        )

    # ── Private helpers ───────────────────────────────────────

    def _scan(self, host: str) -> tuple[str | None, str]:
        """
        Run a JARM scan against host:self.port.

        Returns a (hash, status) tuple where status is:
            "ok"      — a valid non-zero JARM hash was computed
            "no_tls"  — handshakes failed; returned hash is all-zeros
            "error"   — the JARM library raised; treat as unavailable

        Importing the jarm library is done lazily inside the function so
        a missing optional dependency doesn't break atlas at import time —
        the recon tool just returns an error result instead.
        """
        try:
            from jarm.scanner.scanner import Scanner
        except ImportError:
            logger.error("jarm package not installed — install with: pip install pyjarm")
            return None, "error"

        try:
            # Scanner.scan returns (jarm_hash, host, port); we only need the hash.
            # `suppress=True` silences internal warnings about individual handshake
            # failures, which are expected during a JARM probe.
            jarm_hash, _, _ = Scanner.scan(
                dest_host=host,
                dest_port=self.port,
                timeout=self.timeout,
                suppress=True,
            )
        except Exception as exc:  # pragma: no cover — defensive catch
            # The library catches most internal failures and returns the
            # zero-hash, but we wrap anyway in case of unexpected errors
            # (e.g., DNS resolution failure raised before scan starts).
            logger.warning("JARM scan failed for %s:%d: %s", host, self.port, exc)
            return None, "error"

        if jarm_hash == JARM_NO_TLS_HASH:
            return None, "no_tls"

        return jarm_hash, "ok"
