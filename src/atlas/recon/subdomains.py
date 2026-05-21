"""
atlas.recon.subdomains
Recon: Active DNS subdomain enumeration via wordlist bruteforcing.

For each entry in a wordlist, attempts to resolve `<entry>.<target>` as
a DNS name. Names that resolve are reported as discovered subdomains.

This is the only ATLAS tool that generates meaningful outbound network
traffic — a few hundred to many thousand DNS queries depending on the
wordlist size. A rate limit keeps this polite (50 queries/second default).

A one-time warning is shown on first use, then suppressed via a marker
file at ~/.atlas/active_recon_acknowledged. Subsequent runs go straight
to enumeration.

Concurrency uses a ThreadPoolExecutor (20 workers default) — sufficient
for fast scans without overwhelming a single DNS resolver. The combined
effect: a 700-word list completes in ~15 seconds.

Use cases:
    - Find subdomains DNS-bruteforcing can catch that CT logs missed
    - Discover dev/staging/legacy hosts unintentionally exposed
    - Combine with the crt.sh tool for fuller subdomain coverage
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


# The default wordlist ships with the package
DEFAULT_WORDLIST_PATH = Path(__file__).parent / "wordlists" / "subdomains_top500.txt"

# Acknowledgement marker — created on first use
ACK_FILE = Path.home() / ".atlas" / "active_recon_acknowledged"

# Concurrency and rate-limiting defaults
DEFAULT_WORKERS = 20
DEFAULT_QPS = 50  # queries per second (global)
DNS_TIMEOUT_SECONDS = 2.0  # short timeout per query


class _RateLimiter:
    """
    Simple token-bucket-ish rate limiter for global query rate.

    Threads call acquire() before issuing a query. The limiter enforces
    that no more than `rate` calls succeed per second across all threads.
    """

    def __init__(self, rate: int) -> None:
        self.rate = rate
        self.interval = 1.0 / rate
        self.lock = threading.Lock()
        self.last_call = 0.0

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_call
            wait = self.interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self.last_call = time.monotonic()


class SubdomainReconTool(ReconTool):
    name = "subdomains"
    display_name = "Subdomain Enumeration"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        # Pull config; fall back to defaults if not present
        self.workers = DEFAULT_WORKERS
        self.qps = DEFAULT_QPS
        self.timeout = DNS_TIMEOUT_SECONDS

    def _run(self, target: str, **context: object) -> ReconResult:
        # Wordlist path can be overridden via context (set by CLI when --wordlist used)
        wordlist_path = context.get("wordlist_path", DEFAULT_WORKLIST_FALLBACK())
        if isinstance(wordlist_path, str):
            wordlist_path = Path(wordlist_path)

        # Load the wordlist
        try:
            words = self._load_wordlist(wordlist_path)
        except FileNotFoundError:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error=f"wordlist not found: {wordlist_path}",
                data={},
            )

        if not words:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error="wordlist is empty",
                data={},
            )

        logger.info("Starting subdomain enumeration for %s (%d words, %d workers, %d qps)",
                    target, len(words), self.workers, self.qps)

        # Set up the per-thread resolver and rate limiter
        rate_limiter = _RateLimiter(self.qps)
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # Enumerate concurrently
        discovered: list[dict] = []
        attempts = 0
        start = time.monotonic()

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {
                pool.submit(self._try_subdomain, target, word, resolver, rate_limiter): word
                for word in words
            }
            for future in as_completed(futures):
                attempts += 1
                result = future.result()
                if result is not None:
                    discovered.append(result)

        duration = round(time.monotonic() - start, 2)
        logger.info("Subdomain enumeration complete: %d discovered, %d attempts, %.1fs",
                    len(discovered), attempts, duration)

        # Sort discoveries by hostname for stable output
        discovered.sort(key=lambda d: d["hostname"])

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "discovered_subdomains": discovered,
                "discovered_count": len(discovered),
                "wordlist_path": str(wordlist_path),
                "wordlist_size": len(words),
                "attempts": attempts,
                "duration_seconds": duration,
                "queries_per_second": self.qps,
            },
        )

    # ── Private helpers ───────────────────────────────────────

    def _load_wordlist(self, path: Path) -> list[str]:
        """Read the wordlist, stripping comments and blanks."""
        words = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
        return words

    def _try_subdomain(self, target: str, word: str, resolver: dns.resolver.Resolver,
                       rate_limiter: _RateLimiter) -> dict | None:
        """
        Try to resolve <word>.<target> as a DNS A record.
        Returns a dict with the hostname and resolved IPs on success, None on failure.
        """
        hostname = f"{word}.{target}"

        rate_limiter.acquire()

        try:
            answers = resolver.resolve(hostname, "A")
            ips = sorted([str(a) for a in answers])
            return {"hostname": hostname, "ips": ips}

        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            # Domain exists but no A record — sometimes still interesting,
            # but for simplicity we filter these out.
            return None
        except dns.resolver.Timeout:
            return None
        except Exception as exc:
            logger.debug("Unexpected error resolving %s: %s", hostname, exc)
            return None


# ── Acknowledgement handling ──────────────────────────────────


def ensure_acknowledged() -> bool:
    """
    Check whether the user has acknowledged the active-recon warning.

    Returns True if previously acknowledged, False if not. Caller should
    show the warning and (if user confirms) call mark_acknowledged().
    """
    return ACK_FILE.exists()


def mark_acknowledged() -> None:
    """Create the marker file so future runs skip the warning."""
    ACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACK_FILE.touch()


# Wordlist fallback — function rather than constant so import-time errors
# don't fire if the package somehow gets installed without the wordlist.
def DEFAULT_WORKLIST_FALLBACK() -> Path:
    return DEFAULT_WORDLIST_PATH
