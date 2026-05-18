"""
atlas.tiers.local_blocklist
Tier 1: Checks domains against the locally cached StevenBlack malicious hosts list.
Fast, no network calls during analysis — the list is loaded into memory on startup.

Ported from URL Auditor's local_filter.py with added cache freshness checking.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import httpx

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult
from atlas.tiers.base import Tier


logger = logging.getLogger(__name__)


class LocalBlocklistTier(Tier):
    name = "local_blocklist"
    display_name = "Local Blocklist"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.source_url = config.blocklist.source_url
        self.cache_path = Path(config.blocklist.cache_filename)
        self.max_age_hours = config.blocklist.max_cache_age_hours
        self.domains: set[str] = set()

    # ── Public setup ──────────────────────────────────────────

    def load(self) -> None:
        """Load the blocklist into memory, refreshing the cache if stale."""
        if self._cache_is_stale():
            self._download_cache()
        self._parse_cache()
        logger.info("Loaded %d domains into local blocklist", len(self.domains))

    # ── Tier interface ────────────────────────────────────────

    def _check(self, target: str, **context: object) -> TierResult:
        is_blocked = target.lower() in self.domains
        return TierResult(
            flagged=is_blocked,
            confidence=1.0 if is_blocked else 0.0,
            details={
                "source": "StevenBlack Hosts List",
                "domains_loaded": len(self.domains),
            },
        )

    # ── Private helpers ───────────────────────────────────────

    def _cache_is_stale(self) -> bool:
        """Return True if the cache file is missing or older than max_age_hours."""
        if not self.cache_path.exists():
            return True
        age_seconds = time.time() - os.path.getmtime(self.cache_path)
        age_hours = age_seconds / 3600
        if age_hours > self.max_age_hours:
            logger.info("Blocklist cache is %.1f hours old (max %d), refreshing",
                        age_hours, self.max_age_hours)
            return True
        return False

    def _download_cache(self) -> bool:
        """Download the latest hosts file from the source URL."""
        logger.info("Downloading blocklist from %s", self.source_url)
        try:
            response = httpx.get(self.source_url, timeout=30, follow_redirects=True)
            response.raise_for_status()
            self.cache_path.write_text(response.text, encoding="utf-8")
            logger.info("Blocklist cache updated (%d bytes)", len(response.text))
            return True
        except httpx.HTTPError as exc:
            logger.error("Failed to download blocklist: %s", exc)
            return False

    def _parse_cache(self) -> None:
        """Parse the hosts file into an in-memory set of domains."""
        self.domains.clear()

        if not self.cache_path.exists():
            logger.warning("No blocklist cache file found at %s", self.cache_path)
            return

        try:
            with open(self.cache_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                        domain = parts[1].lower()
                        if domain not in ("localhost", "local"):
                            self.domains.add(domain)
        except OSError as exc:
            logger.error("Error reading blocklist cache: %s", exc)
