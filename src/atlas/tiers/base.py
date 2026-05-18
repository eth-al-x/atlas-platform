"""
atlas.tiers.base
Abstract base class for analysis tiers.

Every tier (blocklist, heuristics, DNSBL, VirusTotal, URLhaus, etc.)
implements this interface so the pipeline can treat them uniformly.
"""

from __future__ import annotations

import time
import logging
from abc import ABC, abstractmethod

from atlas.core.config import AtlasConfig
from atlas.core.models import TierResult


logger = logging.getLogger(__name__)


class Tier(ABC):
    """
    Base class for all analysis tiers.

    Subclasses must implement:
        - name:         unique identifier (e.g., "local_blocklist")
        - display_name: human-readable label (e.g., "Local Blocklist")
        - _check():     the actual analysis logic

    The public check() method wraps _check() with timing and error handling,
    so individual tiers don't need to worry about that boilerplate.
    """

    name: str = ""
    display_name: str = ""

    def __init__(self, config: AtlasConfig) -> None:
        self.config = config

    def check(self, target: str, **context: object) -> TierResult:
        """
        Run this tier's analysis on the given domain or URL.

        Wraps _check() with timing, error handling, and structured logging.
        Tiers should NOT override this method — override _check() instead.
        """
        start = time.perf_counter_ns()
        try:
            result = self._check(target, **context)
            result.tier_name = self.name
            result.display_name = self.display_name
            result.duration_ms = (time.perf_counter_ns() - start) // 1_000_000

            if result.flagged:
                logger.warning("%s flagged target: %s", self.display_name, target)
            else:
                logger.debug("%s passed: %s", self.display_name, target)

            return result

        except Exception as exc:
            duration = (time.perf_counter_ns() - start) // 1_000_000
            logger.error("%s failed on %s: %s", self.display_name, target, exc)
            return TierResult(
                tier_name=self.name,
                display_name=self.display_name,
                flagged=False,
                error=str(exc),
                duration_ms=duration,
            )

    @abstractmethod
    def _check(self, target: str, **context: object) -> TierResult:
        """
        Implement the tier's actual analysis logic.

        Args:
            target: The domain or URL to analyze.
            **context: Optional additional context (e.g., raw URL, previous tier results).

        Returns:
            A TierResult with flagged status and any relevant details.
        """
        ...
