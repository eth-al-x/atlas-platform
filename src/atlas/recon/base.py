"""
atlas.recon.base
Abstract base class for recon tools.

Recon tools differ from tiers conceptually: tiers produce verdicts
(i.e. is this risky?), while recon tools produce information (i.e. what does
this domain look like?). Both share a similar lifecycle, but their outputs serve
different purposes - verdicts go into risk scoring, recon data goes into
human-readable investigation reports.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult

logger = logging.getLogger(__name__)

class ReconTool(ABC):
    """
    Base class for all recon tools.

    Subclasses must implement:
        - name:         unique identifier (e.g., "dns")
        - display_name: human-readable label (e.g., "DNS Lookup")
        - _run():       the actual recon logic

    The public run() method wraps _run() with timing and error handling,
    so individual tools don't need to worry about that boilerplate.
    """

    name: str = ""
    display_name: str = ""

    def __init__(self, config: AtlasConfig) -> None:
        self.config = config

    def run(self, target: str, **context: object) -> ReconResult:
        """
        Execute this recon tool against the target.

        Wraps _run() with timing, error handling, and structured logging.
        Tools should NOT override this method - override _run() instead.
        """
        start = time.perf_counter_ns()
        try:
            result = self._run(target, **context)
            result.recon_type = self.name
            result.domain = target
            duration_ms = (time.perf_counter_ns() - start) // 1_000_000
            result.data.setdefault("_duration_ms", duration_ms)

            logger.debug("%s completed for %s in %d ms",
                         self.display_name, target, duration_ms)
            return result

        except Exception as exc:
            duration_ms = (time.perf_counter_ns() - start) // 1_000_000
            logger.error("%s failed for %s: %s", self.display_name, target, exc)
            return ReconResult(
                recon_type=self.name,
                domain=target,
                error=str(exc),
                data={"_duration_ms": duration_ms},
            )

    @abstractmethod
    def _run(self, target: str, **context: object) -> ReconResult:
        """
        Implement the tool's actual recon logic.

        Args:
            target: The domain, IP, or URL to investigate.
            **context: Optional additional context.

        Returns:
            A ReconResult with the gathered information.
        """
        ...