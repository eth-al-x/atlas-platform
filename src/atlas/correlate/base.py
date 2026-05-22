"""
atlas.correlate.base
Abstract base class for correlators.

Correlators differ from tiers and recon tools conceptually:
    Tiers produce verdicts (is this bad?)
    Recon tools produce information (what does this look like?)
    Correlators produce synthesis (what does this all mean?)

A correlator reads an already-completed ScanReport plus a dict of ReconResults
and produces higher-order insights. They typically make zero network calls —
they're pure computation over existing data.

The lifecycle parallels Tier and ReconTool: the public correlate() method
wraps the abstract _correlate() with timing, error handling, and structured
logging boilerplate.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from atlas.core.config import AtlasConfig
from atlas.core.models import CorrelationContext, CorrelationResult

logger = logging.getLogger(__name__)


class Correlator(ABC):
    """
    Base class for all correlators.

    Subclasses must implement:
        - name:         unique identifier (e.g., "risk_score")
        - display_name: human-readable label (e.g., "Composite Risk Score")
        - _correlate(): the actual synthesis logic

    The public correlate() method wraps _correlate() with timing and error
    handling, so individual correlators don't need to worry about that.
    """

    name: str = ""
    display_name: str = ""

    def __init__(self, config: AtlasConfig) -> None:
        self.config = config

    def correlate(self, context: CorrelationContext) -> CorrelationResult:
        """
        Execute the correlator against a scan + recon context.

        Wraps _correlate() with timing, error handling, and structured logging.
        Correlators should NOT override this method — override _correlate() instead.
        """
        start = time.perf_counter_ns()
        try:
            result = self._correlate(context)
            result.correlator_name = self.name
            result.display_name = self.display_name
            duration_ms = (time.perf_counter_ns() - start) // 1_000_000
            result.duration_ms = duration_ms

            logger.debug(
                "%s completed for %s in %d ms",
                self.display_name, context.scan.domain, duration_ms,
            )
            return result

        except Exception as exc:
            duration_ms = (time.perf_counter_ns() - start) // 1_000_000
            logger.error(
                "%s failed for %s: %s",
                self.display_name, context.scan.domain, exc,
            )
            return CorrelationResult(
                correlator_name=self.name,
                display_name=self.display_name,
                error=str(exc),
                duration_ms=duration_ms,
            )

    @abstractmethod
    def _correlate(self, context: CorrelationContext) -> CorrelationResult:
        """
        Implement the correlator's actual synthesis logic.

        Args:
            context: A CorrelationContext bundling the scan report and recon results.

        Returns:
            A CorrelationResult with the synthesized findings.
        """
        ...
