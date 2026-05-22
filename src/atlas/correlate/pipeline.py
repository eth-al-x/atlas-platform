"""
atlas.correlate.pipeline
Orchestrates running all correlators against a CorrelationContext.

Correlators are pure synthesis — they don't talk to the network or hit
external APIs (with extremely rare exceptions). This pipeline runs them
sequentially since they're fast (~milliseconds each) and a thread pool
would be overkill.
"""

from __future__ import annotations

import logging
from typing import Sequence

from atlas.core.config import AtlasConfig, get_config
from atlas.core.models import CorrelationContext, CorrelationResult
from atlas.correlate.base import Correlator
from atlas.correlate.mitre import MitreCorrelator
from atlas.correlate.risk_score import RiskScoreCorrelator
from atlas.correlate.timeline import TimelineCorrelator

logger = logging.getLogger(__name__)


class CorrelationPipeline:
    """Run every registered correlator against a context."""

    def __init__(
        self,
        config: AtlasConfig | None = None,
        correlators: Sequence[Correlator] | None = None,
    ) -> None:
        self.config = config or get_config()
        self._correlators: list[Correlator] = list(correlators) if correlators else []
        if not self._correlators:
            self._setup_correlators()

    def _setup_correlators(self) -> None:
        """Register the default correlator set."""
        self._correlators = [
            RiskScoreCorrelator(self.config),
            TimelineCorrelator(self.config),
            MitreCorrelator(self.config),
        ]

    @property
    def correlator_names(self) -> list[str]:
        return [c.name for c in self._correlators]

    def correlate(self, context: CorrelationContext) -> list[CorrelationResult]:
        """Run every correlator and return their results."""
        results: list[CorrelationResult] = []
        for correlator in self._correlators:
            logger.debug("Running correlator: %s", correlator.name)
            results.append(correlator.correlate(context))
        return results
