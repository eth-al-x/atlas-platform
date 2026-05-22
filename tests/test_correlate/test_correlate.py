"""
Tests for the ATLAS correlation layer.

Correlators are pure synthesis — they take built ScanReport + recon dicts
and produce CorrelationResult. Tests build small synthetic contexts and
verify the correlators surface the expected findings.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from atlas.core.config import AtlasConfig
from atlas.core.models import (
    CorrelationContext,
    ReconResult,
    ScanReport,
    ScanSource,
    TierResult,
    Verdict,
)
from atlas.correlate.mitre import MitreCorrelator
from atlas.correlate.pipeline import CorrelationPipeline
from atlas.correlate.risk_score import RiskScoreCorrelator
from atlas.correlate.timeline import TimelineCorrelator


# ── Helpers ───────────────────────────────────────────────────


def _build_scan(*flagged_tiers: tuple[str, float]) -> ScanReport:
    """Build a minimal ScanReport with the given flagged tier names."""
    return ScanReport(
        id=1,
        url="https://example.com",
        domain="example.com",
        final_verdict=Verdict.CLEAN if not flagged_tiers else Verdict.MEDIUM_RISK,
        tier_results=[
            TierResult(
                tier_name=name,
                display_name=name.title(),
                flagged=True,
                confidence=conf,
            )
            for name, conf in flagged_tiers
        ],
        source=ScanSource.CLI,
    )


def _context(scan: ScanReport, **recon: ReconResult) -> CorrelationContext:
    return CorrelationContext(scan=scan, recon=recon)


@pytest.fixture
def config():
    return AtlasConfig()


# ── Risk Score Correlator ─────────────────────────────────────


class TestRiskScoreCorrelator:

    def test_clean_scan_minimal_score(self, config):
        scan = _build_scan()
        result = RiskScoreCorrelator(config).correlate(_context(scan))
        assert result.data["score"] < 15
        assert result.data["band"] == "Minimal"

    def test_virustotal_flag_drives_high_score(self, config):
        scan = _build_scan(("virustotal", 0.9))
        result = RiskScoreCorrelator(config).correlate(_context(scan))
        assert result.data["score"] >= 30
        # VT contribution should appear in findings
        sources = [f["source"] for f in result.findings]
        assert "virustotal" in sources

    def test_multiple_tiers_compound(self, config):
        scan = _build_scan(
            ("virustotal", 0.8),
            ("typosquat", 0.7),
            ("dnsbl", 0.9),
        )
        result = RiskScoreCorrelator(config).correlate(_context(scan))
        assert result.data["score"] >= 70
        assert result.data["band"] == "High"

    def test_new_domain_adds_points(self, config):
        scan = _build_scan(("dnsbl", 0.5))
        whois = ReconResult(
            recon_type="whois",
            domain="example.com",
            data={
                "creation_date": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
            },
        )
        # Compare with and without the new-domain signal
        without = RiskScoreCorrelator(config).correlate(_context(scan))
        with_new = RiskScoreCorrelator(config).correlate(_context(scan, whois=whois))
        assert with_new.data["score"] > without.data["score"]

    def test_old_domain_no_extra_points(self, config):
        scan = _build_scan(("dnsbl", 0.5))
        whois = ReconResult(
            recon_type="whois",
            domain="example.com",
            data={
                "creation_date": (datetime.now(timezone.utc) - timedelta(days=365 * 5)).isoformat(),
            },
        )
        result = RiskScoreCorrelator(config).correlate(_context(scan, whois=whois))
        # No WHOIS-derived findings should be added for a 5yr old domain
        whois_findings = [f for f in result.findings if f["source"] == "whois"]
        assert len(whois_findings) == 0

    def test_score_clamped_at_100(self, config):
        # Stack everything to verify the upper bound holds
        scan = _build_scan(
            ("virustotal", 1.0),
            ("local_blocklist", 1.0),
            ("dnsbl", 1.0),
            ("typosquat", 1.0),
            ("heuristics", 1.0),
        )
        whois = ReconResult(
            recon_type="whois",
            domain="evil.com",
            data={"creation_date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
        )
        urlscan = ReconResult(
            recon_type="urlscan",
            domain="evil.com",
            data={"malicious": True, "score": 95},
        )
        result = RiskScoreCorrelator(config).correlate(
            _context(scan, whois=whois, urlscan=urlscan)
        )
        assert result.data["score"] <= 100.0

    def test_findings_are_explainable(self, config):
        scan = _build_scan(("virustotal", 0.8))
        result = RiskScoreCorrelator(config).correlate(_context(scan))
        for finding in result.findings:
            assert "source" in finding
            assert "points" in finding
            assert "reason" in finding


# ── Timeline Correlator ───────────────────────────────────────


class TestTimelineCorrelator:

    def test_empty_context_returns_no_events(self, config):
        scan = _build_scan()
        result = TimelineCorrelator(config).correlate(_context(scan))
        assert result.data["event_count"] == 0
        assert "No temporal data" in result.summary

    def test_whois_creates_registration_event(self, config):
        scan = _build_scan()
        whois = ReconResult(
            recon_type="whois",
            domain="example.com",
            data={
                "creation_date": "2020-01-15T00:00:00+00:00",
                "registrar": "ExampleReg",
            },
        )
        result = TimelineCorrelator(config).correlate(_context(scan, whois=whois))
        events = [f for f in result.findings if f["event"] == "Domain registered"]
        assert len(events) == 1
        assert events[0]["details"]["registrar"] == "ExampleReg"

    def test_crtsh_events_sorted_chronologically(self, config):
        scan = _build_scan()
        crtsh = ReconResult(
            recon_type="crtsh",
            domain="example.com",
            data={
                "recent_certs": [
                    {"not_before": "2023-06-01T00:00:00+00:00"},
                    {"not_before": "2020-01-01T00:00:00+00:00"},
                    {"not_before": "2024-12-01T00:00:00+00:00"},
                ],
            },
        )
        result = TimelineCorrelator(config).correlate(_context(scan, crtsh=crtsh))
        dates = [f["date"] for f in result.findings]
        assert dates == sorted(dates)

    def test_new_domain_flagged_in_observations(self, config):
        scan = _build_scan()
        whois = ReconResult(
            recon_type="whois",
            domain="example.com",
            data={"creation_date": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()},
        )
        result = TimelineCorrelator(config).correlate(_context(scan, whois=whois))
        obs = result.data["observations"]
        assert any("3 days old" in o or "days old" in o for o in obs)

    def test_cert_predating_registration_flagged(self, config):
        """A WHOIS that says 'registered yesterday' but crt.sh has 6mo cert history is suspicious."""
        scan = _build_scan()
        whois = ReconResult(
            recon_type="whois",
            domain="example.com",
            data={"creation_date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
        )
        crtsh = ReconResult(
            recon_type="crtsh",
            domain="example.com",
            data={"recent_certs": [
                {"not_before": (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()},
            ]},
        )
        result = TimelineCorrelator(config).correlate(_context(scan, whois=whois, crtsh=crtsh))
        obs = result.data["observations"]
        assert any("predates WHOIS" in o for o in obs)


# ── MITRE ATT&CK Correlator ───────────────────────────────────


class TestMitreCorrelator:

    def test_no_flags_no_techniques(self, config):
        scan = _build_scan()
        result = MitreCorrelator(config).correlate(_context(scan))
        assert result.data["technique_count"] == 0

    def test_typosquat_maps_to_phishing_link(self, config):
        scan = _build_scan(("typosquat", 0.8))
        result = MitreCorrelator(config).correlate(_context(scan))
        tids = [f["technique_id"] for f in result.findings]
        assert "T1566.002" in tids   # Phishing: Spearphishing Link
        assert "T1583.001" in tids   # Acquire Infrastructure: Domains

    def test_virustotal_maps_to_multiple_techniques(self, config):
        scan = _build_scan(("virustotal", 0.9))
        result = MitreCorrelator(config).correlate(_context(scan))
        tids = [f["technique_id"] for f in result.findings]
        assert "T1566.002" in tids
        assert "T1189" in tids   # Drive-by Compromise

    def test_url_includes_attack_link(self, config):
        scan = _build_scan(("virustotal", 0.9))
        result = MitreCorrelator(config).correlate(_context(scan))
        for f in result.findings:
            assert "attack.mitre.org" in f["url"]

    def test_suspicious_js_triggers_T1059_007(self, config):
        scan = _build_scan()
        web = ReconResult(
            recon_type="web_recon",
            domain="example.com",
            data={"suspicious_js_markers": 5},
        )
        result = MitreCorrelator(config).correlate(_context(scan, web_recon=web))
        tids = [f["technique_id"] for f in result.findings]
        assert "T1059.007" in tids

    def test_new_domain_plus_flag_triggers_extra_techniques(self, config):
        scan = _build_scan(("dnsbl", 0.7))
        whois = ReconResult(
            recon_type="whois",
            domain="example.com",
            data={"creation_date": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()},
        )
        result = MitreCorrelator(config).correlate(_context(scan, whois=whois))
        tids = [f["technique_id"] for f in result.findings]
        # New + flagged should add infrastructure techniques
        assert "T1584" in tids

    def test_rationale_accumulates_across_rules(self, config):
        """A technique triggered by multiple rules should list all rationales."""
        scan = _build_scan(("typosquat", 0.8), ("virustotal", 0.8))
        result = MitreCorrelator(config).correlate(_context(scan))
        phishing = next((f for f in result.findings if f["technique_id"] == "T1566.002"), None)
        assert phishing is not None
        assert len(phishing["rationale"]) >= 2

    def test_summary_lists_technique_count(self, config):
        scan = _build_scan(("virustotal", 0.9), ("typosquat", 0.8))
        result = MitreCorrelator(config).correlate(_context(scan))
        assert result.data["technique_count"] > 0
        assert str(result.data["technique_count"]) in result.summary


# ── Pipeline ──────────────────────────────────────────────────


class TestCorrelationPipeline:

    def test_pipeline_runs_all_correlators(self, config):
        pipeline = CorrelationPipeline(config=config)
        scan = _build_scan(("virustotal", 0.9))
        results = pipeline.correlate(_context(scan))
        assert len(results) == 3
        names = {r.correlator_name for r in results}
        assert names == {"risk_score", "timeline", "mitre"}

    def test_pipeline_returns_results_even_when_empty_context(self, config):
        pipeline = CorrelationPipeline(config=config)
        scan = _build_scan()
        results = pipeline.correlate(_context(scan))
        assert len(results) == 3
        # All should complete without errors
        assert all(r.error is None for r in results)

    def test_correlator_names_property(self, config):
        pipeline = CorrelationPipeline(config=config)
        assert pipeline.correlator_names == ["risk_score", "timeline", "mitre"]


# ── Base class error handling ─────────────────────────────────


class TestCorrelatorErrorHandling:

    def test_exception_in_correlator_caught(self, config):
        """A correlator that raises should return an error result, not crash."""
        from atlas.correlate.base import Correlator
        from atlas.core.models import CorrelationResult

        class BrokenCorrelator(Correlator):
            name = "broken"
            display_name = "Broken"

            def _correlate(self, context):
                raise ValueError("intentional test failure")

        scan = _build_scan()
        result = BrokenCorrelator(config).correlate(_context(scan))
        assert result.error is not None
        assert "intentional test failure" in result.error
        assert result.correlator_name == "broken"
