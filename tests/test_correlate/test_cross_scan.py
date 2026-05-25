"""
Tests for the cross-scan correlator and its underlying DB query.

The correlator surfaces infrastructure reuse across multiple scans.
Tests build a small populated DB and verify that:
    - Same-IP matches are found.
    - Same-ASN matches are found.
    - Same-registrar matches are found.
    - The current scan is excluded from its own results.
    - Missing pivots are handled gracefully.
    - The correlator no-ops when no repo is available.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
from atlas.correlate.cross_scan import CrossScanCorrelator
from atlas.correlate.pipeline import CorrelationPipeline
from atlas.storage.db import ScanRepository


# ── Helpers ───────────────────────────────────────────────────


@pytest.fixture
def config():
    return AtlasConfig()


@pytest.fixture
def db_repo(tmp_path):
    """Real SQLite repository backed by a temp DB file."""
    return ScanRepository(db_path=str(tmp_path / "test.db"))


def _make_report(url: str, domain: str, verdict: Verdict = Verdict.CLEAN) -> ScanReport:
    return ScanReport(
        url=url,
        domain=domain,
        final_verdict=verdict,
        tier_results=[],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=10,
        source=ScanSource.CLI,
    )


def _ip_intel(ip: str, asn: str = "AS12345") -> ReconResult:
    return ReconResult(
        recon_type="ip_intel",
        domain="x",
        data={
            "ip": ip,
            "geolocation": {"asn": asn, "country": "US"},
            "exposure": {},
        },
    )


def _whois(registrar: str) -> ReconResult:
    return ReconResult(
        recon_type="whois",
        domain="x",
        data={"registrar": registrar, "creation_date": "2020-01-01T00:00:00+00:00"},
    )


def _populate_three_scans(repo: ScanRepository) -> dict[str, int]:
    """
    Build a tiny dataset:
        scan A: evil1.com  → IP 1.2.3.4, ASN AS999, registrar 'BadReg'
        scan B: evil2.com  → IP 1.2.3.4, ASN AS999, registrar 'BadReg'  (same everything)
        scan C: clean.com  → IP 8.8.8.8, ASN AS15169, registrar 'GoodReg'
    """
    a = repo.save_scan(_make_report("https://evil1.com", "evil1.com", Verdict.HIGH_RISK))
    b = repo.save_scan(_make_report("https://evil2.com", "evil2.com", Verdict.HIGH_RISK))
    c = repo.save_scan(_make_report("https://clean.com", "clean.com", Verdict.CLEAN))

    repo.save_recon_results(a, {
        "ip_intel": _ip_intel("1.2.3.4", asn="AS999"),
        "whois": _whois("BadReg"),
    })
    repo.save_recon_results(b, {
        "ip_intel": _ip_intel("1.2.3.4", asn="AS999"),
        "whois": _whois("BadReg"),
    })
    repo.save_recon_results(c, {
        "ip_intel": _ip_intel("8.8.8.8", asn="AS15169"),
        "whois": _whois("GoodReg"),
    })

    return {"A": a, "B": b, "C": c}


# ═══════════════════════════════════════════════════════════════
# ScanRepository.find_related_scans
# ═══════════════════════════════════════════════════════════════


class TestFindRelatedScans:

    def test_same_ip_match(self, db_repo):
        ids = _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"], ip="1.2.3.4"
        )
        assert len(related["ip"]) == 1
        assert related["ip"][0]["domain"] == "evil2.com"

    def test_same_asn_match(self, db_repo):
        ids = _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"], asn="AS999"
        )
        assert len(related["asn"]) == 1
        assert related["asn"][0]["domain"] == "evil2.com"

    def test_same_registrar_match(self, db_repo):
        ids = _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"], registrar="BadReg"
        )
        assert len(related["registrar"]) == 1
        assert related["registrar"][0]["domain"] == "evil2.com"

    def test_same_jarm_match(self, db_repo):
        """JARM pivot finds scans sharing a TLS fingerprint."""
        # Populate scans, then add JARM data: A and B share a hash, C has its own.
        ids = _populate_three_scans(db_repo)
        shared_hash = "ab" * 31
        other_hash = "cd" * 31
        for sid in (ids["A"], ids["B"]):
            db_repo.save_recon_results(sid, {
                "jarm": ReconResult(
                    recon_type="jarm",
                    domain="x",
                    data={"jarm_hash": shared_hash, "tls_available": True},
                ),
            })
        db_repo.save_recon_results(ids["C"], {
            "jarm": ReconResult(
                recon_type="jarm",
                domain="x",
                data={"jarm_hash": other_hash, "tls_available": True},
            ),
        })

        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"], jarm_hash=shared_hash,
        )
        assert len(related["jarm"]) == 1
        assert related["jarm"][0]["domain"] == "evil2.com"

    def test_jarm_pivot_returns_empty_when_no_match(self, db_repo):
        ids = _populate_three_scans(db_repo)
        db_repo.save_recon_results(ids["A"], {
            "jarm": ReconResult(
                recon_type="jarm",
                domain="x",
                data={"jarm_hash": "ab" * 31, "tls_available": True},
            ),
        })
        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"], jarm_hash="ff" * 31,
        )
        assert related["jarm"] == []

    def test_excludes_current_scan(self, db_repo):
        """The exclude_scan_id must not appear in any result list."""
        ids = _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"],
            ip="1.2.3.4",
            asn="AS999",
            registrar="BadReg",
        )
        all_scan_ids = [r["scan_id"] for cat in related.values() for r in cat]
        assert ids["A"] not in all_scan_ids

    def test_no_pivots_no_results(self, db_repo):
        _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(exclude_scan_id=999)
        assert related == {
            "ip": [], "asn": [], "registrar": [],
            "favicon": [], "slash24": [], "jarm": [],
        }

    def test_no_matches_returns_empty_lists(self, db_repo):
        _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(
            exclude_scan_id=0, ip="99.99.99.99"
        )
        assert related["ip"] == []

    def test_results_include_verdict(self, db_repo):
        ids = _populate_three_scans(db_repo)
        related = db_repo.find_related_scans(
            exclude_scan_id=ids["A"], ip="1.2.3.4"
        )
        assert related["ip"][0]["verdict"] == "High Risk"

    def test_limit_respected(self, db_repo):
        """Insert 15 same-IP scans; query with limit=5 → 5 results."""
        for i in range(15):
            sid = db_repo.save_scan(_make_report(f"https://d{i}.com", f"d{i}.com"))
            db_repo.save_recon_results(sid, {"ip_intel": _ip_intel("7.7.7.7")})

        related = db_repo.find_related_scans(
            exclude_scan_id=0, ip="7.7.7.7", limit_per_category=5
        )
        assert len(related["ip"]) == 5


# ═══════════════════════════════════════════════════════════════
# CrossScanCorrelator unit tests
# ═══════════════════════════════════════════════════════════════


class TestCrossScanCorrelator:

    def test_no_repo_returns_skip_result(self, config):
        scan = _make_report("https://example.com", "example.com")
        scan.id = 1
        ctx = CorrelationContext(scan=scan, recon={})
        result = CrossScanCorrelator(config, repo=None).correlate(ctx)
        assert result.data["skipped"] is True
        assert result.data["reason"] == "no_repo"
        assert result.findings == []

    def test_no_scan_id_returns_skip_result(self, config, db_repo):
        scan = _make_report("https://example.com", "example.com")
        # scan.id is None by default — not yet persisted
        ctx = CorrelationContext(scan=scan, recon={})
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)
        assert result.data["skipped"] is True
        assert result.data["reason"] == "no_scan_id"

    def test_no_pivots_returns_skip_result(self, config, db_repo):
        """Recon data with no usable IP/ASN/registrar should be a no-op."""
        scan = _make_report("https://example.com", "example.com")
        scan.id = 1
        ctx = CorrelationContext(scan=scan, recon={})
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)
        assert result.data["skipped"] is True
        assert result.data["reason"] == "no_pivots"

    def test_finds_matching_ip(self, config, db_repo):
        """A scan sharing an IP with two others surfaces them in findings."""
        ids = _populate_three_scans(db_repo)

        scan = _make_report("https://evil1.com", "evil1.com")
        scan.id = ids["A"]
        ctx = CorrelationContext(
            scan=scan,
            recon={"ip_intel": _ip_intel("1.2.3.4", asn="AS999")},
        )
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)

        ip_findings = [f for f in result.findings if f["category"] == "ip"]
        assert len(ip_findings) == 1
        assert ip_findings[0]["domain"] == "evil2.com"

    def test_summary_mentions_match_counts(self, config, db_repo):
        ids = _populate_three_scans(db_repo)
        scan = _make_report("https://evil1.com", "evil1.com")
        scan.id = ids["A"]
        ctx = CorrelationContext(
            scan=scan,
            recon={
                "ip_intel": _ip_intel("1.2.3.4", asn="AS999"),
                "whois": _whois("BadReg"),
            },
        )
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)
        # All three categories match evil2.com
        assert "same IP" in result.summary
        assert "same ASN" in result.summary
        assert "same registrar" in result.summary

    def test_risky_count_in_data(self, config, db_repo):
        """Related scans with risky verdicts should be counted."""
        ids = _populate_three_scans(db_repo)
        scan = _make_report("https://evil1.com", "evil1.com")
        scan.id = ids["A"]
        ctx = CorrelationContext(
            scan=scan,
            recon={"ip_intel": _ip_intel("1.2.3.4", asn="AS999")},
        )
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)
        # evil2.com is High Risk in our fixture data
        assert result.data["risky_related_domains"] >= 1

    def test_no_matches_clean_summary(self, config, db_repo):
        """A scan with no related scans should report cleanly."""
        ids = _populate_three_scans(db_repo)
        scan = _make_report("https://lonely.com", "lonely.com")
        scan.id = 9999  # not in DB
        ctx = CorrelationContext(
            scan=scan,
            recon={"ip_intel": _ip_intel("9.9.9.9", asn="AS_NOPE")},
        )
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)
        assert "No related scans" in result.summary
        assert result.findings == []

    def test_common_infra_flagged(self, config, db_repo):
        """ASN matches against well-known cloud ASNs get the is_common_infra hint."""
        # Insert two scans sharing the Cloudflare ASN
        for i in range(2):
            sid = db_repo.save_scan(_make_report(f"https://c{i}.com", f"c{i}.com"))
            db_repo.save_recon_results(sid, {
                "ip_intel": _ip_intel(f"104.16.0.{i}", asn="AS13335"),
            })

        scan = _make_report("https://current.com", "current.com")
        scan.id = 8888
        ctx = CorrelationContext(
            scan=scan,
            recon={"ip_intel": _ip_intel("104.16.0.99", asn="AS13335")},
        )
        result = CrossScanCorrelator(config, repo=db_repo).correlate(ctx)
        asn_findings = [f for f in result.findings if f["category"] == "asn"]
        assert all(f["is_common_infra"] for f in asn_findings)


# ═══════════════════════════════════════════════════════════════
# Pipeline integration
# ═══════════════════════════════════════════════════════════════


class TestPipelineIntegration:

    def test_pipeline_without_repo_has_three_correlators(self, config):
        """No repo → cross_scan is not registered."""
        pipeline = CorrelationPipeline(config=config)
        assert pipeline.correlator_names == ["risk_score", "timeline", "mitre"]

    def test_pipeline_with_repo_has_four_correlators(self, config, db_repo):
        """With repo → cross_scan is added."""
        pipeline = CorrelationPipeline(config=config, repo=db_repo)
        assert pipeline.correlator_names == [
            "risk_score", "timeline", "mitre", "cross_scan"
        ]

    def test_pipeline_runs_cross_scan_correlator(self, config, db_repo):
        ids = _populate_three_scans(db_repo)
        scan = _make_report("https://evil1.com", "evil1.com")
        scan.id = ids["A"]
        ctx = CorrelationContext(
            scan=scan,
            recon={"ip_intel": _ip_intel("1.2.3.4", asn="AS999")},
        )
        pipeline = CorrelationPipeline(config=config, repo=db_repo)
        results = pipeline.correlate(ctx)
        names = {r.correlator_name for r in results}
        assert "cross_scan" in names

    def test_cross_scan_result_persisted(self, config, db_repo):
        """A cross-scan correlation result round-trips through the DB normally."""
        ids = _populate_three_scans(db_repo)
        scan = _make_report("https://evil1.com", "evil1.com")
        scan.id = ids["A"]
        ctx = CorrelationContext(
            scan=scan,
            recon={"ip_intel": _ip_intel("1.2.3.4", asn="AS999")},
        )
        pipeline = CorrelationPipeline(config=config, repo=db_repo)
        results = pipeline.correlate(ctx)
        db_repo.save_correlations(ids["A"], results)

        loaded = db_repo.get_correlations(ids["A"])
        cross = [c for c in loaded if c.correlator_name == "cross_scan"]
        assert len(cross) == 1
