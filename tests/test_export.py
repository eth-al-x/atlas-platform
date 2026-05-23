"""
Tests for atlas.core.export and the CLI --output flag wiring.

The export module is pure serialization, so most tests are direct unit
tests that build small Pydantic objects and verify their dumped shape.
A few integration tests use Typer's CliRunner with a temp DB to confirm
that --output json/csv produces parseable output and that the default
behavior (terminal) is unchanged.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from atlas.cli.main import app
from atlas.core import export
from atlas.core.models import (
    CorrelationResult,
    ReconResult,
    ScanReport,
    ScanSource,
    ScanStats,
    TierResult,
    Verdict,
)
from atlas.storage.db import ScanRepository


# ── Helpers ───────────────────────────────────────────────────


@pytest.fixture
def runner():
    return CliRunner()


def _make_report(
    *, scan_id: int = 1, verdict: Verdict = Verdict.MEDIUM_RISK
) -> ScanReport:
    return ScanReport(
        id=scan_id,
        url="https://example.com",
        domain="example.com",
        final_verdict=verdict,
        tier_results=[
            TierResult(
                tier_name="heuristics",
                display_name="Heuristics",
                flagged=True,
                confidence=0.5,
                details={"signals_fired": ["is_new_domain"]},
            ),
            TierResult(
                tier_name="virustotal",
                display_name="VirusTotal",
                flagged=False,
                confidence=0.0,
            ),
        ],
        scanned_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
        scan_duration_ms=250,
        source=ScanSource.CLI,
    )


def _make_correlations() -> list[CorrelationResult]:
    return [
        CorrelationResult(
            correlator_name="risk_score",
            display_name="Composite Risk Score",
            summary="Risk Score: 45/100 (Medium)",
            findings=[{"source": "heuristics", "points": 15.0, "reason": "..."}],
            data={"score": 45.0, "band": "Medium"},
        ),
        CorrelationResult(
            correlator_name="mitre",
            display_name="MITRE ATT&CK Mapping",
            summary="2 ATT&CK techniques mapped",
            findings=[
                {"technique_id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
                {"technique_id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development"},
            ],
            data={"technique_count": 2},
        ),
        CorrelationResult(
            correlator_name="cross_scan",
            display_name="Cross-Scan Infrastructure",
            summary="2 related domain(s) found",
            findings=[],
            data={"unique_related_domains": 2, "risky_related_domains": 1},
        ),
    ]


# ═══════════════════════════════════════════════════════════════
# JSON serialization
# ═══════════════════════════════════════════════════════════════


class TestReportToJson:

    def test_returns_valid_json(self):
        report = _make_report()
        out = export.report_to_json(report)
        parsed = json.loads(out)
        assert parsed["scan"]["url"] == "https://example.com"
        assert parsed["scan"]["domain"] == "example.com"
        assert parsed["scan"]["final_verdict"] == "Medium Risk"

    def test_tier_results_serialized(self):
        report = _make_report()
        out = export.report_to_json(report)
        parsed = json.loads(out)
        tiers = parsed["scan"]["tier_results"]
        assert len(tiers) == 2
        assert tiers[0]["tier_name"] == "heuristics"
        assert tiers[0]["flagged"] is True

    def test_includes_correlations_when_provided(self):
        report = _make_report()
        out = export.report_to_json(report, correlations=_make_correlations())
        parsed = json.loads(out)
        assert "correlations" in parsed
        assert len(parsed["correlations"]) == 3

    def test_includes_recon_when_provided(self):
        report = _make_report()
        recon = {
            "dns": ReconResult(
                recon_type="dns",
                domain="example.com",
                data={"records": {"A": ["1.2.3.4"]}},
            )
        }
        out = export.report_to_json(report, recon=recon)
        parsed = json.loads(out)
        assert "recon" in parsed
        assert parsed["recon"]["dns"]["recon_type"] == "dns"

    def test_recon_omitted_when_none(self):
        report = _make_report()
        out = export.report_to_json(report)
        parsed = json.loads(out)
        assert "recon" not in parsed

    def test_compact_mode(self):
        report = _make_report()
        out = export.report_to_json(report, indent=None)
        assert "\n" not in out  # Compact: no newlines

    def test_datetime_serialized_as_iso(self):
        report = _make_report()
        out = export.report_to_json(report)
        parsed = json.loads(out)
        # Pydantic mode='json' serializes datetimes as ISO strings
        assert "2026" in parsed["scan"]["scanned_at"]
        assert "T" in parsed["scan"]["scanned_at"]


class TestReportsToJson:

    def test_array_output(self):
        reports = [_make_report(scan_id=1), _make_report(scan_id=2)]
        out = export.reports_to_json(reports)
        parsed = json.loads(out)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0]["id"] == 1
        assert parsed[1]["id"] == 2

    def test_empty_list_gives_empty_array(self):
        out = export.reports_to_json([])
        assert json.loads(out) == []


class TestStatsToJson:

    def test_returns_valid_json(self):
        stats = ScanStats(total_scans=10, high_risk=2, low_risk=1, clean=7)
        out = export.stats_to_json(stats)
        parsed = json.loads(out)
        assert parsed["total_scans"] == 10
        assert parsed["high_risk"] == 2
        assert parsed["low_risk"] == 1


# ═══════════════════════════════════════════════════════════════
# CSV serialization
# ═══════════════════════════════════════════════════════════════


class TestReportToCsv:

    def test_has_header(self):
        report = _make_report()
        out = export.report_to_csv(report)
        first_line = out.splitlines()[0]
        assert "scan_id" in first_line
        assert "final_verdict" in first_line

    def test_no_header_when_disabled(self):
        report = _make_report()
        out = export.report_to_csv(report, header=False)
        # First (and only) row is the data row, no header
        reader = csv.reader(io.StringIO(out))
        rows = list(reader)
        assert len(rows) == 1
        # No "scan_id" in first cell — it's the actual id
        assert rows[0][0] != "scan_id"

    def test_flagged_tiers_joined(self):
        report = _make_report()
        out = export.report_to_csv(report)
        reader = csv.DictReader(io.StringIO(out))
        row = next(reader)
        # Only heuristics is flagged in the fixture
        assert row["flagged_tiers"] == "heuristics"

    def test_risk_score_extracted_from_correlations(self):
        report = _make_report()
        out = export.report_to_csv(report, correlations=_make_correlations())
        reader = csv.DictReader(io.StringIO(out))
        row = next(reader)
        assert row["risk_score"] == "45.0"
        assert row["risk_band"] == "Medium"

    def test_mitre_techniques_joined(self):
        report = _make_report()
        out = export.report_to_csv(report, correlations=_make_correlations())
        reader = csv.DictReader(io.StringIO(out))
        row = next(reader)
        assert "T1566.002" in row["mitre_techniques"]
        assert "T1583.001" in row["mitre_techniques"]
        assert ";" in row["mitre_techniques"]

    def test_related_count_extracted(self):
        report = _make_report()
        out = export.report_to_csv(report, correlations=_make_correlations())
        reader = csv.DictReader(io.StringIO(out))
        row = next(reader)
        assert row["related_domain_count"] == "2"

    def test_empty_fields_when_no_correlations(self):
        report = _make_report()
        out = export.report_to_csv(report)
        reader = csv.DictReader(io.StringIO(out))
        row = next(reader)
        assert row["risk_score"] == ""
        assert row["mitre_techniques"] == ""


class TestReportsToCsv:

    def test_multiple_rows(self):
        reports = [_make_report(scan_id=1), _make_report(scan_id=2)]
        out = export.reports_to_csv(reports)
        lines = out.strip().splitlines()
        assert len(lines) == 3  # header + 2 rows


class TestHistoryToCsv:

    def test_writes_history_rows(self):
        rows = [
            {"id": 1, "url": "https://a.com", "domain": "a.com",
             "final_verdict": "Clean", "scanned_at": "2026-05-01T12:00:00",
             "scan_duration_ms": 100},
            {"id": 2, "url": "https://b.com", "domain": "b.com",
             "final_verdict": "High Risk", "scanned_at": "2026-05-02T12:00:00",
             "scan_duration_ms": 150},
        ]
        out = export.history_to_csv(rows)
        reader = csv.DictReader(io.StringIO(out))
        data = list(reader)
        assert len(data) == 2
        assert data[0]["domain"] == "a.com"
        assert data[1]["final_verdict"] == "High Risk"


class TestStatsToCsv:

    def test_key_value_format(self):
        stats = ScanStats(total_scans=10, high_risk=2, low_risk=1, clean=7)
        out = export.stats_to_csv(stats)
        reader = csv.reader(io.StringIO(out))
        rows = list(reader)
        # header + 6 metric rows
        assert rows[0] == ["metric", "value"]
        # Find the total_scans row
        total_row = next(r for r in rows if r[0] == "total_scans")
        assert total_row[1] == "10"


# ═══════════════════════════════════════════════════════════════
# CLI integration — using CliRunner + temp DB
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def populated_repo(tmp_path, monkeypatch):
    """
    Populate a temp DB and point the CLI's repo getter at it.
    """
    db_path = str(tmp_path / "atlas.db")
    repo = ScanRepository(db_path=db_path)

    # Seed three scans across all verdict bands
    for url, verdict in (
        ("https://evil.com", Verdict.HIGH_RISK),
        ("https://maybe.com", Verdict.LOW_RISK),
        ("https://clean.com", Verdict.CLEAN),
    ):
        report = ScanReport(
            url=url,
            domain=url.replace("https://", ""),
            final_verdict=verdict,
            tier_results=[
                TierResult(
                    tier_name="test",
                    flagged=(verdict != Verdict.CLEAN),
                    confidence=0.7,
                )
            ],
            scanned_at=datetime.now(timezone.utc),
            scan_duration_ms=100,
            source=ScanSource.CLI,
        )
        repo.save_scan(report)

    # Force the CLI to use this repo by overriding the lazy singleton
    import atlas.cli.main as cli_main
    monkeypatch.setattr(cli_main, "_repo", repo)
    return repo


class TestCLIHistoryStructuredOutput:

    def test_history_json_is_valid_array(self, runner, populated_repo):
        result = runner.invoke(app, ["history", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 3
        verdicts = {item["final_verdict"] for item in data}
        assert verdicts == {"High Risk", "Low Risk", "Clean"}

    def test_history_csv_is_parseable(self, runner, populated_repo):
        result = runner.invoke(app, ["history", "--output", "csv"])
        assert result.exit_code == 0
        reader = csv.DictReader(io.StringIO(result.stdout))
        rows = list(reader)
        assert len(rows) == 3

    def test_history_terminal_default_unchanged(self, runner, populated_repo):
        """Default invocation should still render the Rich table."""
        result = runner.invoke(app, ["history"])
        assert result.exit_code == 0
        # The table title is rendered as text
        assert "Recent Scans" in result.stdout

    def test_invalid_output_format_rejected(self, runner, populated_repo):
        result = runner.invoke(app, ["history", "--output", "xml"])
        assert result.exit_code == 2
        assert "Invalid --output" in result.stdout


class TestCLIStatsStructuredOutput:

    def test_stats_json(self, runner, populated_repo):
        result = runner.invoke(app, ["stats", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total_scans"] == 3
        assert data["high_risk"] == 1
        assert data["low_risk"] == 1
        assert data["clean"] == 1

    def test_stats_csv(self, runner, populated_repo):
        result = runner.invoke(app, ["stats", "--output", "csv"])
        assert result.exit_code == 0
        reader = csv.reader(io.StringIO(result.stdout))
        rows = list(reader)
        # header + 6 metric rows
        assert rows[0] == ["metric", "value"]
        assert any(r[0] == "high_risk" and r[1] == "1" for r in rows)


class TestCLICorrelateStructuredOutput:

    def test_correlate_json(self, runner, populated_repo):
        # Get the first scan_id from the repo
        scans = populated_repo.list_scans(limit=1)
        scan_id = scans[0]["id"]
        result = runner.invoke(app, ["correlate", str(scan_id), "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "scan" in data
        assert "correlations" in data

    def test_correlate_not_found_json(self, runner, populated_repo):
        result = runner.invoke(app, ["correlate", "99999", "--output", "json"])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert "error" in data
