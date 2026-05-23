"""
Tests for the domain watch list feature.

Covers three layers:
    1. WatchRepository — CRUD + update_after_check
    2. WatchAlert model — direction classification
    3. CLI watch commands — add, list, remove, run (via CliRunner + mocks)
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from atlas.cli.main import app
from atlas.core.models import (
    ScanReport,
    ScanSource,
    TierResult,
    Verdict,
    WatchAlert,
    WatchEntry,
)
from atlas.storage.db import ScanRepository, WatchRepository


# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def watch_repo(tmp_path):
    return WatchRepository(db_path=str(tmp_path / "atlas.db"))


@pytest.fixture
def scan_repo(tmp_path):
    return ScanRepository(db_path=str(tmp_path / "atlas.db"))


@pytest.fixture
def both_repos(tmp_path):
    """Single DB shared by scan and watch repos."""
    db_path = str(tmp_path / "atlas.db")
    return ScanRepository(db_path=db_path), WatchRepository(db_path=db_path)


def _make_scan_report(verdict: Verdict = Verdict.CLEAN) -> ScanReport:
    return ScanReport(
        url="https://example.com",
        domain="example.com",
        final_verdict=verdict,
        tier_results=[TierResult(tier_name="test", flagged=(verdict != Verdict.CLEAN), confidence=0.7)],
        scanned_at=datetime.now(timezone.utc),
        scan_duration_ms=100,
        source=ScanSource.CLI,
    )


def _make_entry(**kwargs) -> WatchEntry:
    defaults = dict(id=1, domain="example.com", url="https://example.com", active=True, check_count=0)
    defaults.update(kwargs)
    return WatchEntry(**defaults)


# ═══════════════════════════════════════════════════════════════
# WatchRepository — CRUD
# ═══════════════════════════════════════════════════════════════


class TestWatchRepositoryCRUD:

    def test_add_watch(self, watch_repo):
        entry = watch_repo.add_watch("example.com", "https://example.com")
        assert entry.id is not None
        assert entry.domain == "example.com"
        assert entry.url == "https://example.com"
        assert entry.active is True
        assert entry.check_count == 0

    def test_add_watch_is_idempotent_reactivates(self, watch_repo):
        """Adding the same domain twice should re-activate, not duplicate."""
        first = watch_repo.add_watch("example.com", "https://example.com")
        watch_repo.remove_watch(first.id)
        second = watch_repo.add_watch("example.com", "https://example.com")
        assert second.id == first.id
        assert second.active is True

    def test_list_watches_empty(self, watch_repo):
        assert watch_repo.list_watches() == []

    def test_list_watches_returns_all(self, watch_repo):
        watch_repo.add_watch("a.com", "https://a.com")
        watch_repo.add_watch("b.com", "https://b.com")
        entries = watch_repo.list_watches()
        assert len(entries) == 2
        domains = {e.domain for e in entries}
        assert domains == {"a.com", "b.com"}

    def test_list_active_only_excludes_removed(self, watch_repo):
        e = watch_repo.add_watch("a.com", "https://a.com")
        watch_repo.add_watch("b.com", "https://b.com")
        watch_repo.remove_watch(e.id)
        active = watch_repo.list_watches(active_only=True)
        assert len(active) == 1
        assert active[0].domain == "b.com"

    def test_get_watch_by_id(self, watch_repo):
        entry = watch_repo.add_watch("example.com", "https://example.com")
        fetched = watch_repo.get_watch(entry.id)
        assert fetched.domain == "example.com"

    def test_get_watch_missing_returns_none(self, watch_repo):
        assert watch_repo.get_watch(9999) is None

    def test_get_watch_by_domain(self, watch_repo):
        watch_repo.add_watch("example.com", "https://example.com")
        found = watch_repo.get_watch_by_domain("example.com")
        assert found is not None
        assert found.domain == "example.com"

    def test_get_watch_by_domain_missing_returns_none(self, watch_repo):
        assert watch_repo.get_watch_by_domain("nope.com") is None

    def test_remove_watch_deactivates(self, watch_repo):
        entry = watch_repo.add_watch("example.com", "https://example.com")
        removed = watch_repo.remove_watch(entry.id)
        assert removed is True
        fetched = watch_repo.get_watch(entry.id)
        assert fetched.active is False

    def test_remove_watch_returns_false_when_missing(self, watch_repo):
        assert watch_repo.remove_watch(9999) is False

    def test_remove_watch_already_inactive_returns_false(self, watch_repo):
        entry = watch_repo.add_watch("example.com", "https://example.com")
        watch_repo.remove_watch(entry.id)
        # Second remove on already-inactive watch
        assert watch_repo.remove_watch(entry.id) is False


class TestWatchRepositoryUpdateAfterCheck:

    def test_updates_verdict_and_check_count(self, watch_repo, scan_repo):
        entry = watch_repo.add_watch("example.com", "https://example.com")
        report = _make_scan_report(Verdict.MEDIUM_RISK)
        scan_id = scan_repo.save_scan(report)

        watch_repo.update_after_check(entry.id, "Medium Risk", scan_id)

        updated = watch_repo.get_watch(entry.id)
        assert updated.last_verdict == "Medium Risk"
        assert updated.last_scan_id == scan_id
        assert updated.check_count == 1
        assert updated.last_checked_at is not None

    def test_check_count_increments_per_run(self, watch_repo, scan_repo):
        entry = watch_repo.add_watch("example.com", "https://example.com")
        for _ in range(3):
            scan_id = scan_repo.save_scan(_make_scan_report())
            watch_repo.update_after_check(entry.id, "Clean", scan_id)
        assert watch_repo.get_watch(entry.id).check_count == 3


# ═══════════════════════════════════════════════════════════════
# WatchAlert — direction classification
# ═══════════════════════════════════════════════════════════════


class TestWatchAlert:

    def test_first_check_direction_is_new(self):
        entry = _make_entry(last_verdict=None)
        alert = WatchAlert.build(entry, Verdict.CLEAN, scan_id=1)
        assert alert.is_new is True
        assert alert.direction == "new"
        assert alert.changed is False  # first check is not a "change"

    def test_unchanged_verdict(self):
        entry = _make_entry(last_verdict="Clean")
        alert = WatchAlert.build(entry, Verdict.CLEAN, scan_id=1)
        assert alert.direction == "unchanged"
        assert alert.changed is False

    def test_escalation_clean_to_medium(self):
        entry = _make_entry(last_verdict="Clean")
        alert = WatchAlert.build(entry, Verdict.MEDIUM_RISK, scan_id=1)
        assert alert.direction == "escalated"
        assert alert.changed is True

    def test_escalation_medium_to_high(self):
        entry = _make_entry(last_verdict="Medium Risk")
        alert = WatchAlert.build(entry, Verdict.HIGH_RISK, scan_id=1)
        assert alert.direction == "escalated"
        assert alert.changed is True

    def test_de_escalation_high_to_clean(self):
        entry = _make_entry(last_verdict="High Risk")
        alert = WatchAlert.build(entry, Verdict.CLEAN, scan_id=1)
        assert alert.direction == "de-escalated"
        assert alert.changed is True

    def test_de_escalation_medium_to_low(self):
        entry = _make_entry(last_verdict="Medium Risk")
        alert = WatchAlert.build(entry, Verdict.LOW_RISK, scan_id=1)
        assert alert.direction == "de-escalated"
        assert alert.changed is True

    def test_alert_fields_populated(self):
        entry = _make_entry(last_verdict="Clean")
        alert = WatchAlert.build(entry, Verdict.HIGH_RISK, scan_id=42)
        assert alert.watch_id == 1
        assert alert.domain == "example.com"
        assert alert.previous_verdict == "Clean"
        assert alert.new_verdict == "High Risk"
        assert alert.scan_id == 42

    def test_all_severity_orderings(self):
        """Confirm escalation works across all verdict pairings."""
        order = [Verdict.CLEAN, Verdict.LOW_RISK, Verdict.MEDIUM_RISK, Verdict.HIGH_RISK]
        for i, lower in enumerate(order):
            for higher in order[i + 1:]:
                entry = _make_entry(last_verdict=lower.value)
                alert = WatchAlert.build(entry, higher, scan_id=1)
                assert alert.direction == "escalated", f"{lower} → {higher}"

                entry2 = _make_entry(last_verdict=higher.value)
                alert2 = WatchAlert.build(entry2, lower, scan_id=1)
                assert alert2.direction == "de-escalated", f"{higher} → {lower}"


# ═══════════════════════════════════════════════════════════════
# CLI integration — using CliRunner
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def patched_repos(tmp_path, monkeypatch):
    """
    Point the CLI's lazy singletons at temp DBs so tests are isolated.
    Returns (scan_repo, watch_repo) for direct setup.
    """
    db_path = str(tmp_path / "atlas.db")
    s_repo = ScanRepository(db_path=db_path)
    w_repo = WatchRepository(db_path=db_path)

    import atlas.cli.main as cli_main
    monkeypatch.setattr(cli_main, "_repo", s_repo)
    monkeypatch.setattr(cli_main, "_watch_repo", w_repo)
    return s_repo, w_repo


class TestWatchAddCLI:

    def test_add_registers_domain(self, runner, patched_repos):
        _, w_repo = patched_repos
        result = runner.invoke(app, ["watch", "add", "example.com"])
        assert result.exit_code == 0
        assert "Now watching" in result.stdout
        entries = w_repo.list_watches()
        assert len(entries) == 1
        assert entries[0].domain == "example.com"

    def test_add_normalizes_url_input(self, runner, patched_repos):
        _, w_repo = patched_repos
        runner.invoke(app, ["watch", "add", "https://evil.com/path"])
        entries = w_repo.list_watches()
        assert entries[0].domain == "evil.com"
        assert entries[0].url == "https://evil.com/path"

    def test_add_reactivates_removed_domain(self, runner, patched_repos):
        _, w_repo = patched_repos
        runner.invoke(app, ["watch", "add", "example.com"])
        entry = w_repo.list_watches()[0]
        w_repo.remove_watch(entry.id)

        result = runner.invoke(app, ["watch", "add", "example.com"])
        assert result.exit_code == 0
        # Should re-activate, not create duplicate
        assert len(w_repo.list_watches()) == 1
        assert w_repo.list_watches()[0].active is True


class TestWatchListCLI:

    def test_list_empty(self, runner, patched_repos):
        result = runner.invoke(app, ["watch", "list"])
        assert result.exit_code == 0
        assert "No domains" in result.stdout

    def test_list_shows_entries(self, runner, patched_repos):
        _, w_repo = patched_repos
        w_repo.add_watch("evil.com", "https://evil.com")
        result = runner.invoke(app, ["watch", "list"])
        assert result.exit_code == 0
        assert "evil.com" in result.stdout

    def test_list_json(self, runner, patched_repos):
        _, w_repo = patched_repos
        w_repo.add_watch("evil.com", "https://evil.com")
        result = runner.invoke(app, ["watch", "list", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert data[0]["domain"] == "evil.com"

    def test_list_csv(self, runner, patched_repos):
        _, w_repo = patched_repos
        w_repo.add_watch("evil.com", "https://evil.com")
        result = runner.invoke(app, ["watch", "list", "--output", "csv"])
        assert result.exit_code == 0
        reader = csv.DictReader(io.StringIO(result.stdout))
        rows = list(reader)
        assert rows[0]["domain"] == "evil.com"


class TestWatchRemoveCLI:

    def test_remove_deactivates(self, runner, patched_repos):
        _, w_repo = patched_repos
        entry = w_repo.add_watch("evil.com", "https://evil.com")
        result = runner.invoke(app, ["watch", "remove", str(entry.id)])
        assert result.exit_code == 0
        assert "Removed" in result.stdout
        assert w_repo.get_watch(entry.id).active is False

    def test_remove_not_found(self, runner, patched_repos):
        result = runner.invoke(app, ["watch", "remove", "9999"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()


class TestWatchRunCLI:

    def _mock_pipeline(self, verdict: Verdict) -> MagicMock:
        pipeline = MagicMock()
        pipeline.tier_names = ["local_blocklist", "heuristics", "typosquat"]
        report = ScanReport(
            url="https://example.com",
            domain="example.com",
            final_verdict=verdict,
            tier_results=[TierResult(
                tier_name="test",
                flagged=(verdict != Verdict.CLEAN),
                confidence=0.7,
            )],
            scanned_at=datetime.now(timezone.utc),
            scan_duration_ms=50,
            source=ScanSource.CLI,
        )
        pipeline.analyze.return_value = report
        return pipeline

    def test_run_empty_watch_list(self, runner, patched_repos, monkeypatch):
        import atlas.cli.main as cli_main
        monkeypatch.setattr(cli_main, "_pipeline", self._mock_pipeline(Verdict.CLEAN))
        result = runner.invoke(app, ["watch", "run"])
        assert result.exit_code == 0
        assert "No active watches" in result.stdout

    def test_run_first_check_shows_new(self, runner, patched_repos, monkeypatch):
        import atlas.cli.main as cli_main
        _, w_repo = patched_repos
        w_repo.add_watch("example.com", "https://example.com")
        monkeypatch.setattr(cli_main, "_pipeline", self._mock_pipeline(Verdict.CLEAN))

        result = runner.invoke(app, ["watch", "run"])
        assert result.exit_code == 0
        assert "example.com" in result.stdout

    def test_run_escalation_detected(self, runner, patched_repos, monkeypatch):
        import atlas.cli.main as cli_main
        s_repo, w_repo = patched_repos
        entry = w_repo.add_watch("example.com", "https://example.com")
        # Seed a previous clean verdict
        scan_id = s_repo.save_scan(_make_scan_report(Verdict.CLEAN))
        w_repo.update_after_check(entry.id, "Clean", scan_id)

        # Now scan returns HIGH_RISK
        monkeypatch.setattr(cli_main, "_pipeline", self._mock_pipeline(Verdict.HIGH_RISK))
        result = runner.invoke(app, ["watch", "run"])
        assert result.exit_code == 0
        assert "1 verdict change" in result.stdout

    def test_run_updates_last_verdict(self, runner, patched_repos, monkeypatch):
        import atlas.cli.main as cli_main
        _, w_repo = patched_repos
        entry = w_repo.add_watch("example.com", "https://example.com")
        monkeypatch.setattr(cli_main, "_pipeline", self._mock_pipeline(Verdict.HIGH_RISK))

        runner.invoke(app, ["watch", "run"])
        updated = w_repo.get_watch(entry.id)
        assert updated.last_verdict == "High Risk"
        assert updated.check_count == 1

    def test_run_json_output(self, runner, patched_repos, monkeypatch):
        import atlas.cli.main as cli_main
        _, w_repo = patched_repos
        w_repo.add_watch("example.com", "https://example.com")
        monkeypatch.setattr(cli_main, "_pipeline", self._mock_pipeline(Verdict.MEDIUM_RISK))

        result = runner.invoke(app, ["watch", "run", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["domain"] == "example.com"
        assert data[0]["new_verdict"] == "Medium Risk"
        assert data[0]["direction"] == "new"

    def test_run_json_changed_only(self, runner, patched_repos, monkeypatch):
        """--changed-only should exclude unchanged entries."""
        import atlas.cli.main as cli_main
        s_repo, w_repo = patched_repos

        # Two watches: one will change, one will stay Clean
        entry_a = w_repo.add_watch("change.com", "https://change.com")
        entry_b = w_repo.add_watch("stable.com", "https://stable.com")

        # Seed stable.com as already Clean
        sid = s_repo.save_scan(_make_scan_report(Verdict.CLEAN))
        w_repo.update_after_check(entry_b.id, "Clean", sid)

        # Mock pipeline: returns HIGH_RISK for all (so change.com escalates,
        # stable.com... let's give stable a different mock)
        # Actually we need domain-specific mocks. Let's use side_effect.
        pipeline = MagicMock()
        pipeline.tier_names = ["test"]
        call_count = [0]

        def analyze(req):
            call_count[0] += 1
            verdict = Verdict.HIGH_RISK if "change" in req.url else Verdict.CLEAN
            return ScanReport(
                url=req.url, domain=req.url.replace("https://", ""),
                final_verdict=verdict,
                tier_results=[TierResult(tier_name="test", flagged=(verdict != Verdict.CLEAN), confidence=0.8)],
                scanned_at=datetime.now(timezone.utc), scan_duration_ms=10,
                source=ScanSource.CLI,
            )

        pipeline.analyze.side_effect = analyze
        monkeypatch.setattr(cli_main, "_pipeline", pipeline)

        result = runner.invoke(app, ["watch", "run", "--output", "json", "--changed-only"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # Only change.com should appear (stable.com is unchanged)
        assert len(data) == 1
        assert data[0]["domain"] == "change.com"

    def test_run_csv_output(self, runner, patched_repos, monkeypatch):
        import atlas.cli.main as cli_main
        _, w_repo = patched_repos
        w_repo.add_watch("example.com", "https://example.com")
        monkeypatch.setattr(cli_main, "_pipeline", self._mock_pipeline(Verdict.CLEAN))

        result = runner.invoke(app, ["watch", "run", "--output", "csv"])
        assert result.exit_code == 0
        reader = csv.DictReader(io.StringIO(result.stdout))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["domain"] == "example.com"
        assert "direction" in rows[0]
