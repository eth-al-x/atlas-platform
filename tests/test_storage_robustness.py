"""
Tests for storage-layer robustness improvements:
  - _retry_on_busy decorator handles transient SQLITE_BUSY errors
  - add_watch is atomic (UPSERT) — survives concurrent adds without races
"""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from atlas.storage.db import (
    ScanRepository,
    WatchRepository,
    _is_transient_sqlite_error,
    _retry_on_busy,
    initialize_db,
)


# ── _is_transient_sqlite_error ────────────────────────────────


class TestIsTransientError:

    def test_database_is_locked_is_transient(self):
        exc = sqlite3.OperationalError("database is locked")
        assert _is_transient_sqlite_error(exc) is True

    def test_database_is_busy_is_transient(self):
        exc = sqlite3.OperationalError("database is busy")
        assert _is_transient_sqlite_error(exc) is True

    def test_locked_with_extra_context_still_matches(self):
        exc = sqlite3.OperationalError("database is locked (cannot rollback)")
        assert _is_transient_sqlite_error(exc) is True

    def test_other_operational_errors_not_transient(self):
        """Schema errors, missing tables, etc. should propagate."""
        exc = sqlite3.OperationalError("no such table: foo")
        assert _is_transient_sqlite_error(exc) is False

    def test_other_exception_types_not_transient(self):
        assert _is_transient_sqlite_error(ValueError("oops")) is False
        assert _is_transient_sqlite_error(sqlite3.IntegrityError("dup")) is False


# ── _retry_on_busy ────────────────────────────────────────────


class TestRetryOnBusy:

    def test_succeeds_first_try(self):
        calls = []

        @_retry_on_busy
        def good():
            calls.append("call")
            return "ok"

        assert good() == "ok"
        assert len(calls) == 1

    def test_retries_until_success(self):
        attempts = {"n": 0}

        @_retry_on_busy
        def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        result = flaky()
        assert result == "ok"
        assert attempts["n"] == 3

    def test_gives_up_after_max_attempts(self):
        attempts = {"n": 0}

        @_retry_on_busy
        def always_busy():
            attempts["n"] += 1
            raise sqlite3.OperationalError("database is locked")

        with pytest.raises(sqlite3.OperationalError, match="locked"):
            always_busy()

        assert attempts["n"] == 4  # 4 attempts per the wrapper

    def test_non_transient_errors_propagate_immediately(self):
        """A schema error should not be retried."""
        attempts = {"n": 0}

        @_retry_on_busy
        def schema_error():
            attempts["n"] += 1
            raise sqlite3.OperationalError("no such table: foo")

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            schema_error()

        assert attempts["n"] == 1  # no retries

    def test_unrelated_exceptions_propagate(self):
        """Non-OperationalErrors should not be retried."""
        @_retry_on_busy
        def value_error():
            raise ValueError("bad input")

        with pytest.raises(ValueError):
            value_error()

    def test_uses_exponential_backoff(self):
        """Successive retries should wait progressively longer."""
        attempts = {"n": 0}
        sleep_calls: list[float] = []

        @_retry_on_busy
        def fails_thrice():
            attempts["n"] += 1
            if attempts["n"] < 4:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            fails_thrice()

        # Three retries → three sleeps with doubling intervals
        assert len(sleep_calls) == 3
        assert sleep_calls[0] < sleep_calls[1] < sleep_calls[2]


# ── add_watch UPSERT atomicity ────────────────────────────────


@pytest.fixture
def tmp_db():
    """Fresh SQLite DB in a temp file; cleaned up automatically."""
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "test_atlas.db")
        initialize_db(path)
        yield path


class TestAddWatchUpsert:

    def test_first_add_creates_entry(self, tmp_db):
        repo = WatchRepository(tmp_db)
        entry = repo.add_watch("example.com", "https://example.com")

        assert entry.domain == "example.com"
        assert entry.url == "https://example.com"
        assert entry.active is True

    def test_re_adding_same_domain_updates_url(self, tmp_db):
        repo = WatchRepository(tmp_db)
        repo.add_watch("example.com", "https://example.com")
        entry = repo.add_watch("example.com", "https://example.com/new-path")

        # Same row, updated URL
        assert entry.url == "https://example.com/new-path"

        # Only one row in the table
        watches = repo.list_watches()
        assert len(watches) == 1

    def test_re_adding_deactivated_watch_reactivates(self, tmp_db):
        repo = WatchRepository(tmp_db)
        first = repo.add_watch("example.com", "https://example.com")
        repo.remove_watch(first.id)

        # Should be inactive now
        deactivated = repo.list_watches()[0]
        assert deactivated.active is False

        # Re-add reactivates
        reactivated = repo.add_watch("example.com", "https://example.com")
        assert reactivated.active is True

        # Still one row total
        assert len(repo.list_watches()) == 1

    def test_concurrent_adds_do_not_duplicate(self, tmp_db):
        """
        The historical pattern (SELECT then INSERT) could race between
        two threads adding the same domain. With UPSERT it's atomic and
        either succeeds with one row, or both succeed with one row.
        """
        errors: list[Exception] = []

        def add_in_thread():
            try:
                # Use a fresh repo per thread to mimic real usage
                WatchRepository(tmp_db).add_watch("race.example.com", "https://race.example.com")
            except Exception as e:  # noqa: BLE001 — collected for test inspection
                errors.append(e)

        threads = [threading.Thread(target=add_in_thread) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors raised, exactly one row stored
        assert not errors, f"unexpected errors: {errors}"
        watches = WatchRepository(tmp_db).list_watches()
        assert len(watches) == 1
        assert watches[0].domain == "race.example.com"
