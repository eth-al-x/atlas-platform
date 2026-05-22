"""
atlas.storage.db
SQLite database connection and schema management.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from atlas.core.config import get_config
from atlas.core.models import CorrelationResult, ScanReport, ScanStats, TierResult, Verdict


logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    final_verdict TEXT NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scan_duration_ms INTEGER,
    source TEXT
);

CREATE TABLE IF NOT EXISTS tier_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    tier_name TEXT NOT NULL,
    display_name TEXT,
    flagged BOOLEAN NOT NULL,
    confidence REAL,
    details JSON,
    error TEXT,
    duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    correlator_name TEXT NOT NULL,
    display_name TEXT,
    summary TEXT,
    findings JSON,
    data JSON,
    error TEXT,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(final_verdict);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_tier_scan ON tier_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_correlation_scan ON correlations(scan_id);
"""


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Create a SQLite connection with sensible defaults."""
    path = db_path or get_config().storage.database_path
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def initialize_db(db_path: str | None = None) -> None:
    """Create tables and indexes if they don't exist."""
    conn = get_connection(db_path)
    conn.executescript(_SCHEMA)
    conn.close()
    logger.info("Database initialized at %s", db_path or get_config().storage.database_path)


class ScanRepository:
    """Query interface for persisting and retrieving scan data."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or get_config().storage.database_path
        initialize_db(self.db_path)

    def _conn(self) -> sqlite3.Connection:
        return get_connection(self.db_path)

    def save_scan(self, report: ScanReport) -> int:
        """Persist a scan report and its tier results. Returns the scan ID."""
        conn = self._conn()
        try:
            cursor = conn.execute(
                "INSERT INTO scans (url, domain, final_verdict, scanned_at, scan_duration_ms, source) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (report.url, report.domain, report.final_verdict.value,
                 report.scanned_at.isoformat(), report.scan_duration_ms, report.source.value),
            )
            scan_id = cursor.lastrowid or 0

            for tr in report.tier_results:
                conn.execute(
                    "INSERT INTO tier_results "
                    "(scan_id, tier_name, display_name, flagged, confidence, details, error, duration_ms) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, tr.tier_name, tr.display_name, tr.flagged,
                     tr.confidence, json.dumps(tr.details), tr.error, tr.duration_ms),
                )

            for cr in report.correlations:
                conn.execute(
                    "INSERT INTO correlations "
                    "(scan_id, correlator_name, display_name, summary, findings, data, error, duration_ms) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, cr.correlator_name, cr.display_name, cr.summary,
                     json.dumps(cr.findings), json.dumps(cr.data), cr.error, cr.duration_ms),
                )

            conn.commit()
            logger.debug("Saved scan %d for %s", scan_id, report.url)
            return scan_id
        finally:
            conn.close()

    def save_correlations(self, scan_id: int, correlations: list[CorrelationResult]) -> None:
        """Persist correlation results for an existing scan."""
        conn = self._conn()
        try:
            for cr in correlations:
                conn.execute(
                    "INSERT INTO correlations "
                    "(scan_id, correlator_name, display_name, summary, findings, data, error, duration_ms) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, cr.correlator_name, cr.display_name, cr.summary,
                     json.dumps(cr.findings), json.dumps(cr.data), cr.error, cr.duration_ms),
                )
            conn.commit()
        finally:
            conn.close()

    def get_correlations(self, scan_id: int) -> list[CorrelationResult]:
        """Retrieve correlation results for a scan."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM correlations WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
            return [
                CorrelationResult(
                    correlator_name=row["correlator_name"],
                    display_name=row["display_name"] or "",
                    summary=row["summary"] or "",
                    findings=json.loads(row["findings"]) if row["findings"] else [],
                    data=json.loads(row["data"]) if row["data"] else {},
                    error=row["error"],
                    duration_ms=row["duration_ms"] or 0,
                )
                for row in rows
            ]
        finally:
            conn.close()

    def get_scan(self, scan_id: int) -> ScanReport | None:
        """Retrieve a single scan report by ID."""
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not row:
                return None

            tier_rows = conn.execute(
                "SELECT * FROM tier_results WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()

            corr_rows = conn.execute(
                "SELECT * FROM correlations WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()

            return ScanReport(
                id=row["id"],
                url=row["url"],
                domain=row["domain"],
                final_verdict=Verdict(row["final_verdict"]),
                scan_duration_ms=row["scan_duration_ms"] or 0,
                tier_results=[
                    TierResult(
                        tier_name=tr["tier_name"],
                        display_name=tr["display_name"] or "",
                        flagged=bool(tr["flagged"]),
                        confidence=tr["confidence"] or 0.0,
                        details=json.loads(tr["details"]) if tr["details"] else {},
                        error=tr["error"],
                        duration_ms=tr["duration_ms"] or 0,
                    )
                    for tr in tier_rows
                ],
                correlations=[
                    CorrelationResult(
                        correlator_name=cr["correlator_name"],
                        display_name=cr["display_name"] or "",
                        summary=cr["summary"] or "",
                        findings=json.loads(cr["findings"]) if cr["findings"] else [],
                        data=json.loads(cr["data"]) if cr["data"] else {},
                        error=cr["error"],
                        duration_ms=cr["duration_ms"] or 0,
                    )
                    for cr in corr_rows
                ],
            )
        finally:
            conn.close()

    def list_scans(self, limit: int = 20, offset: int = 0) -> list[dict]:
        """List recent scans with basic metadata."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT id, url, domain, final_verdict, scanned_at, scan_duration_ms "
                "FROM scans ORDER BY scanned_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_stats(self, days: int = 7) -> ScanStats:
        """Aggregate statistics over the specified number of days."""
        conn = self._conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            high = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE final_verdict = ?",
                (Verdict.HIGH_RISK.value,)
            ).fetchone()[0]
            medium = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE final_verdict = ?",
                (Verdict.MEDIUM_RISK.value,)
            ).fetchone()[0]
            clean = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE final_verdict = ?",
                (Verdict.CLEAN.value,)
            ).fetchone()[0]
            recent = conn.execute(
                "SELECT COUNT(*) FROM scans "
                "WHERE scanned_at > datetime('now', '-1 day')"
            ).fetchone()[0]

            top = conn.execute(
                "SELECT domain, COUNT(*) as count, final_verdict "
                "FROM scans WHERE final_verdict != ? "
                "GROUP BY domain ORDER BY count DESC LIMIT 10",
                (Verdict.CLEAN.value,)
            ).fetchall()

            return ScanStats(
                total_scans=total,
                high_risk=high,
                medium_risk=medium,
                clean=clean,
                scans_last_24h=recent,
                top_flagged_domains=[dict(row) for row in top],
            )
        finally:
            conn.close()
