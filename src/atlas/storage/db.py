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

CREATE TABLE IF NOT EXISTS recon_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    recon_type TEXT NOT NULL,
    domain TEXT NOT NULL,
    data JSON,
    error TEXT,
    performed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(final_verdict);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_tier_scan ON tier_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_correlation_scan ON correlations(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_scan ON recon_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_type ON recon_results(recon_type);

CREATE TABLE IF NOT EXISTS watches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMP,
    last_verdict TEXT,
    last_scan_id INTEGER REFERENCES scans(id),
    active BOOLEAN DEFAULT 1,
    check_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_watches_active ON watches(active);
CREATE INDEX IF NOT EXISTS idx_watches_domain ON watches(domain);
"""


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Create a SQLite connection with sensible defaults."""
    path = db_path or get_config().storage.database_path
    # `timeout` is SQLite's busy_timeout under the hood: when a write is
    # blocked by another writer, the call will wait up to this many seconds
    # before raising OperationalError. WAL mode (set below) makes long
    # waits rare, but bursts during concurrent CLI + watch runs can still
    # hit short contention windows.
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ── Defense-in-depth retry for SQLITE_BUSY ────────────────────
# The connect() timeout above is the primary protection. This wrapper
# catches the rare cases where SQLite still raises OperationalError —
# e.g., during writer-vs-checkpoint races in WAL mode under heavy load.

_SQLITE_BUSY_TOKENS = ("database is locked", "database is busy")


def _is_transient_sqlite_error(exc: BaseException) -> bool:
    return (
        isinstance(exc, sqlite3.OperationalError)
        and any(t in str(exc).lower() for t in _SQLITE_BUSY_TOKENS)
    )


def _retry_on_busy(fn):
    """
    Decorator: retry transient SQLITE_BUSY errors with exponential backoff.
    Up to 4 attempts (50ms, 100ms, 200ms delays — total ~350ms worst case).
    Non-transient OperationalErrors (schema mismatch, etc.) pass through.
    """
    import functools
    import time

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        last_exc: BaseException | None = None
        for attempt in range(4):
            try:
                return fn(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                if not _is_transient_sqlite_error(exc):
                    raise
                last_exc = exc
                if attempt < 3:
                    time.sleep(0.05 * (2 ** attempt))
                    logger.warning(
                        "SQLite busy on attempt %d, retrying: %s",
                        attempt + 1, exc,
                    )
        assert last_exc is not None
        raise last_exc

    return wrapped


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

    @_retry_on_busy
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

    @_retry_on_busy
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

    @_retry_on_busy
    def save_recon_results(self, scan_id: int, recon: dict[str, "ReconResult"]) -> None:
        """Persist recon results for an existing scan."""
        from atlas.core.models import ReconResult  # avoid circular at module level

        conn = self._conn()
        try:
            for name, rr in recon.items():
                conn.execute(
                    "INSERT INTO recon_results "
                    "(scan_id, recon_type, domain, data, error, performed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (scan_id, rr.recon_type, rr.domain,
                     json.dumps(rr.data), rr.error,
                     rr.performed_at.isoformat() if rr.performed_at else None),
                )
            conn.commit()
            logger.debug("Saved %d recon results for scan %d", len(recon), scan_id)
        finally:
            conn.close()

    def get_recon_results(self, scan_id: int) -> dict[str, "ReconResult"]:
        """Retrieve recon results for a scan, keyed by recon_type."""
        from atlas.core.models import ReconResult

        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM recon_results WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
            results: dict[str, ReconResult] = {}
            for row in rows:
                rr = ReconResult(
                    recon_type=row["recon_type"],
                    domain=row["domain"],
                    data=json.loads(row["data"]) if row["data"] else {},
                    error=row["error"],
                )
                if row["performed_at"]:
                    from datetime import datetime
                    try:
                        rr.performed_at = datetime.fromisoformat(row["performed_at"])
                    except (ValueError, TypeError):
                        pass
                results[row["recon_type"]] = rr
            return results
        finally:
            conn.close()

    def find_related_scans(
        self,
        exclude_scan_id: int,
        ip: str | None = None,
        asn: str | None = None,
        registrar: str | None = None,
        favicon_hash: int | None = None,
        slash24: str | None = None,
        limit_per_category: int = 10,
    ) -> dict[str, list[dict]]:
        """
        Find scans that share infrastructure attributes with a given scan.

        Uses SQLite's JSON1 extension to query inside the stored recon_results
        JSON without needing a normalized schema. Each match category returns
        up to `limit_per_category` results, ordered by recency.

        Pivot categories: ip, asn, registrar, favicon, slash24
        The slash24 pivot uses SQLite GLOB to find IPs in the same /24 range
        without needing CIDR-aware indexing. The exact-IP pivot is still
        run separately so we can show both kinds of relationships clearly.
        """
        related: dict[str, list[dict]] = {
            "ip": [], "asn": [], "registrar": [], "favicon": [], "slash24": [],
        }
        conn = self._conn()
        try:
            if ip:
                related["ip"] = self._match_recon(
                    conn,
                    recon_type="ip_intel",
                    json_path="$.ip",
                    value=ip,
                    exclude_scan_id=exclude_scan_id,
                    limit=limit_per_category,
                )
            if asn:
                related["asn"] = self._match_recon(
                    conn,
                    recon_type="ip_intel",
                    json_path="$.geolocation.asn",
                    value=asn,
                    exclude_scan_id=exclude_scan_id,
                    limit=limit_per_category,
                )
            if registrar:
                related["registrar"] = self._match_recon(
                    conn,
                    recon_type="whois",
                    json_path="$.registrar",
                    value=registrar,
                    exclude_scan_id=exclude_scan_id,
                    limit=limit_per_category,
                )
            if favicon_hash is not None:
                # MMH3 returns an int; SQLite JSON1 also compares ints, so we
                # pass it through directly. No type coercion needed.
                related["favicon"] = self._match_recon(
                    conn,
                    recon_type="web_recon",
                    json_path="$.favicon.mmh3_hash",
                    value=favicon_hash,
                    exclude_scan_id=exclude_scan_id,
                    limit=limit_per_category,
                )
            if slash24:
                # GLOB pattern matching: '1.2.3.*' matches every IP in 1.2.3.0/24.
                # Also exclude the exact IP if we have one — those are already
                # in related['ip'] and we don't want them appearing in both buckets.
                exclude_ip = ip if ip else None
                related["slash24"] = self._match_recon_glob(
                    conn,
                    recon_type="ip_intel",
                    json_path="$.ip",
                    glob_pattern=f"{slash24}.*",
                    exclude_scan_id=exclude_scan_id,
                    exclude_value=exclude_ip,
                    limit=limit_per_category,
                )
            return related
        finally:
            conn.close()

    def find_scans_in_subnet(
        self,
        cidr: str,
        exclude_scan_id: int | None = None,
        exclude_exact_ip: str | None = None,
        limit: int = 20,
    ) -> list[dict]:
        """
        Find all scans whose resolved IP falls within `cidr`.

        Two-stage strategy: narrow with a string prefix in SQL (cheap and
        index-friendly enough at our scale), then post-filter precisely
        with `ipaddress.ip_network` to handle non-octet-aligned CIDRs.

        Args:
            cidr: Any valid IPv4 CIDR (`1.2.3.0/24`, `203.0.113.0/27`, etc.).
            exclude_scan_id: Omit this scan from results (use when called
                from a correlator on the current scan).
            exclude_exact_ip: Omit scans whose IP matches this exactly —
                useful when stacking with the IP-exact pivot to avoid
                surfacing the same scan in two categories.
            limit: Max rows returned.

        Returns scan rows enriched with `matched_ip` so the caller can
        show *which* IP in the subnet was hit.
        """
        import ipaddress

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            logger.warning("Invalid CIDR %r: %s", cidr, exc)
            return []

        # IPv6 isn't supported yet — the rest of ATLAS resolves only A records.
        if network.version != 4:
            return []

        # Pick the broadest octet-aligned prefix that contains the network.
        # /24 → "a.b.c.", /16 → "a.b.", /8 → "a.". For sub-/24, we still use
        # the /24 prefix and post-filter — false positives are cheap.
        if network.prefixlen >= 24:
            prefix_octets = 3
        elif network.prefixlen >= 16:
            prefix_octets = 2
        elif network.prefixlen >= 8:
            prefix_octets = 1
        else:
            prefix_octets = 0  # extremely broad — let SQL return everything

        if prefix_octets > 0:
            base_parts = str(network.network_address).split(".")
            sql_prefix = ".".join(base_parts[:prefix_octets]) + "."
            sql_where = "AND json_extract(r.data, '$.ip') LIKE ?"
            sql_params = (sql_prefix + "%",)
        else:
            sql_where = ""
            sql_params = ()

        # We pull more than `limit` from SQL because post-filtering may discard rows
        # (when the CIDR is narrower than the prefix). 4x is a comfortable margin.
        sql_limit = max(limit * 4, 100)

        conn = self._conn()
        try:
            rows = conn.execute(
                f"""
                SELECT s.id            AS scan_id,
                       s.domain        AS domain,
                       s.url           AS url,
                       s.final_verdict AS verdict,
                       s.scanned_at    AS scanned_at,
                       json_extract(r.data, '$.ip') AS matched_ip
                FROM recon_results r
                JOIN scans s ON s.id = r.scan_id
                WHERE r.recon_type = 'ip_intel'
                  AND json_extract(r.data, '$.ip') IS NOT NULL
                  {sql_where}
                ORDER BY s.scanned_at DESC
                LIMIT ?
                """,
                (*sql_params, sql_limit),
            ).fetchall()
        finally:
            conn.close()

        results: list[dict] = []
        for row in rows:
            scan_id = row["scan_id"]
            ip_str = row["matched_ip"]
            if exclude_scan_id is not None and scan_id == exclude_scan_id:
                continue
            if exclude_exact_ip is not None and ip_str == exclude_exact_ip:
                continue
            try:
                if ipaddress.ip_address(ip_str) not in network:
                    continue
            except ValueError:
                continue
            results.append(dict(row))
            if len(results) >= limit:
                break

        return results

    @staticmethod
    def _match_recon(
        conn: sqlite3.Connection,
        *,
        recon_type: str,
        json_path: str,
        value: str | int,
        exclude_scan_id: int,
        limit: int,
    ) -> list[dict]:
        """
        Join recon_results → scans to find scans whose recon data has a
        JSON field matching the given value. Returns enriched rows.
        """
        rows = conn.execute(
            """
            SELECT s.id          AS scan_id,
                   s.domain      AS domain,
                   s.url         AS url,
                   s.final_verdict AS verdict,
                   s.scanned_at  AS scanned_at
            FROM recon_results r
            JOIN scans s ON s.id = r.scan_id
            WHERE r.recon_type = ?
              AND json_extract(r.data, ?) = ?
              AND r.scan_id != ?
            ORDER BY s.scanned_at DESC
            LIMIT ?
            """,
            (recon_type, json_path, value, exclude_scan_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _match_recon_glob(
        conn: sqlite3.Connection,
        *,
        recon_type: str,
        json_path: str,
        glob_pattern: str,
        exclude_scan_id: int,
        exclude_value: str | None,
        limit: int,
    ) -> list[dict]:
        """
        Same shape as _match_recon, but uses SQLite GLOB instead of equality.
        Enables CIDR-style "same /24" queries via patterns like '1.2.3.*'.

        Optionally excludes a specific exact value (so a slash24 result
        doesn't duplicate an exact-IP result already in another category).
        Also excludes the JSON null literal '*' patterns return on missing
        fields (json_extract returns NULL → GLOB never matches, so this is
        safe; we mention it because it's a subtle SQLite behavior).
        """
        sql = """
            SELECT s.id            AS scan_id,
                   s.domain        AS domain,
                   s.url           AS url,
                   s.final_verdict AS verdict,
                   s.scanned_at    AS scanned_at,
                   json_extract(r.data, ?) AS matched_value
            FROM recon_results r
            JOIN scans s ON s.id = r.scan_id
            WHERE r.recon_type = ?
              AND json_extract(r.data, ?) GLOB ?
              AND r.scan_id != ?
        """
        params: list = [json_path, recon_type, json_path, glob_pattern, exclude_scan_id]
        if exclude_value is not None:
            sql += " AND json_extract(r.data, ?) != ?"
            params.extend([json_path, exclude_value])
        sql += " ORDER BY s.scanned_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

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
            low = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE final_verdict = ?",
                (Verdict.LOW_RISK.value,)
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
                low_risk=low,
                clean=clean,
                scans_last_24h=recent,
                top_flagged_domains=[dict(row) for row in top],
            )
        finally:
            conn.close()


class WatchRepository:
    """Query interface for the watch list — domains registered for ongoing monitoring."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or get_config().storage.database_path
        initialize_db(self.db_path)

    def _conn(self) -> sqlite3.Connection:
        return get_connection(self.db_path)

    @_retry_on_busy
    def add_watch(self, domain: str, url: str) -> "WatchEntry":
        """
        Register a domain for monitoring.

        Idempotent: if the domain already exists, re-activates it (in case
        it was previously removed) and updates the URL. Implemented as an
        atomic UPSERT so concurrent callers don't race between the
        existence check and the INSERT.
        """
        from atlas.core.models import WatchEntry  # noqa: F401  (used by _row_to_entry)

        conn = self._conn()
        try:
            # Single atomic statement: insert or update on the unique domain.
            # ON CONFLICT clause replaces the prior check-then-INSERT pattern
            # that could race with another writer between the two steps.
            conn.execute(
                """
                INSERT INTO watches (domain, url, active)
                VALUES (?, ?, 1)
                ON CONFLICT(domain) DO UPDATE SET
                    url = excluded.url,
                    active = 1
                """,
                (domain, url),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM watches WHERE domain = ?", (domain,)
            ).fetchone()
            return self._row_to_entry(row)
        finally:
            conn.close()

    def list_watches(self, active_only: bool = False) -> list["WatchEntry"]:
        """Return all watch entries, optionally filtered to active only."""
        from atlas.core.models import WatchEntry

        conn = self._conn()
        try:
            if active_only:
                rows = conn.execute(
                    "SELECT * FROM watches WHERE active = 1 ORDER BY added_at ASC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM watches ORDER BY added_at ASC"
                ).fetchall()
            return [self._row_to_entry(r) for r in rows]
        finally:
            conn.close()

    def get_watch(self, watch_id: int) -> "WatchEntry | None":
        """Retrieve a single watch entry by id."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM watches WHERE id = ?", (watch_id,)
            ).fetchone()
            return self._row_to_entry(row) if row else None
        finally:
            conn.close()

    def get_watch_by_domain(self, domain: str) -> "WatchEntry | None":
        """Retrieve a watch entry by domain name."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM watches WHERE domain = ?", (domain,)
            ).fetchone()
            return self._row_to_entry(row) if row else None
        finally:
            conn.close()

    @_retry_on_busy
    def remove_watch(self, watch_id: int) -> bool:
        """
        Deactivate a watch (soft delete — keeps history).
        Returns True if a record was found and deactivated, False if not found.
        """
        conn = self._conn()
        try:
            cursor = conn.execute(
                "UPDATE watches SET active = 0 WHERE id = ? AND active = 1",
                (watch_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    @_retry_on_busy
    def update_after_check(
        self,
        watch_id: int,
        verdict: str,
        scan_id: int,
    ) -> None:
        """
        Record the outcome of a monitoring check.
        Called once per watch per `atlas watch run` invocation.
        """
        conn = self._conn()
        try:
            conn.execute(
                """
                UPDATE watches
                SET last_checked_at = datetime('now'),
                    last_verdict = ?,
                    last_scan_id = ?,
                    check_count = check_count + 1
                WHERE id = ?
                """,
                (verdict, scan_id, watch_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ── Private helpers ───────────────────────────────────────

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> "WatchEntry":
        from atlas.core.models import WatchEntry
        from datetime import datetime

        def _parse_dt(val: str | None) -> "datetime | None":
            if not val:
                return None
            try:
                return datetime.fromisoformat(val)
            except (ValueError, TypeError):
                return None

        return WatchEntry(
            id=row["id"],
            domain=row["domain"],
            url=row["url"],
            added_at=_parse_dt(row["added_at"]) or __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
            last_checked_at=_parse_dt(row["last_checked_at"]),
            last_verdict=row["last_verdict"],
            last_scan_id=row["last_scan_id"],
            active=bool(row["active"]),
            check_count=row["check_count"] or 0,
        )
