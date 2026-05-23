"""
atlas.core.export
Structured-output serialization for scan reports, recon results, and stats.

This module is the bridge from ATLAS's internal Pydantic models to the
formats downstream tools want: JSON for programmatic consumers (dashboards,
SIEMs, follow-up pipelines) and CSV for spreadsheet/database ingestion.

Two output formats are supported:

    JSON — full-fidelity dump. The structure mirrors the API's
    InvestigateResponse schema ({scan, recon, correlations}) so consumers
    can ingest CLI and API output through the same parser.

    CSV — flattened, one-row-per-scan summary with the analyst-relevant
    fields. Lossy by design: when you want everything, use JSON.

All emitters return strings rather than writing to disk, so callers can
print to stdout, pipe, or persist as they see fit.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable

from atlas.core.models import (
    CorrelationResult,
    ReconResult,
    ScanReport,
    ScanStats,
)


# ── Constants ─────────────────────────────────────────────────

OUTPUT_FORMATS = ("terminal", "json", "csv")

SCAN_CSV_COLUMNS = (
    "scan_id",
    "url",
    "domain",
    "final_verdict",
    "scanned_at",
    "scan_duration_ms",
    "tiers_run",
    "flagged_tiers",
    "risk_score",
    "risk_band",
    "mitre_techniques",
    "related_domain_count",
)


# ── JSON helpers ──────────────────────────────────────────────


def report_to_dict(
    report: ScanReport,
    recon: dict[str, ReconResult] | None = None,
    correlations: list[CorrelationResult] | None = None,
) -> dict[str, Any]:
    """
    Serialize a ScanReport (plus optional recon and correlations) to a
    plain-Python dict, ready for JSON encoding. The structure matches
    the API's InvestigateResponse so CLI and API output share a schema.

    `recon` and `correlations` are accepted as separate arguments because
    a scan command may not have run recon, and stored correlations may
    differ from what's on the report instance.
    """
    payload: dict[str, Any] = {
        "scan": report.model_dump(mode="json"),
    }
    # Use the report's correlations if none passed explicitly
    corrs = correlations if correlations is not None else report.correlations
    if corrs is not None:
        payload["correlations"] = [c.model_dump(mode="json") for c in corrs]
    if recon is not None:
        payload["recon"] = {
            name: r.model_dump(mode="json") for name, r in recon.items()
        }
    return payload


def report_to_json(
    report: ScanReport,
    recon: dict[str, ReconResult] | None = None,
    correlations: list[CorrelationResult] | None = None,
    indent: int | None = 2,
) -> str:
    """
    Serialize a scan report to a JSON string. Pretty-printed by default;
    pass indent=None for compact output suitable for piping.
    """
    return json.dumps(
        report_to_dict(report, recon=recon, correlations=correlations),
        indent=indent,
        ensure_ascii=False,
    )


def reports_to_json(reports: Iterable[ScanReport], indent: int | None = 2) -> str:
    """Serialize a sequence of ScanReports as a JSON array."""
    return json.dumps(
        [r.model_dump(mode="json") for r in reports],
        indent=indent,
        ensure_ascii=False,
    )


def stats_to_json(stats: ScanStats, indent: int | None = 2) -> str:
    """Serialize a ScanStats object as JSON."""
    return json.dumps(stats.model_dump(mode="json"), indent=indent, ensure_ascii=False)


# ── CSV helpers ───────────────────────────────────────────────


def _flat_row(
    report: ScanReport,
    correlations: list[CorrelationResult] | None = None,
) -> dict[str, Any]:
    """
    Reduce a ScanReport (+ correlations) to a single flat row of the
    most analyst-relevant fields. Lists become semicolon-joined strings.
    """
    corrs = correlations if correlations is not None else (report.correlations or [])
    flagged = [tr.tier_name for tr in report.tier_results if tr.flagged]

    risk_score: float | None = None
    risk_band: str | None = None
    mitre_ids: list[str] = []
    related_count: int = 0

    for cr in corrs:
        if cr.correlator_name == "risk_score" and not cr.error:
            risk_score = cr.data.get("score")
            risk_band = cr.data.get("band")
        elif cr.correlator_name == "mitre" and not cr.error:
            mitre_ids = [f.get("technique_id", "") for f in cr.findings if f.get("technique_id")]
        elif cr.correlator_name == "cross_scan" and not cr.error:
            related_count = cr.data.get("unique_related_domains", 0) or 0

    return {
        "scan_id": report.id or "",
        "url": report.url,
        "domain": report.domain,
        "final_verdict": report.final_verdict.value,
        "scanned_at": report.scanned_at.isoformat(),
        "scan_duration_ms": report.scan_duration_ms,
        "tiers_run": report.tiers_run,
        "flagged_tiers": ";".join(flagged),
        "risk_score": "" if risk_score is None else risk_score,
        "risk_band": risk_band or "",
        "mitre_techniques": ";".join(mitre_ids),
        "related_domain_count": related_count,
    }


def report_to_csv(
    report: ScanReport,
    correlations: list[CorrelationResult] | None = None,
    header: bool = True,
) -> str:
    """
    Serialize a single scan report as a one-row CSV.
    Pass header=False when appending to an existing CSV stream.
    """
    return reports_to_csv([report], all_correlations=[correlations] if correlations is not None else None, header=header)


def reports_to_csv(
    reports: list[ScanReport],
    all_correlations: list[list[CorrelationResult] | None] | None = None,
    header: bool = True,
) -> str:
    """
    Serialize a sequence of scan reports as a multi-row CSV.

    Pass `all_correlations` as a parallel list (one entry per report) when
    correlations were fetched separately from the reports. Otherwise the
    correlations on each report instance are used.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=SCAN_CSV_COLUMNS, extrasaction="ignore")
    if header:
        writer.writeheader()
    for i, report in enumerate(reports):
        corrs = all_correlations[i] if all_correlations else None
        writer.writerow(_flat_row(report, correlations=corrs))
    return buf.getvalue()


def history_to_csv(rows: list[dict]) -> str:
    """
    Serialize the output of ScanRepository.list_scans() (already dict-shaped)
    as a CSV. Uses a narrower column set since the list endpoint only stores
    high-level metadata, not full tier results.
    """
    columns = ("id", "url", "domain", "final_verdict", "scanned_at", "scan_duration_ms")
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def stats_to_csv(stats: ScanStats) -> str:
    """
    Serialize aggregate stats as a two-column key/value CSV.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(("metric", "value"))
    writer.writerow(("total_scans", stats.total_scans))
    writer.writerow(("high_risk", stats.high_risk))
    writer.writerow(("medium_risk", stats.medium_risk))
    writer.writerow(("low_risk", stats.low_risk))
    writer.writerow(("clean", stats.clean))
    writer.writerow(("scans_last_24h", stats.scans_last_24h))
    return buf.getvalue()
