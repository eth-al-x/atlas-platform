"""
atlas.cli.main
Command-line interface for ATLAS.

Usage:
    atlas scan https://example.com
    atlas scan https://example.com --verbose
    atlas scan --file urls.txt
    atlas history --limit 10
    atlas stats
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from atlas.core.config import get_config
from atlas.core.models import ScanReport, ScanRequest, ScanSource, Verdict
from atlas.core.pipeline import AnalysisPipeline
from atlas.storage.db import ScanRepository


app = typer.Typer(
    name="atlas",
    help="ATLAS — A multi-layered defensive security analysis platform.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

# ── Lazy singletons ───────────────────────────────────────────

_pipeline: AnalysisPipeline | None = None
_repo: ScanRepository | None = None


def _get_pipeline() -> AnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline


def _get_repo() -> ScanRepository:
    global _repo
    if _repo is None:
        _repo = ScanRepository()
    return _repo


# ── Display helpers ───────────────────────────────────────────


def _verdict_style(verdict: Verdict) -> tuple[str, str]:
    """Return (icon, rich color) for a verdict."""
    match verdict:
        case Verdict.HIGH_RISK:
            return "🚨", "bold red"
        case Verdict.MEDIUM_RISK:
            return "⚠️ ", "bold yellow"
        case Verdict.LOW_RISK:
            return "📋", "dim yellow"
        case Verdict.CLEAN:
            return "✅", "bold green"


def _print_report(report: ScanReport, verbose: bool = False) -> None:
    """Render a scan report to the terminal using rich."""
    icon, color = _verdict_style(report.final_verdict)

    # Header panel
    header = Text()
    header.append(f"{icon} {report.final_verdict.value}\n", style=color)
    header.append(f"URL:    {report.url}\n", style="dim")
    header.append(f"Domain: {report.domain}\n", style="dim")
    header.append(f"Time:   {report.scan_duration_ms}ms  |  Tiers run: {report.tiers_run}",
                  style="dim")
    console.print(Panel(header, title="[bold]ATLAS Scan Result[/bold]", border_style="blue"))

    # Tier results table
    table = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    table.add_column("Tier", min_width=20)
    table.add_column("Status", min_width=10)
    table.add_column("Confidence", min_width=10, justify="right")
    table.add_column("Time", min_width=8, justify="right")

    for tr in report.tier_results:
        status = "[red]FLAGGED[/red]" if tr.flagged else "[green]Clear[/green]"
        if tr.error:
            status = f"[yellow]Error[/yellow]"
        conf = f"{tr.confidence:.0%}" if tr.flagged else "—"
        table.add_row(tr.display_name, status, conf, f"{tr.duration_ms}ms")

    console.print(table)

    # Verbose details
    if verbose:
        console.print("\n[bold]Detailed Results:[/bold]")
        for tr in report.tier_results:
            if tr.details:
                console.print(f"\n[cyan]{tr.display_name}:[/cyan]")
                for key, value in tr.details.items():
                    console.print(f"  {key}: {value}")
            if tr.error:
                console.print(f"  [yellow]Error: {tr.error}[/yellow]")

    console.print()


# ── Commands ──────────────────────────────────────────────────


@app.command()
def scan(
    url: str = typer.Argument(None, help="URL to analyze"),
    file: Path = typer.Option(None, "--file", "-f", help="Text file with one URL per line"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed tier output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all output except verdict"),
) -> None:
    """Analyze one or more URLs through the tiered security pipeline."""
    # Configure logging based on verbosity — silence noisy libraries
    log_level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(level=log_level, format="%(message)s")
    for noisy in ("httpx", "httpcore", "urllib3", "whois"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    pipeline = _get_pipeline()
    repo = _get_repo()

    urls: list[str] = []

    if file:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        urls = [line.strip() for line in file.read_text().splitlines() if line.strip()]
        if not urls:
            console.print("[yellow]File is empty.[/yellow]")
            raise typer.Exit(1)
    elif url:
        urls = [url]
    else:
        # Interactive mode
        console.print("[bold blue]ATLAS[/bold blue] — Interactive Mode")
        console.print("Enter a URL to scan, or [bold]quit[/bold] to exit.\n")
        while True:
            try:
                user_input = console.input("[blue]atlas>[/blue] ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if user_input.lower() in ("quit", "exit", "q"):
                break
            if user_input:
                request = ScanRequest(url=user_input, source=ScanSource.CLI)
                report = pipeline.analyze(request)
                scan_id = repo.save_scan(report)
                report.id = scan_id
                _print_report(report, verbose=verbose)
        return

    # Single or batch mode
    source = ScanSource.BATCH if file else ScanSource.CLI

    for target_url in urls:
        request = ScanRequest(url=target_url, source=source)
        report = pipeline.analyze(request)
        scan_id = repo.save_scan(report)
        report.id = scan_id

        if quiet:
            icon, _ = _verdict_style(report.final_verdict)
            console.print(f"{icon} {report.final_verdict.value}  {target_url}")
        else:
            _print_report(report, verbose=verbose)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
) -> None:
    """Show recent scan history."""
    logging.basicConfig(level=logging.WARNING)
    repo = _get_repo()
    scans = repo.list_scans(limit=limit)

    if not scans:
        console.print("[dim]No scans recorded yet.[/dim]")
        return

    table = Table(title="Recent Scans", show_header=True, header_style="bold cyan")
    table.add_column("ID", min_width=4, justify="right")
    table.add_column("URL", min_width=30)
    table.add_column("Verdict", min_width=12)
    table.add_column("Time", min_width=8, justify="right")
    table.add_column("Date", min_width=16)

    for s in scans:
        verdict = s["final_verdict"]
        style = "red" if verdict == "High Risk" else ("yellow" if verdict == "Medium Risk" else "green")
        table.add_row(
            str(s["id"]),
            s["url"][:50],
            f"[{style}]{verdict}[/{style}]",
            f"{s['scan_duration_ms'] or 0}ms",
            s["scanned_at"][:16] if s["scanned_at"] else "—",
        )

    console.print(table)


@app.command()
def stats() -> None:
    """Show aggregate scan statistics."""
    logging.basicConfig(level=logging.WARNING)
    repo = _get_repo()
    s = repo.get_stats()

    table = Table(title="ATLAS Statistics", show_header=False, box=None)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Total scans", str(s.total_scans))
    table.add_row("High Risk", f"[red]{s.high_risk}[/red]")
    table.add_row("Medium Risk", f"[yellow]{s.medium_risk}[/yellow]")
    table.add_row("Clean", f"[green]{s.clean}[/green]")
    table.add_row("Scans (last 24h)", str(s.scans_last_24h))

    console.print(table)

    if s.top_flagged_domains:
        console.print("\n[bold]Top Flagged Domains:[/bold]")
        for d in s.top_flagged_domains:
            console.print(f"  {d['domain']}  ({d['count']} hits, {d['final_verdict']})")


# ── Recon subcommand group ────────────────────────────────────

recon_app = typer.Typer(
    name="recon",
    help="Investigative recon tools (DNS, headers, WHOIS, etc.)",
    no_args_is_help=True,
)
app.add_typer(recon_app, name="recon")


def _print_recon_result(result, title: str) -> None:
    """Render a recon result with a header and the structured data."""
    duration = result.data.get("_duration_ms", 0)
    header = Text()
    header.append(f"🔎 {title}\n", style="bold blue")
    header.append(f"Domain: {result.domain}\n", style="dim")
    header.append(f"Time:   {duration}ms", style="dim")
    console.print(Panel(header, border_style="blue"))

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}\n")
        return

    # Dispatch to a per-type renderer
    renderers = {
        "dns": _render_dns,
        "http_headers": _render_http_headers,
        "web_recon": _render_web_recon,
    }
    renderer = renderers.get(result.recon_type)
    if renderer:
        renderer(result)
    console.print()


def _render_dns(result) -> None:
    """Render DNS records as a clean two-column table."""
    records = result.data.get("records", {})
    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Type", min_width=6)
    table.add_column("Value")

    for rtype, values in records.items():
        if isinstance(values, dict) and "error" in values:
            table.add_row(rtype, f"[yellow]({values['error']})[/yellow]")
        elif isinstance(values, list) and values:
            for v in values:
                table.add_row(rtype, v)
        else:
            table.add_row(rtype, "[dim]no records[/dim]")

    console.print(table)


def _render_http_headers(result) -> None:
    """Render HTTP header analysis — status, server, and security scoring."""
    data = result.data
    console.print(f"[bold]Status:[/bold] {data.get('status_code')}   "
                  f"[bold]Server:[/bold] {data.get('server', 'unknown')}   "
                  f"[bold]Redirects:[/bold] {data.get('redirects', 0)}")
    console.print(f"[bold]Content-Type:[/bold] {data.get('content_type', 'unknown')}")

    security = data.get("security", {})
    rating = security.get("rating", "Unknown")
    score = security.get("score", "—")
    rating_color = {"Strong": "green", "Moderate": "yellow", "Weak": "red"}.get(rating, "white")

    console.print(f"\n[bold]Security Header Score:[/bold] "
                  f"[{rating_color}]{rating}[/{rating_color}] ({score})\n")

    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Header", min_width=28)
    table.add_column("Status", min_width=10)
    table.add_column("Description")

    for header_name, info in security.get("headers", {}).items():
        present = info.get("present", False)
        status = "[green]✓ present[/green]" if present else "[red]✗ missing[/red]"
        table.add_row(header_name, status, info.get("description", ""))

    console.print(table)


def _render_web_recon(result) -> None:
    """Render web recon — title, links, forms, scripts, suspicious JS markers."""
    data = result.data

    if data.get("note"):
        console.print(f"[yellow]{data['note']}[/yellow]")
        return

    console.print(f"[bold]Title:[/bold]       {data.get('title') or '[dim](none)[/dim]'}")
    console.print(f"[bold]Description:[/bold] {data.get('description') or '[dim](none)[/dim]'}")
    if data.get("keywords"):
        console.print(f"[bold]Keywords:[/bold]    {data['keywords']}")
    console.print(f"[bold]Page size:[/bold]   {data.get('page_size_bytes', 0):,} bytes")

    # Forms — phishing pages often hinge on these
    forms = data.get("forms", {})
    console.print(f"\n[bold]Forms:[/bold] {forms.get('count', 0)}")
    for f in forms.get("actions", [])[:5]:
        console.print(f"  → {f['method'].upper()} {f['action']}")

    # Scripts
    scripts = data.get("scripts", {})
    console.print(f"\n[bold]Scripts:[/bold] {scripts.get('inline_count', 0)} inline, "
                  f"{scripts.get('external_count', 0)} external")

    # Suspicious JS — only highlight if there's anything notable
    suspicious = data.get("suspicious_js", {})
    if suspicious.get("total_matches", 0) > 0:
        color = "red" if suspicious.get("high_volume") else "yellow"
        console.print(f"\n[bold {color}]Suspicious JS markers: "
                      f"{suspicious['total_matches']} total[/bold {color}]")
        for pattern, count in suspicious.get("patterns", {}).items():
            if count > 0:
                console.print(f"  • {pattern}: {count}")

    # External links — top 5
    links = data.get("external_links", [])
    if links:
        console.print(f"\n[bold]External links:[/bold] {len(links)} total")
        for link in links[:5]:
            console.print(f"  • {link}")
        if len(links) > 5:
            console.print(f"  [dim](+{len(links) - 5} more)[/dim]")


@recon_app.command("dns")
def recon_dns(
    domain: str = typer.Argument(..., help="Domain to look up"),
) -> None:
    """Resolve A, AAAA, MX, TXT, and NS records for a domain."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.core.domain import extract_domain
    from atlas.recon.dns import DNSReconTool

    # Normalize input — accept full URLs too
    clean_domain = extract_domain(domain) if "/" in domain else domain.lower().strip()

    tool = DNSReconTool(get_config())
    result = tool.run(clean_domain)
    _print_recon_result(result, "DNS Lookup")


@recon_app.command("headers")
def recon_headers(
    url: str = typer.Argument(..., help="URL to inspect (e.g. https://example.com)"),
) -> None:
    """Fetch and analyze HTTP response headers, including security headers."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.recon.http_headers import HTTPHeadersReconTool

    tool = HTTPHeadersReconTool(get_config())
    result = tool.run(url)
    _print_recon_result(result, "HTTP Headers")


@recon_app.command("web")
def recon_web(
    url: str = typer.Argument(..., help="URL to scrape (e.g. https://example.com)"),
) -> None:
    """Fetch a page and extract title, meta, links, forms, scripts, and suspicious JS."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.recon.web_recon import WebReconTool

    tool = WebReconTool(get_config())
    result = tool.run(url)
    _print_recon_result(result, "Web Recon")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    app()
