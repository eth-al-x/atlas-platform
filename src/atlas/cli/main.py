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

import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from atlas.core.config import get_config
from atlas.core.models import ReconResult, ScanReport, ScanRequest, ScanSource, Verdict
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
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """Analyze one or more URLs through the tiered security pipeline."""
    from atlas.core.export import (
        OUTPUT_FORMATS, report_to_json, reports_to_csv,
    )
    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use one of: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)
    structured = output != "terminal"

    # Configure logging based on verbosity — silence noisy libraries
    # Structured output forces silent logging so JSON/CSV stays parseable.
    if structured:
        log_level = logging.WARNING
    else:
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
        if structured:
            console.print("[red]Interactive mode is not available with --output json/csv.[/red]")
            raise typer.Exit(2)
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

    # Collect reports — print or emit at the end based on output format
    collected_reports: list[ScanReport] = []

    for target_url in urls:
        request = ScanRequest(url=target_url, source=source)
        report = pipeline.analyze(request)
        scan_id = repo.save_scan(report)
        report.id = scan_id
        collected_reports.append(report)

        if structured:
            # Defer all output until the end so we can produce a single
            # well-formed JSON document or CSV stream.
            continue

        if quiet:
            icon, _ = _verdict_style(report.final_verdict)
            console.print(f"{icon} {report.final_verdict.value}  {target_url}")
        else:
            _print_report(report, verbose=verbose)

    # ── Structured emission ───────────────────────────────────
    if output == "json":
        if len(collected_reports) == 1:
            typer.echo(report_to_json(collected_reports[0]))
        else:
            from atlas.core.export import reports_to_json
            typer.echo(reports_to_json(collected_reports))
    elif output == "csv":
        typer.echo(reports_to_csv(collected_reports), nl=False)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """Show recent scan history."""
    from atlas.core.export import OUTPUT_FORMATS, history_to_csv

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use one of: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)

    logging.basicConfig(level=logging.WARNING)
    repo = _get_repo()
    scans = repo.list_scans(limit=limit)

    # Structured output: dump and return
    if output == "json":
        typer.echo(json.dumps(scans, indent=2, default=str))
        return
    if output == "csv":
        typer.echo(history_to_csv(scans), nl=False)
        return

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
        style = "red" if verdict == "High Risk" else ("yellow" if verdict == "Medium Risk" else ("dim yellow" if verdict == "Low Risk" else "green"))
        table.add_row(
            str(s["id"]),
            s["url"][:50],
            f"[{style}]{verdict}[/{style}]",
            f"{s['scan_duration_ms'] or 0}ms",
            s["scanned_at"][:16] if s["scanned_at"] else "—",
        )

    console.print(table)


@app.command()
def stats(
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """Show aggregate scan statistics."""
    from atlas.core.export import OUTPUT_FORMATS, stats_to_csv, stats_to_json

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use one of: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)

    logging.basicConfig(level=logging.WARNING)
    repo = _get_repo()
    s = repo.get_stats()

    if output == "json":
        typer.echo(stats_to_json(s))
        return
    if output == "csv":
        typer.echo(stats_to_csv(s), nl=False)
        return

    table = Table(title="ATLAS Statistics", show_header=False, box=None)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Total scans", str(s.total_scans))
    table.add_row("High Risk", f"[red]{s.high_risk}[/red]")
    table.add_row("Medium Risk", f"[yellow]{s.medium_risk}[/yellow]")
    table.add_row("Low Risk", f"[dim yellow]{s.low_risk}[/dim yellow]")
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
        "whois": _render_whois,
        "ip_intel": _render_ip_intel,
        "crtsh": _render_crtsh,
        "urlscan": _render_urlscan,
        "subdomains": _render_subdomains,
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


@recon_app.command("whois")
def recon_whois(
    domain: str = typer.Argument(..., help="Domain to look up WHOIS for"),
) -> None:
    """Fetch domain registration details — registrar, dates, name servers."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3", "whois"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.core.domain import extract_domain
    from atlas.recon.whois_lookup import WhoisReconTool

    clean_domain = extract_domain(domain) if "/" in domain else domain.lower().strip()
    tool = WhoisReconTool(get_config())
    result = tool.run(clean_domain)
    _print_recon_result(result, "WHOIS")


@recon_app.command("ip")
def recon_ip(
    domain: str = typer.Argument(..., help="Domain to resolve and look up"),
) -> None:
    """Resolve a domain to an IP and query free reputation sources."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.core.domain import extract_domain
    from atlas.recon.ip_intel import IPIntelReconTool

    clean_domain = extract_domain(domain) if "/" in domain else domain.lower().strip()
    tool = IPIntelReconTool(get_config())
    result = tool.run(clean_domain)
    _print_recon_result(result, "IP Intelligence")


@recon_app.command("crtsh")
def recon_crtsh(
    domain: str = typer.Argument(..., help="Domain to look up in CT logs"),
) -> None:
    """Search Certificate Transparency logs (crt.sh) for cert history and subdomains."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.core.domain import extract_domain
    from atlas.recon.crtsh import CrtShReconTool

    clean_domain = extract_domain(domain) if "/" in domain else domain.lower().strip()
    tool = CrtShReconTool(get_config())
    result = tool.run(clean_domain)
    _print_recon_result(result, "Certificate Transparency (crt.sh)")


@recon_app.command("urlscan")
def recon_urlscan(
    url: str = typer.Argument(..., help="URL to scan in urlscan.io's sandbox browser"),
) -> None:
    """Submit a URL to urlscan.io for sandboxed browser analysis (~20-30 sec)."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from rich.progress import Progress, SpinnerColumn, TextColumn

    from atlas.recon.urlscan import URLScanReconTool

    tool = URLScanReconTool(get_config())

    # Show a progress spinner during the synchronous submit + poll cycle.
    # transient=True clears the spinner from the terminal after completion.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(
            description=f"Submitting {url} to urlscan.io and waiting for results...",
            total=None,
        )
        result = tool.run(url)

    _print_recon_result(result, "urlscan.io (Sandbox Browser Analysis)")


@recon_app.command("subdomains")
def recon_subdomains(
    domain: str = typer.Argument(..., help="Domain to enumerate subdomains for"),
    wordlist: str = typer.Option(None, "--wordlist", "-w",
                                 help="Path to custom wordlist (default: built-in ~700 entries)"),
) -> None:
    """Brute-force discover subdomains via concurrent DNS resolution against a wordlist."""
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3", "dns"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from atlas.core.domain import extract_domain
    from atlas.recon.subdomains import (
        SubdomainReconTool,
        ensure_acknowledged,
        mark_acknowledged,
    )
    from rich.progress import Progress, SpinnerColumn, TextColumn

    # One-time warning before any active recon happens
    if not ensure_acknowledged():
        console.print()
        console.print(Panel(
            Text(
                "⚠  Active Recon Notice\n\n"
                "Subdomain enumeration generates real DNS queries against\n"
                "public infrastructure. Running this against domains you don't\n"
                "own or have permission to test may violate terms of service\n"
                "or local laws. Use responsibly.\n\n"
                "This warning will only be shown once.",
                style="bold yellow",
            ),
            border_style="yellow",
        ))
        if not typer.confirm("\nProceed?", default=True):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)
        mark_acknowledged()
        console.print()

    clean_domain = extract_domain(domain) if "/" in domain else domain.lower().strip()
    tool = SubdomainReconTool(get_config())

    context = {}
    if wordlist:
        context["wordlist_path"] = wordlist

    # Spinner during the (potentially 10-30s) enumeration run
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(
            description=f"Enumerating subdomains for {clean_domain}...",
            total=None,
        )
        result = tool.run(clean_domain, **context)

    _print_recon_result(result, "Subdomain Enumeration")


def _render_subdomains(result) -> None:
    """Render subdomain enumeration results — count, hostnames, IPs."""
    data = result.data
    discovered = data.get("discovered_subdomains", [])
    count = data.get("discovered_count", 0)

    console.print(f"[bold]Discovered:[/bold]    {count} subdomains")
    console.print(f"[bold]Wordlist:[/bold]      {data.get('wordlist_size', 0)} entries")
    console.print(f"[bold]Attempts:[/bold]      {data.get('attempts', 0)}")
    console.print(f"[bold]Duration:[/bold]      {data.get('duration_seconds', 0)}s")
    console.print(f"[bold]Rate limit:[/bold]    {data.get('queries_per_second', 0)} qps")

    if not discovered:
        console.print("\n[dim]No subdomains resolved against the wordlist.[/dim]")
        return

    console.print(f"\n[bold cyan]Discovered subdomains[/bold cyan]")

    # Show all discoveries with their IPs — these are the operational findings
    for entry in discovered:
        hostname = entry["hostname"]
        ips = entry.get("ips", [])
        ip_display = ", ".join(ips) if ips else "[dim]no IPs[/dim]"
        console.print(f"  • {hostname:40s}  → {ip_display}")


# ── Renderers for WHOIS and IP Intel ──────────────────────────


def _render_whois(result) -> None:
    """Render WHOIS data — registrar, dates, status, name servers."""
    data = result.data
    status = data.get("status", "unknown")
    status_color = {
        "active": "green",
        "expiring soon": "yellow",
        "expired": "red",
        "unknown": "dim",
    }.get(status, "white")

    console.print(f"[bold]Registrar:[/bold]      {data.get('registrar') or '[dim](unknown)[/dim]'}")
    if data.get("registrant_org"):
        console.print(f"[bold]Registrant:[/bold]     {data['registrant_org']}")
    if data.get("country"):
        console.print(f"[bold]Country:[/bold]        {data['country']}")

    console.print(f"\n[bold]Status:[/bold]         [{status_color}]{status}[/{status_color}]")

    if data.get("age_years") is not None:
        console.print(f"[bold]Age:[/bold]            {data['age_years']} years "
                      f"({data['age_days']} days)")

    if data.get("creation_date"):
        console.print(f"[bold]Created:[/bold]        {data['creation_date'][:10]}")
    if data.get("expiration_date"):
        console.print(f"[bold]Expires:[/bold]        {data['expiration_date'][:10]} "
                      f"(in {data.get('expires_in_days', '?')} days)")
    if data.get("updated_date"):
        console.print(f"[bold]Last updated:[/bold]   {data['updated_date'][:10]}")

    name_servers = data.get("name_servers", [])
    if name_servers:
        console.print(f"\n[bold]Name servers:[/bold]")
        for ns in name_servers:
            console.print(f"  • {ns}")


def _render_ip_intel(result) -> None:
    """Render IP intelligence — geolocation, ASN, ports, vulnerabilities."""
    data = result.data
    console.print(f"[bold]IP address:[/bold] {data.get('ip', 'unknown')}")

    geo = data.get("geolocation", {})
    if geo.get("error"):
        console.print(f"\n[yellow]Geolocation error: {geo['error']}[/yellow]")
    else:
        console.print(f"\n[bold cyan]Geolocation[/bold cyan]")
        location_parts = [geo.get("city"), geo.get("region"), geo.get("country")]
        location = ", ".join(p for p in location_parts if p) or "unknown"
        console.print(f"  Location: {location}")
        if geo.get("isp"):
            console.print(f"  ISP:      {geo['isp']}")
        if geo.get("organization"):
            console.print(f"  Org:      {geo['organization']}")
        if geo.get("asn"):
            console.print(f"  ASN:      {geo['asn']}")
        if geo.get("timezone"):
            console.print(f"  Timezone: {geo['timezone']}")

    exposure = data.get("exposure", {})
    if exposure.get("error"):
        console.print(f"\n[yellow]Exposure check error: {exposure['error']}[/yellow]")
    elif exposure.get("note"):
        console.print(f"\n[dim]{exposure['note']}[/dim]")
    else:
        console.print(f"\n[bold cyan]Exposure (Shodan InternetDB)[/bold cyan]")
        ports = exposure.get("open_ports", [])
        if ports:
            console.print(f"  Open ports:   {', '.join(str(p) for p in ports)}")
        else:
            console.print(f"  Open ports:   none reported")

        tags = exposure.get("tags", [])
        if tags:
            console.print(f"  Tags:         {', '.join(tags)}")

        vulns = exposure.get("vulnerabilities", [])
        if vulns:
            vuln_color = "red" if len(vulns) > 5 else "yellow"
            console.print(f"  [{vuln_color}]Vulnerabilities: {len(vulns)} CVEs[/{vuln_color}]")
            # Show the first 5 CVE IDs
            for cve in vulns[:5]:
                console.print(f"    • {cve}")
            if len(vulns) > 5:
                console.print(f"    [dim](+{len(vulns) - 5} more)[/dim]")
        else:
            console.print(f"  Vulnerabilities: none reported")

        cpes = exposure.get("cpes", [])
        if cpes:
            console.print(f"  Software:     {len(cpes)} components identified")


def _render_crtsh(result) -> None:
    """Render CT log data — cert counts, issuers, discovered subdomains."""
    data = result.data
    total = data.get("total_certs", 0)
    recent = data.get("recent_certs_30d", 0)

    if total == 0:
        console.print("[dim]No certificates found in CT logs.[/dim]")
        return

    # Headline metrics
    console.print(f"[bold]Total certs in CT logs:[/bold]  {total}")

    recent_color = "yellow" if recent > 10 else ("red" if recent > 30 else "green")
    console.print(f"[bold]Issued in last 30 days:[/bold]  "
                  f"[{recent_color}]{recent}[/{recent_color}]")

    if data.get("oldest_cert_date"):
        console.print(f"[bold]Oldest cert:[/bold]             {data['oldest_cert_date'][:10]}")
    if data.get("newest_cert_date"):
        console.print(f"[bold]Newest cert:[/bold]             {data['newest_cert_date'][:10]}")

    # Issuer breakdown
    issuers = data.get("issuers", {})
    if issuers:
        console.print(f"\n[bold cyan]Top issuers[/bold cyan]")
        for issuer, count in issuers.items():
            console.print(f"  • {issuer}: {count} certs")

    # Discovered subdomains — the most operationally useful part
    subdomains = data.get("unique_subdomains", [])
    wildcards = data.get("wildcard_subdomains", [])

    console.print(f"\n[bold cyan]Discovered subdomains[/bold cyan] "
                  f"({len(subdomains)} regular + {len(wildcards)} wildcard)")

    for sub in subdomains[:20]:
        console.print(f"  • {sub}")
    if len(subdomains) > 20:
        console.print(f"  [dim](+{len(subdomains) - 20} more — use --verbose to see all)[/dim]")

    if wildcards:
        console.print(f"\n[bold]Wildcard certs:[/bold]")
        for w in wildcards[:5]:
            console.print(f"  • {w}")


def _render_urlscan(result) -> None:
    """Render urlscan.io results — verdict, screenshot link, contacted infrastructure."""
    data = result.data

    # If the scan was submitted but didn't complete, show what we have
    if data.get("note"):
        console.print(f"[yellow]{data['note']}[/yellow]")
        if data.get("report_url"):
            console.print(f"[bold]Report URL:[/bold] {data['report_url']}")
            console.print("[dim](results may be available there in a few moments)[/dim]")
        return

    # Headline verdict
    malicious = data.get("malicious", False)
    score = data.get("score", 0)
    tags = data.get("tags", [])

    if malicious:
        console.print(f"[bold red]urlscan verdict: MALICIOUS[/bold red]   "
                      f"Score: [red]{score}[/red]")
    elif score > 0:
        console.print(f"[bold yellow]urlscan verdict: Suspicious[/bold yellow]   "
                      f"Score: [yellow]{score}[/yellow]")
    else:
        console.print(f"[bold green]urlscan verdict: Clean[/bold green]   Score: 0")

    if tags:
        console.print(f"[bold]Tags:[/bold] {', '.join(tags)}")

    # Links to the urlscan report and screenshot
    console.print()
    if data.get("report_url"):
        console.print(f"[bold]Report:[/bold]     {data['report_url']}")
    if data.get("screenshot_url"):
        console.print(f"[bold]Screenshot:[/bold] {data['screenshot_url']}")
    if data.get("scanned_url"):
        console.print(f"[bold]Final URL:[/bold]  {data['scanned_url']}")

    # Where the page actually loaded from
    page = data.get("page", {})
    if page.get("ip") or page.get("country"):
        console.print(f"\n[bold cyan]Page loaded from[/bold cyan]")
        if page.get("ip"):
            console.print(f"  IP:       {page['ip']}")
        if page.get("country"):
            console.print(f"  Country:  {page['country']}")
        if page.get("server"):
            console.print(f"  Server:   {page['server']}")
        if page.get("umbrella_rank") is not None:
            rank = page["umbrella_rank"]
            note = " (very popular)" if rank < 10000 else ""
            console.print(f"  Popularity rank: {rank:,}{note}")

    # Behavioral stats from the sandbox
    stats = data.get("stats", {})
    if stats.get("total_requests"):
        console.print(f"\n[bold cyan]Sandbox behavior[/bold cyan]")
        console.print(f"  Total network requests:   {stats.get('total_requests', 0)}")
        console.print(f"  Unique IPs contacted:     {stats.get('unique_ips', 0)}")
        console.print(f"  Unique domains:           {stats.get('unique_domains', 0)}")
        console.print(f"  Unique countries:         {stats.get('unique_countries', 0)}")

        mal_reqs = stats.get("malicious_requests", 0)
        if mal_reqs > 0:
            console.print(f"  [red]Malicious requests:       {mal_reqs}[/red]")

    # Show top contacted domains — useful for IoC extraction
    domains = data.get("contacted_domains", [])
    if domains:
        console.print(f"\n[bold]Contacted domains ({len(domains)}):[/bold]")
        for d in domains[:10]:
            console.print(f"  • {d}")
        if len(domains) > 10:
            console.print(f"  [dim](+{len(domains) - 10} more)[/dim]")


# ── Unified investigate command ───────────────────────────────


@app.command()
def investigate(
    target: str = typer.Argument(..., help="Domain or URL to investigate"),
    skip_scan: bool = typer.Option(False, "--skip-scan", help="Skip the threat verdict pipeline"),
    skip_slow: bool = typer.Option(False, "--skip-slow",
                                   help="Skip slow tools (urlscan.io adds ~30s)"),
    with_subdomains: bool = typer.Option(False, "--with-subdomains",
                                          help="Also run active subdomain enumeration (~15s)"),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """
    Run all recon tools plus the threat analysis pipeline on a target.

    This is the flagship command for investigating a suspicious domain:
    one input, full output across DNS, WHOIS, IP intel, CT logs, HTTP
    headers, web content, urlscan sandbox analysis, and the tiered
    threat verdict.
    """
    from atlas.core.export import OUTPUT_FORMATS, report_to_csv, report_to_json

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use one of: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)
    structured = output != "terminal"

    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3", "whois", "dns"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from rich.progress import Progress, SpinnerColumn, TextColumn

    from atlas.core.domain import extract_domain, normalize_url
    from atlas.recon.crtsh import CrtShReconTool
    from atlas.recon.dns import DNSReconTool
    from atlas.recon.http_headers import HTTPHeadersReconTool
    from atlas.recon.ip_intel import IPIntelReconTool
    from atlas.recon.subdomains import (
        SubdomainReconTool, ensure_acknowledged, mark_acknowledged,
    )
    from atlas.recon.urlscan import URLScanReconTool
    from atlas.recon.web_recon import WebReconTool
    from atlas.recon.whois_lookup import WhoisReconTool

    config = get_config()
    clean_domain = extract_domain(target) if "/" in target else target.lower().strip()
    full_url = normalize_url(target if "/" in target else clean_domain)

    # Active-recon ack check happens once, before the investigation starts,
    # so the warning doesn't interrupt mid-flow.
    if with_subdomains and structured:
        console.print(
            "[red]--with-subdomains is interactive; not available with --output json/csv.[/red]"
        )
        raise typer.Exit(2)

    if with_subdomains and not ensure_acknowledged():
        console.print()
        console.print(Panel(
            Text(
                "⚠  Active Recon Notice\n\n"
                "Subdomain enumeration generates real DNS queries against\n"
                "public infrastructure. Running this against domains you don't\n"
                "own or have permission to test may violate terms of service\n"
                "or local laws. Use responsibly.\n\n"
                "This warning will only be shown once.",
                style="bold yellow",
            ),
            border_style="yellow",
        ))
        if not typer.confirm("\nProceed?", default=True):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)
        mark_acknowledged()

    # Header for the whole investigation
    if not structured:
        console.print()
        console.print(Panel(
            Text(f"🔬 Investigating: {clean_domain}", style="bold blue"),
            border_style="blue",
        ))
        console.print()

    # ── Threat verdict (unless skipped) ──────────────────────
    # report and scan_id may be None if skip_scan is set
    report = None
    scan_id = None
    repo = _get_repo()
    if not skip_scan:
        if not structured:
            console.print("[bold cyan]━━━ Threat Analysis ━━━[/bold cyan]\n")
        pipeline = _get_pipeline()
        request = ScanRequest(url=full_url, source=ScanSource.CLI)
        report = pipeline.analyze(request)
        scan_id = repo.save_scan(report)
        report.id = scan_id
        if not structured:
            _print_report(report)

    # ── Recon tools in sequence ──────────────────────────────
    tools = [
        ("━━━ DNS Records ━━━", DNSReconTool(config), clean_domain, "DNS Lookup", False),
        ("━━━ WHOIS ━━━", WhoisReconTool(config), clean_domain, "WHOIS", False),
        ("━━━ IP Intelligence ━━━", IPIntelReconTool(config), clean_domain,
         "IP Intelligence", False),
        ("━━━ Certificate Transparency ━━━", CrtShReconTool(config), clean_domain,
         "Certificate Transparency (crt.sh)", False),
        ("━━━ HTTP Headers ━━━", HTTPHeadersReconTool(config), full_url,
         "HTTP Headers", False),
        ("━━━ Web Content ━━━", WebReconTool(config), full_url, "Web Recon", False),
        ("━━━ urlscan.io Sandbox ━━━", URLScanReconTool(config), full_url,
         "urlscan.io (Sandbox Browser Analysis)", True),  # True = slow
    ]

    # Optional active-recon step
    if with_subdomains:
        tools.append(
            ("━━━ Subdomain Enumeration ━━━", SubdomainReconTool(config), clean_domain,
             "Subdomain Enumeration", True)
        )

    # Accumulate recon results for correlation
    recon_results: dict[str, ReconResult] = {}

    for section_header, tool, target_input, render_title, is_slow in tools:
        if is_slow and skip_slow:
            continue

        if not structured:
            console.print(f"\n[bold cyan]{section_header}[/bold cyan]\n")

        # Wrap slow tools in a progress spinner (only meaningful in terminal mode)
        if is_slow and not structured:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                progress.add_task(
                    description=f"Running {tool.display_name} (this can take ~30s)...",
                    total=None,
                )
                result = tool.run(target_input)
        else:
            result = tool.run(target_input)

        recon_results[tool.name] = result
        if not structured:
            _print_recon_result(result, render_title)

    # ── Correlations ─────────────────────────────────────────
    if not structured:
        console.print(f"\n[bold cyan]━━━ Correlations ━━━[/bold cyan]\n")
    from atlas.correlate.pipeline import CorrelationPipeline
    from atlas.core.models import CorrelationContext

    correlations: list = []
    if report is not None:
        correlation_pipeline = CorrelationPipeline(config=config, repo=repo)
        context = CorrelationContext(scan=report, recon=recon_results)
        correlations = correlation_pipeline.correlate(context)

        # Attach + persist correlations against this scan
        report.correlations = correlations
        if scan_id:
            repo.save_recon_results(scan_id, recon_results)
            repo.save_correlations(scan_id, correlations)

    if not structured:
        for cr in correlations:
            _print_correlation(cr)
        return

    # ── Structured emission ───────────────────────────────────
    # If --skip-scan was used we may not have a scan report; build a minimal
    # report-shaped payload so JSON/CSV output is still well-formed.
    if report is None:
        # No scan was run — emit just the recon data
        payload = {
            "scan": None,
            "recon": {name: r.model_dump(mode="json") for name, r in recon_results.items()},
            "correlations": [],
        }
        if output == "json":
            typer.echo(json.dumps(payload, indent=2, default=str))
        elif output == "csv":
            # No scan summary available; emit empty CSV with just the header
            from atlas.core.export import SCAN_CSV_COLUMNS
            import csv as _csv, io as _io
            buf = _io.StringIO()
            _csv.DictWriter(buf, fieldnames=SCAN_CSV_COLUMNS).writeheader()
            typer.echo(buf.getvalue(), nl=False)
        return

    if output == "json":
        typer.echo(report_to_json(report, recon=recon_results, correlations=correlations))
    elif output == "csv":
        typer.echo(report_to_csv(report, correlations=correlations), nl=False)


def _print_correlation(cr) -> None:
    """Render a single CorrelationResult."""
    from rich.panel import Panel

    if cr.error:
        console.print(Panel(
            f"[bold red]Error:[/bold red] {cr.error}",
            title=f"❌ {cr.display_name}",
            border_style="red",
        ))
        return

    # Compose body
    body = f"[bold]{cr.summary}[/bold]\n"
    if cr.findings:
        body += "\n"
        for f in cr.findings[:10]:  # cap to keep output sane
            if cr.correlator_name == "risk_score":
                body += f"  • [yellow]+{f.get('points', 0)}[/yellow] — {f.get('reason', '')}\n"
            elif cr.correlator_name == "timeline":
                body += f"  • [cyan]{f.get('date', '')[:10]}[/cyan] — {f.get('event', '')}\n"
            elif cr.correlator_name == "mitre":
                body += f"  • [magenta]{f.get('technique_id')}[/magenta] {f.get('name')} ([dim]{f.get('tactic')}[/dim])\n"
            elif cr.correlator_name == "cross_scan":
                verdict = f.get("verdict", "?")
                v_color = (
                    "red" if verdict == "High Risk"
                    else "yellow" if verdict == "Medium Risk"
                    else "dim yellow" if verdict == "Low Risk"
                    else "green"
                )
                infra_hint = " [dim](common infra)[/dim]" if f.get("is_common_infra") else ""
                body += (
                    f"  • [cyan]{f.get('label')}[/cyan] "
                    f"[bold]{f.get('domain')}[/bold] "
                    f"([{v_color}]{verdict}[/{v_color}]) "
                    f"— {f.get('matched_value')}{infra_hint}\n"
                )
        if len(cr.findings) > 10:
            body += f"  [dim]...and {len(cr.findings) - 10} more[/dim]\n"

    # Observations for timeline
    obs = cr.data.get("observations", [])
    if obs:
        body += "\n[bold]Observations:[/bold]\n"
        for o in obs:
            body += f"  • {o}\n"

    console.print(Panel(body.rstrip(), title=f"🔗 {cr.display_name}", border_style="cyan"))


# ── Correlate subcommand ──────────────────────────────────────


@app.command()
def correlate(
    scan_id: int = typer.Argument(..., help="Scan ID to re-correlate."),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """
    Run correlators against an existing scan (without re-running tiers/recon).

    Useful for re-analyzing past scans after adding new correlators, or for
    inspecting what synthesis a scan produces without re-paying the cost
    of fresh recon.
    """
    from atlas.core.export import OUTPUT_FORMATS, report_to_csv, report_to_json

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use one of: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)

    repo = _get_repo()
    report = repo.get_scan(scan_id)
    if not report:
        if output == "terminal":
            console.print(f"[bold red]Scan {scan_id} not found.[/bold red]")
        else:
            typer.echo(json.dumps({"error": f"Scan {scan_id} not found"}))
        raise typer.Exit(1)

    # Without stored recon data we can only correlate against tier results
    from atlas.correlate.pipeline import CorrelationPipeline
    from atlas.core.models import CorrelationContext

    config = get_config()
    pipeline = CorrelationPipeline(config=config, repo=repo)

    # Load stored recon data if available — enables full correlations
    stored_recon = repo.get_recon_results(scan_id)
    context = CorrelationContext(scan=report, recon=stored_recon)
    correlations = pipeline.correlate(context)

    report.correlations = correlations
    repo.save_correlations(scan_id, correlations)

    if output == "json":
        typer.echo(report_to_json(report, recon=stored_recon, correlations=correlations))
        return
    if output == "csv":
        typer.echo(report_to_csv(report, correlations=correlations), nl=False)
        return

    console.print(f"\n[bold]Correlations for scan #{scan_id}[/bold] — {report.url}\n")
    for cr in correlations:
        _print_correlation(cr)


# ── Serve command ─────────────────────────────────────────────


@app.command("serve")
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", help="Port to listen on."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (dev mode)."),
    workers: int = typer.Option(1, "--workers", help="Number of uvicorn worker processes."),
) -> None:
    """
    Start the ATLAS REST API server.

    Launches a uvicorn server exposing the full ATLAS API.
    Browse to http://localhost:<port>/docs for the interactive Swagger UI.

    Examples:

        atlas serve                          # Default: 0.0.0.0:8000

        atlas serve --port 9000             # Custom port

        atlas serve --reload                # Dev mode with auto-reload

        atlas serve --host 127.0.0.1       # Local-only binding
    """
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[bold red]uvicorn is not installed.[/bold red] "
            "Run [bold]pip install 'atlas[api]'[/bold] to add API support.",
            highlight=False,
        )
        raise typer.Exit(1)

    console.print(
        f"\n[bold cyan]ATLAS API[/bold cyan] starting on "
        f"[bold]http://{host}:{port}[/bold]\n"
        f"  Swagger UI → [link]http://localhost:{port}/docs[/link]\n"
        f"  ReDoc      → [link]http://localhost:{port}/redoc[/link]\n"
    )

    uvicorn.run(
        "atlas.api.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,  # workers > 1 incompatible with reload
        log_level="info",
    )


# ── Entry point ───────────────────────────────────────────────

# ── Watch subcommand group ────────────────────────────────────

_watch_repo: "WatchRepository | None" = None  # type: ignore[name-defined]


def _get_watch_repo() -> "WatchRepository":  # type: ignore[name-defined]
    global _watch_repo
    if _watch_repo is None:
        from atlas.storage.db import WatchRepository
        _watch_repo = WatchRepository()
    return _watch_repo


watch_app = typer.Typer(
    name="watch",
    help="Domain watch list — monitor domains for verdict changes.",
    no_args_is_help=True,
)
app.add_typer(watch_app, name="watch")


@watch_app.command("add")
def watch_add(
    target: str = typer.Argument(..., help="Domain or URL to watch (e.g. evil.com)"),
) -> None:
    """Register a domain for ongoing verdict monitoring."""
    from atlas.core.domain import extract_domain, normalize_url

    # Accept bare domains or full URLs; normalize both ways
    domain = extract_domain(target) if "/" in target else target.lower().strip()
    url = normalize_url(target if "/" in target else domain)

    watch_repo = _get_watch_repo()
    entry = watch_repo.add_watch(domain=domain, url=url)

    if entry.check_count > 0:
        # Was re-activated
        console.print(
            f"[green]Re-activated watch #{entry.id}[/green]: [bold]{domain}[/bold]"
        )
    else:
        console.print(
            f"[green]Now watching[/green]: [bold]{domain}[/bold]  "
            f"([dim]id={entry.id}[/dim])\n"
            f"  URL: {url}"
        )


@watch_app.command("list")
def watch_list(
    all_watches: bool = typer.Option(
        False, "--all", "-a", help="Include removed (inactive) watches"
    ),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """Show all watched domains and their last known verdicts."""
    from atlas.core.export import OUTPUT_FORMATS
    import csv as _csv, io as _io

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)

    watch_repo = _get_watch_repo()
    entries = watch_repo.list_watches(active_only=not all_watches)

    if output == "json":
        typer.echo(json.dumps(
            [e.model_dump(mode="json") for e in entries],
            indent=2, default=str,
        ))
        return

    if output == "csv":
        columns = ("id", "domain", "url", "active", "last_verdict",
                   "last_checked_at", "check_count")
        buf = _io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow({
                "id": e.id, "domain": e.domain, "url": e.url,
                "active": e.active, "last_verdict": e.last_verdict or "",
                "last_checked_at": e.last_checked_at.isoformat() if e.last_checked_at else "",
                "check_count": e.check_count,
            })
        typer.echo(buf.getvalue(), nl=False)
        return

    if not entries:
        console.print("[dim]No domains being watched.[/dim]  "
                      "Use [bold]atlas watch add <domain>[/bold] to add one.")
        return

    table = Table(
        title="Watch List", show_header=True, header_style="bold cyan"
    )
    table.add_column("ID", min_width=4, justify="right")
    table.add_column("Domain", min_width=20)
    table.add_column("Status", min_width=8)
    table.add_column("Last Verdict", min_width=12)
    table.add_column("Last Checked", min_width=16)
    table.add_column("Checks", min_width=6, justify="right")

    for e in entries:
        status = "[green]Active[/green]" if e.active else "[dim]Removed[/dim]"
        if e.last_verdict:
            icon, color = _verdict_style(
                # Map string verdict back to the enum for styling
                next((v for v in __import__("atlas.core.models", fromlist=["Verdict"]).Verdict
                      if v.value == e.last_verdict), None) or
                __import__("atlas.core.models", fromlist=["Verdict"]).Verdict.CLEAN
            )
            verdict_str = f"[{color}]{e.last_verdict}[/{color}]"
        else:
            verdict_str = "[dim](not yet run)[/dim]"

        last_checked = (
            e.last_checked_at.strftime("%Y-%m-%d %H:%M")
            if e.last_checked_at else "—"
        )

        table.add_row(
            str(e.id), e.domain, status,
            verdict_str, last_checked, str(e.check_count),
        )

    console.print(table)


@watch_app.command("remove")
def watch_remove(
    watch_id: int = typer.Argument(..., help="Watch ID to remove (from 'atlas watch list')"),
) -> None:
    """Stop monitoring a domain (soft delete — history is preserved)."""
    watch_repo = _get_watch_repo()
    entry = watch_repo.get_watch(watch_id)
    if entry is None:
        console.print(f"[red]Watch #{watch_id} not found.[/red]")
        raise typer.Exit(1)
    removed = watch_repo.remove_watch(watch_id)
    if removed:
        console.print(f"[dim]Removed watch #{watch_id}[/dim] ({entry.domain})")
    else:
        console.print(f"[yellow]Watch #{watch_id} was already inactive.[/yellow]")


@watch_app.command("run")
def watch_run(
    skip_slow: bool = typer.Option(
        True, "--skip-slow/--no-skip-slow",
        help="Skip slow recon tools (urlscan.io). Default: skip.",
    ),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
    changed_only: bool = typer.Option(
        False, "--changed-only", "-c",
        help="In structured output, only emit entries where the verdict changed.",
    ),
) -> None:
    """
    Check all active watched domains for verdict changes.

    Each domain is scanned through the analysis pipeline. When a verdict
    changes since the last check, an alert is printed (or emitted to the
    structured output). Updates last_verdict and last_checked_at for every
    checked domain.

    Designed to be called from cron or any scheduler:

        # Check every hour
        0 * * * * atlas watch run --output json >> /var/log/atlas-alerts.jsonl
    """
    from atlas.core.export import OUTPUT_FORMATS
    from atlas.core.models import WatchAlert

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)
    structured = output != "terminal"

    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "httpcore", "urllib3", "whois", "dns"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    watch_repo = _get_watch_repo()
    scan_repo = _get_repo()
    pipeline = _get_pipeline()

    entries = watch_repo.list_watches(active_only=True)

    if not entries:
        if not structured:
            console.print("[dim]No active watches. Add one with[/dim] "
                          "[bold]atlas watch add <domain>[/bold]")
        else:
            typer.echo("[]" if output == "json" else "")
        return

    if not structured:
        console.print(f"\n[bold cyan]Checking {len(entries)} watched domain(s)...[/bold cyan]\n")

    alerts: list[WatchAlert] = []

    for entry in entries:
        from atlas.core.models import ScanRequest, ScanSource, Verdict

        request = ScanRequest(url=entry.url, source=ScanSource.CLI)
        report = pipeline.analyze(request)
        scan_id = scan_repo.save_scan(report)
        report.id = scan_id

        alert = WatchAlert.build(
            watch=entry,
            new_verdict=report.final_verdict,
            scan_id=scan_id,
        )
        alerts.append(alert)
        watch_repo.update_after_check(
            watch_id=entry.id,
            verdict=report.final_verdict.value,
            scan_id=scan_id,
        )

        if not structured:
            _print_watch_alert(alert)

    if not structured:
        changed = [a for a in alerts if a.changed]
        if changed:
            console.print(
                f"\n[bold yellow]⚠  {len(changed)} verdict change(s) detected.[/bold yellow]"
            )
        else:
            console.print("\n[dim]No verdict changes detected.[/dim]")
        return

    # ── Structured output ─────────────────────────────────────
    emit = [a for a in alerts if a.changed or a.is_new] if changed_only else alerts

    if output == "json":
        typer.echo(json.dumps(
            [a.model_dump(mode="json") for a in emit],
            indent=2, default=str,
        ))
    elif output == "csv":
        import csv as _csv, io as _io
        columns = (
            "watch_id", "domain", "url", "previous_verdict",
            "new_verdict", "direction", "changed", "is_new", "scan_id",
        )
        buf = _io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for a in emit:
            writer.writerow(a.model_dump(mode="json"))
        typer.echo(buf.getvalue(), nl=False)


def _print_watch_alert(alert: "WatchAlert") -> None:  # type: ignore[name-defined]
    """Render a single watch alert line to the terminal."""
    direction_icon = {
        "new":           "🆕",
        "escalated":     "🚨",
        "de-escalated":  "✅",
        "unchanged":     "  ",
    }.get(alert.direction, "  ")

    prev = alert.previous_verdict or "—"
    new = alert.new_verdict
    _, color = _verdict_style(
        next((v for v in __import__("atlas.core.models", fromlist=["Verdict"]).Verdict
              if v.value == new), None) or
        __import__("atlas.core.models", fromlist=["Verdict"]).Verdict.CLEAN
    )

    if alert.direction in ("escalated", "de-escalated"):
        change = f"[dim]{prev} →[/dim] [{color}]{new}[/{color}]"
    elif alert.direction == "new":
        change = f"[{color}]{new}[/{color}] [dim](first check)[/dim]"
    else:
        change = f"[{color}]{new}[/{color}]"

    console.print(
        f"  {direction_icon} [bold]{alert.domain:<35}[/bold] {change}"
    )


# ── Pivot subcommand group ────────────────────────────────────
#
# Pivots take a single piece of evidence (an IP, a favicon hash, etc.) and
# answer "what else have we scanned that shares this attribute?". This is
# the same machinery the cross-scan correlator uses, but exposed as direct
# investigative commands so an analyst can pivot from any signal without
# needing to first scan a domain.

pivot_app = typer.Typer(
    name="pivot",
    help="Pivot from a single piece of evidence to all related scans.",
    no_args_is_help=True,
)
app.add_typer(pivot_app, name="pivot")


@pivot_app.command("favicon")
def pivot_favicon(
    favicon_hash: int = typer.Argument(
        ...,
        help="MMH3 favicon hash (signed 32-bit int, Shodan-compatible).",
    ),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or csv",
    ),
) -> None:
    """
    Find every prior scan whose favicon hashed to the same MMH3 value.

    Favicons are one of the strongest brand-impersonation signals available:
    phishing kits almost universally copy the target brand's icon. Two
    domains sharing a favicon hash are very likely either the same site
    or both impersonating the same brand.
    """
    from atlas.core.export import OUTPUT_FORMATS
    import csv as _csv, io as _io

    if output not in OUTPUT_FORMATS:
        console.print(f"[red]Invalid --output: {output!r}. Use: {', '.join(OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(2)

    repo = _get_repo()
    related = repo.find_related_scans(
        exclude_scan_id=-1,  # don't exclude anything — caller didn't scan
        favicon_hash=favicon_hash,
    )
    matches = related.get("favicon", [])

    if output == "json":
        typer.echo(json.dumps(
            {"favicon_hash": favicon_hash, "matches": matches},
            indent=2, default=str,
        ))
        return

    if output == "csv":
        columns = ("scan_id", "domain", "url", "verdict", "scanned_at")
        buf = _io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for m in matches:
            writer.writerow(m)
        typer.echo(buf.getvalue(), nl=False)
        return

    # ── Terminal output ───────────────────────────────────────
    if not matches:
        console.print(
            f"[dim]No scans found with favicon hash[/dim] [bold]{favicon_hash}[/bold]"
        )
        return

    from atlas.core.models import Verdict
    table = Table(
        title=f"Scans sharing favicon hash [bold cyan]{favicon_hash}[/bold cyan]",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Scan ID", justify="right", min_width=8)
    table.add_column("Domain", min_width=24)
    table.add_column("URL", min_width=32)
    table.add_column("Verdict", min_width=12)
    table.add_column("Scanned At", min_width=20)

    for m in matches:
        verdict_enum = next(
            (v for v in Verdict if v.value == m["verdict"]),
            Verdict.CLEAN,
        )
        _, color = _verdict_style(verdict_enum)
        table.add_row(
            str(m["scan_id"]),
            m["domain"],
            (m.get("url") or "")[:60],
            f"[{color}]{m['verdict']}[/{color}]",
            (m.get("scanned_at") or "")[:19],
        )
    console.print(table)
    console.print(
        f"[dim]{len(matches)} match(es). "
        f"Domains sharing a favicon often share an operator or impersonation target.[/dim]"
    )


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    app()
