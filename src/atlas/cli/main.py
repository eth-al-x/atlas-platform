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
) -> None:
    """
    Run all recon tools plus the threat analysis pipeline on a target.

    This is the flagship command for investigating a suspicious domain:
    one input, full output across DNS, WHOIS, IP intel, CT logs, HTTP
    headers, web content, urlscan sandbox analysis, and the tiered
    threat verdict.
    """
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
    console.print()
    console.print(Panel(
        Text(f"🔬 Investigating: {clean_domain}", style="bold blue"),
        border_style="blue",
    ))
    console.print()

    # ── Threat verdict (unless skipped) ──────────────────────
    if not skip_scan:
        console.print("[bold cyan]━━━ Threat Analysis ━━━[/bold cyan]\n")
        pipeline = _get_pipeline()
        repo = _get_repo()
        request = ScanRequest(url=full_url, source=ScanSource.CLI)
        report = pipeline.analyze(request)
        scan_id = repo.save_scan(report)
        report.id = scan_id
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

    for section_header, tool, target_input, render_title, is_slow in tools:
        if is_slow and skip_slow:
            continue

        console.print(f"\n[bold cyan]{section_header}[/bold cyan]\n")

        # Wrap slow tools in a progress spinner
        if is_slow:
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

        _print_recon_result(result, render_title)


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

if __name__ == "__main__":
    app()
