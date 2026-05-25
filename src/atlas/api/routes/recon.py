"""
atlas.api.routes.recon
Recon tool endpoints and the unified investigate command.

GET  /recon/dns/{domain}          DNS record lookup
GET  /recon/headers               HTTP security header analysis
GET  /recon/web                   Web page content recon
GET  /recon/whois/{domain}        WHOIS registration data
GET  /recon/ip/{domain}           IP geolocation + exposure
GET  /recon/crtsh/{domain}        Certificate Transparency log search
GET  /recon/urlscan               urlscan.io sandbox analysis
GET  /recon/subdomains/{domain}   Active subdomain enumeration

POST /investigate                 Full investigation: scan + all recon tools
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, Query

from atlas.api.dependencies import get_atlas_config, get_pipeline, get_repo
from atlas.api.schemas import (
    InvestigateRequestBody,
    InvestigateResponse,
    ReconResponse,
)
from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult, ScanRequest, ScanSource
from atlas.core.pipeline import AnalysisPipeline
from atlas.storage.db import ScanRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["Recon"])
investigate_router = APIRouter(tags=["Analysis"])


# ── Tool factory ──────────────────────────────────────────────

def _make_recon_tools(config: AtlasConfig) -> dict:
    """
    Lazily import and instantiate all recon tools.
    Importing inside this function avoids circular imports and keeps
    optional deps (scapy) from breaking the import chain.
    """
    from atlas.recon.dns import DNSReconTool
    from atlas.recon.http_headers import HTTPHeadersReconTool
    from atlas.recon.web_recon import WebReconTool
    from atlas.recon.whois_lookup import WhoisReconTool
    from atlas.recon.ip_intel import IPIntelReconTool
    from atlas.recon.crtsh import CrtShReconTool
    from atlas.recon.urlscan import URLScanReconTool
    from atlas.recon.subdomains import SubdomainReconTool
    from atlas.recon.email_recon import EmailReconTool
    from atlas.recon.ip_neighborhood import IPNeighborhoodReconTool
    from atlas.recon.greynoise import GreyNoiseReconTool
    from atlas.recon.censys_certs import CensysCertsReconTool
    from atlas.recon.jarm import JarmReconTool

    return {
        "dns": DNSReconTool(config),
        "http_headers": HTTPHeadersReconTool(config),
        "web_recon": WebReconTool(config),
        "whois": WhoisReconTool(config),
        "ip_intel": IPIntelReconTool(config),
        "crtsh": CrtShReconTool(config),
        "urlscan": URLScanReconTool(config),
        "subdomains": SubdomainReconTool(config),
        "email_recon": EmailReconTool(config),
        "ip_neighborhood": IPNeighborhoodReconTool(config),
        "greynoise": GreyNoiseReconTool(config),
        "censys_certs": CensysCertsReconTool(config),
        "jarm": JarmReconTool(config),
    }


# Module-level tool cache — instantiated once after startup
_tools: dict | None = None


def get_tools(config: AtlasConfig = Depends(get_atlas_config)) -> dict:
    global _tools
    if _tools is None:
        _tools = _make_recon_tools(config)
    return _tools


async def _run_tool(tool, target: str, **kwargs) -> ReconResult:
    """Run a synchronous recon tool in the thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        partial(tool.run, target, **kwargs),
    )


# ── Individual recon endpoints ────────────────────────────────


@router.get(
    "/dns/{domain}",
    response_model=ReconResponse,
    summary="DNS lookup",
    description="Resolves A, AAAA, MX, TXT, and NS records for the given domain.",
)
async def recon_dns(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["dns"], domain)
    return ReconResponse(result=result)


@router.get(
    "/headers",
    response_model=ReconResponse,
    summary="HTTP security headers",
    description=(
        "Fetches HTTP response headers and grades the site's security posture "
        "based on OWASP Secure Headers recommendations."
    ),
)
async def recon_headers(
    url: str = Query(..., description="Full URL to inspect (e.g. https://example.com)"),
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["http_headers"], url)
    return ReconResponse(result=result)


@router.get(
    "/web",
    response_model=ReconResponse,
    summary="Web content recon",
    description=(
        "Fetches and parses the page at the given URL. Returns title, meta description, "
        "external links, script counts, form counts, and obfuscation markers."
    ),
)
async def recon_web(
    url: str = Query(..., description="Full URL to inspect (e.g. https://example.com)"),
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["web_recon"], url)
    return ReconResponse(result=result)


@router.get(
    "/whois/{domain}",
    response_model=ReconResponse,
    summary="WHOIS lookup",
    description="Returns registrar, registration date, expiry, and name servers.",
)
async def recon_whois(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["whois"], domain)
    return ReconResponse(result=result)


@router.get(
    "/ip/{domain}",
    response_model=ReconResponse,
    summary="IP intelligence",
    description=(
        "Resolves the domain to an IP, then returns geolocation, ISP, ASN, "
        "and open port/CVE data from Shodan InternetDB."
    ),
)
async def recon_ip(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["ip_intel"], domain)
    return ReconResponse(result=result)


@router.get(
    "/crtsh/{domain}",
    response_model=ReconResponse,
    summary="Certificate Transparency search",
    description=(
        "Queries crt.sh for every TLS certificate ever issued for the domain. "
        "Useful for subdomain discovery and infrastructure timeline analysis."
    ),
)
async def recon_crtsh(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["crtsh"], domain)
    return ReconResponse(result=result)


@router.get(
    "/urlscan",
    response_model=ReconResponse,
    summary="urlscan.io sandbox analysis",
    description=(
        "Submits the URL to urlscan.io for sandboxed browser analysis. "
        "Returns verdict score, screenshot URL, and contacted infrastructure. "
        "Requires URLSCAN_API_KEY in environment. Takes 15–30 seconds."
    ),
)
async def recon_urlscan(
    url: str = Query(..., description="Full URL to sandbox (e.g. https://example.com)"),
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["urlscan"], url)
    return ReconResponse(result=result)


@router.get(
    "/subdomains/{domain}",
    response_model=ReconResponse,
    summary="Active subdomain enumeration",
    description=(
        "Bruteforces subdomains via DNS using a built-in wordlist. "
        "Generates real DNS traffic — only use against domains you own or have permission to test. "
        "Takes 10–20 seconds for the default 500-word list."
    ),
)
async def recon_subdomains(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["subdomains"], domain)
    return ReconResponse(result=result)


@router.get(
    "/email/{domain}",
    response_model=ReconResponse,
    summary="Email infrastructure & anti-spoofing posture",
    description=(
        "Resolves MX records and parses SPF, DMARC, and DKIM policies "
        "for the domain. Returns a 0–100 posture score plus the raw "
        "policies and a list of human-readable issues.\n\n"
        "Pure DNS, fast (< 5s typical). A domain that impersonates a "
        "brand but has no MX or weak DMARC is overwhelmingly more "
        "likely to be a phishing lander than a real corporate domain."
    ),
)
async def recon_email(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["email_recon"], domain)
    return ReconResponse(result=result)


@router.get(
    "/greynoise/{domain}",
    response_model=ReconResponse,
    summary="GreyNoise IP classification",
    description=(
        "Resolves the domain to an IP and queries the GreyNoise Community API. "
        "Returns noise/RIOT/classification signals — useful for distinguishing "
        "targeted threats from internet background noise and suppressing false "
        "positives on known-benign infrastructure.\n\n"
        "Requires GREYNOISE_API_KEY in environment for higher rate limits. "
        "Works without a key at 100 req/day."
    ),
)
async def recon_greynoise(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["greynoise"], domain)
    return ReconResponse(result=result)


@router.get(
    "/censys/{domain}",
    response_model=ReconResponse,
    summary="Censys certificate search",
    description=(
        "Queries the Censys v2 API for all TLS certificates ever issued for "
        "the domain, with richer metadata than crt.sh: validation level "
        "(DV/OV/EV), parsed issuer, and SAN lists.\n\n"
        "Requires CENSYS_API_ID and CENSYS_API_SECRET in environment. "
        "Free tier: 250 queries/month (each paginated request = 1 query). "
        "Returns a no-credentials result when keys are absent rather than erroring."
    ),
)
async def recon_censys(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["censys_certs"], domain)
    return ReconResponse(result=result)


@router.get(
    "/jarm/{domain}",
    response_model=ReconResponse,
    summary="JARM TLS fingerprint",
    description=(
        "Compute the JARM TLS fingerprint for the host by sending 10 "
        "specially crafted TLS Client Hello packets and hashing the "
        "server's responses.\n\n"
        "Two hosts with the same JARM run an identical TLS stack — "
        "useful for campaign attribution where operators redeploy the "
        "same server image across rotating domains. JARM is a clustering "
        "signal, not a verdict signal: many benign defaults share JARMs.\n\n"
        "Returns the all-zeros sentinel internally for hosts with no TLS; "
        "the recon tool surfaces that as `tls_available: false`."
    ),
)
async def recon_jarm(
    domain: str,
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["jarm"], domain)
    return ReconResponse(result=result)



@router.get(
    "/neighbors/{domain}",
    response_model=ReconResponse,
    summary="IP neighborhood enumeration (PTR-sweep)",
    description=(
        "Resolves the domain's IP and runs PTR lookups against every "
        "address in the surrounding CIDR block. Surfaces other domains "
        "parked on the same shared host or in the same tight provider "
        "range — a frequent signal of campaign infrastructure.\n\n"
        "Pure DNS, no contact with the target host. Default neighborhood "
        "is /28 (16 IPs); use cidr_bits to widen up to /24 (256 IPs) "
        "or narrow to /30 (4 IPs)."
    ),
)
async def recon_neighbors(
    domain: str,
    cidr_bits: int = Query(default=28, ge=24, le=30,
                            description="CIDR prefix length to enumerate (24-30)."),
    tools: dict = Depends(get_tools),
) -> ReconResponse:
    result = await _run_tool(tools["ip_neighborhood"], domain, cidr_bits=cidr_bits)
    return ReconResponse(result=result)


# ── Investigate endpoint ──────────────────────────────────────


@investigate_router.post(
    "/investigate",
    response_model=InvestigateResponse,
    summary="Full investigation",
    description=(
        "Runs the full ATLAS investigation: threat-analysis pipeline + all recon tools. "
        "The most comprehensive endpoint — expect 30–90 seconds depending on options. "
        "Use skip_slow=true to omit urlscan.io."
    ),
)
async def investigate(
    body: InvestigateRequestBody,
    pipeline: AnalysisPipeline = Depends(get_pipeline),
    repo: ScanRepository = Depends(get_repo),
    tools: dict = Depends(get_tools),
) -> InvestigateResponse:
    """Run scan + all recon tools concurrently where possible."""
    from atlas.core.domain import extract_domain

    domain = extract_domain(body.url)

    # Step 1: Run the scan pipeline (must complete first for the verdict)
    loop = asyncio.get_event_loop()
    request = ScanRequest(url=body.url, source=ScanSource.API)
    report = await loop.run_in_executor(
        None,
        partial(pipeline.analyze, request),
    )
    scan_id = repo.save_scan(report)
    report.id = scan_id

    # Step 2: Run recon tools concurrently
    # urlscan needs the full URL; others work on the domain
    tool_targets = {
        "dns": (domain, {}),
        "whois": (domain, {}),
        "ip_intel": (domain, {}),
        "crtsh": (domain, {}),
        "censys_certs": (domain, {}),
        "http_headers": (body.url, {}),
        "web_recon": (body.url, {}),
        "email_recon": (domain, {}),
        "ip_neighborhood": (domain, {}),
        "greynoise": (domain, {}),
        "jarm": (domain, {}),
    }

    if not body.skip_slow:
        tool_targets["urlscan"] = (body.url, {})

    if body.include_subdomains:
        tool_targets["subdomains"] = (domain, {})

    # Launch all recon tasks concurrently
    async def run(name: str, target: str, kwargs: dict) -> tuple[str, ReconResult]:
        result = await _run_tool(tools[name], target, **kwargs)
        return name, result

    gathered = await asyncio.gather(
        *[run(name, target, kwargs) for name, (target, kwargs) in tool_targets.items()],
        return_exceptions=True,
    )

    recon_results: dict[str, ReconResult] = {}
    for item in gathered:
        if isinstance(item, Exception):
            logger.error("Recon task failed: %s", item)
            continue
        name, result = item
        recon_results[name] = result

    # Step 3: Run correlations against the gathered data
    from atlas.correlate.pipeline import CorrelationPipeline
    from atlas.core.models import CorrelationContext

    correlation_pipeline = CorrelationPipeline(config=pipeline.config, repo=repo)
    context = CorrelationContext(scan=report, recon=recon_results)
    correlations = await loop.run_in_executor(
        None,
        partial(correlation_pipeline.correlate, context),
    )
    report.correlations = correlations
    repo.save_correlations(scan_id, correlations)
    repo.save_recon_results(scan_id, recon_results)

    return InvestigateResponse(
        scan=report,
        recon=recon_results,
    )
