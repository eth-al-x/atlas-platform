"""
atlas.correlate.pivots
Shared pivot extraction logic.

Both the cross-scan correlator and the graph endpoint need to extract the
same set of pivot attributes from a scan's recon results: IP, ASN, registrar,
favicon hash, /24 prefix. This module is the single source of truth.

The helpers operate on a plain `dict[str, ReconResult]` rather than a
`CorrelationContext`, so they can be used from anywhere that has access
to recon data — including API routes that don't construct a context.
"""

from __future__ import annotations

from atlas.core.models import ReconResult


def extract_ip(recon: dict[str, ReconResult]) -> str | None:
    """Pull the resolved IPv4/IPv6 address out of ip_intel recon data."""
    ip_intel = recon.get("ip_intel")
    if not ip_intel or ip_intel.error:
        return None
    ip = ip_intel.data.get("ip")
    return ip if isinstance(ip, str) and ip else None


def extract_asn(recon: dict[str, ReconResult]) -> str | None:
    """Pull the ASN string out of ip_intel.geolocation."""
    ip_intel = recon.get("ip_intel")
    if not ip_intel or ip_intel.error:
        return None
    geo = ip_intel.data.get("geolocation") or {}
    asn = geo.get("asn")
    return asn if isinstance(asn, str) and asn else None


def extract_registrar(recon: dict[str, ReconResult]) -> str | None:
    """Pull the registrar name out of whois recon data."""
    whois = recon.get("whois")
    if not whois or whois.error:
        return None
    registrar = whois.data.get("registrar")
    return registrar if isinstance(registrar, str) and registrar else None


def extract_favicon_hash(recon: dict[str, ReconResult]) -> int | None:
    """
    Pull the MMH3 favicon hash out of web_recon data.

    Returns None if web_recon didn't run, failed, the favicon sub-result
    failed, or the hash wasn't an int — all are normal outcomes that
    should leave this pivot inactive.
    """
    web = recon.get("web_recon")
    if not web or web.error:
        return None
    favicon = web.data.get("favicon") or {}
    if not isinstance(favicon, dict) or favicon.get("error"):
        return None
    h = favicon.get("mmh3_hash")
    return h if isinstance(h, int) else None


def extract_jarm(recon: dict[str, ReconResult]) -> str | None:
    """
    Pull the JARM TLS fingerprint out of jarm recon data.

    Returns None if jarm didn't run, the scan errored, the host had no
    TLS (jarm_hash stored as None by the recon tool), or if the stored
    value is the all-zeros sentinel for any reason. Matching on the
    all-zeros sentinel would cluster every TLS-less host together, which
    is meaningless.
    """
    jarm = recon.get("jarm")
    if not jarm or jarm.error:
        return None
    h = jarm.data.get("jarm_hash")
    if not isinstance(h, str) or not h:
        return None
    if h == "0" * 62:  # the no-TLS sentinel, defensive check
        return None
    return h


def slash24_prefix(ip: str | None) -> str | None:
    """
    Reduce an IPv4 address to its /24 prefix string (e.g. '1.2.3').

    Returns None for IPv6, malformed addresses, or None input — those
    can't be pivoted via the GLOB pattern the storage layer uses.
    """
    if not ip:
        return None
    octets = ip.split(".")
    if len(octets) != 4:
        return None
    try:
        for octet in octets:
            n = int(octet)
            if not (0 <= n <= 255):
                return None
    except ValueError:
        return None
    return ".".join(octets[:3])


def extract_all(recon: dict[str, ReconResult]) -> dict:
    """
    Extract every pivot attribute in one call.

    Returns a dict with keys ip, asn, registrar, favicon_hash, slash24, jarm.
    Any field that couldn't be extracted is None.
    """
    ip = extract_ip(recon)
    return {
        "ip": ip,
        "asn": extract_asn(recon),
        "registrar": extract_registrar(recon),
        "favicon_hash": extract_favicon_hash(recon),
        "slash24": slash24_prefix(ip),
        "jarm": extract_jarm(recon),
    }
