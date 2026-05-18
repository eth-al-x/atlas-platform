"""
atlas.core.domain
Domain extraction and normalization utilities.
Ported from URL Auditor's _extract_domain with expanded edge-case handling.
"""

from __future__ import annotations

import urllib.parse


# Prefixes to strip when normalizing domains for blocklist lookups
_COMMON_PREFIXES = ("www.", "www2.", "www3.", "m.", "mobile.", "mail.")


def extract_domain(url: str) -> str:
    """
    Extract the registrable domain from a full URL.

    Handles missing schemes, port numbers, authentication strings,
    and common subdomain prefixes. Returns a lowercase, prefix-stripped domain.

    Examples:
        >>> extract_domain("https://www.example.com/path?q=1")
        'example.com'
        >>> extract_domain("mail.google.com:8080")
        'google.com'
        >>> extract_domain("user:pass@evil.com")
        'evil.com'
    """
    url = url.strip()
    parsed = urllib.parse.urlparse(url)

    domain = parsed.netloc or ""

    # If urlparse didn't find a netloc, the URL probably lacks a scheme
    if not domain:
        parsed = urllib.parse.urlparse("http://" + url)
        domain = parsed.netloc or ""

    # Strip userinfo (user:pass@)
    if "@" in domain:
        domain = domain.split("@", 1)[1]

    # Strip port number
    if ":" in domain:
        domain = domain.rsplit(":", 1)[0]

    domain = domain.lower().rstrip(".")

    # Strip common subdomain prefixes for consistent blocklist matching
    for prefix in _COMMON_PREFIXES:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
            break

    return domain


def normalize_url(url: str) -> str:
    """Ensure a URL has a scheme for consistent HTTP requests."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url
