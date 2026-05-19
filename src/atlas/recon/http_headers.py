"""
atlas.recon.http_headers
Recon: HTTP response headers inspection with security header analysis.

Fetches the response headers from a URL and evaluates the site's security
posture based on which protective headers are configured. A well-secured
site sends HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, and Permissions-Policy...missing or weak values on these
indicate either oversight or active negligence.

Ported from Cybersecurity Toolkit's get_http_headers() with the security
scoring layer added on top.
"""

from __future__ import annotations

import logging

import httpx

from atlas.core.config import AtlasConfig
from atlas.core.domain import normalize_url
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


# Security headers we check for, with a brief rationale that the CLI / API
# can display. These are the "OWASP Secure Headers" core set.
SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "Forces HTTPS connections (HSTS)",
    "content-security-policy": "Restricts which resources the page can load (CSP)",
    "x-frame-options": "Prevents clickjacking via iframe embedding",
    "x-content-type-options": "Prevents MIME-type sniffing attacks",
    "referrer-policy": "Controls referrer header leakage",
    "permissions-policy": "Restricts browser feature access",
}


class HTTPHeadersReconTool(ReconTool):
    name = "http_headers"
    display_name = "HTTP Headers"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.timeout = config.analysis.request_timeout

    def _run(self, target: str, **context: object) -> ReconResult:
        url = normalize_url(target)

        # Use GET (not HEAD) because some servers return different headers
        # for HEAD requests, and a few don't support HEAD at all. We don't
        # care about the body, but we do care about getting accurate headers.
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            response = client.get(url)

        # Normalize all headers to lowercase keys for consistent lookups.
        # HTTP headers are case-insensitive per RFC 7230.
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # Run the security analysis
        security = self._analyze_security_headers(headers_lower)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "url": str(response.url), # Final URL after redirects
                "status_code": response.status_code,
                "server": headers_lower.get("server", "not disclosed"),
                "content_type": headers_lower.get("content-type", "unknown"),
                "all_headers": dict(response.headers),
                "security": security,
                "redirects": len(response.history),
            },
        )

    # --- Private Helpers ----------------------------------------------------------

    def _analyze_security_headers(self, headers: dict[str, str]) -> dict:
        """
        Score the site's security posture by which protective headers are present.
        Returns a structured analysis with per-header status and overall score.
        """
        analysis = {}
        present_count = 0

        for header_name, description in SECURITY_HEADERS.items():
            value = headers.get(header_name)
            is_present = value is not None
            if is_present:
                present_count += 1

            analysis[header_name] = {
                "present": is_present,
                "value": value,
                "description": description,
            }

        total = len(SECURITY_HEADERS)
        score_pct = round((present_count / total) * 100)

        # Human-readable rating bucket
        if score_pct >= 85:
            rating = "Strong"
        elif score_pct >= 50:
            rating = "Moderate"
        else:
            rating = "Weak"

        return {
            "headers": analysis,
            "score": f"{present_count}/{total}",
            "score_percentage": score_pct,
            "rating": rating,
        }