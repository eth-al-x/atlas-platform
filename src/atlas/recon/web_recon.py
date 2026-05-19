"""
atlas.recon.web_recon
Recon: HTML content analysis for a URL.

Fetches the page and extracts:
    - Title and meta description
    - All external links (unique, sorted)
    - Form count and their action URLs (phishing pages collect credentials via forms)
    - Inline and external script counts
    - Suspicious JavaScript markers (eval, atob, document.write, long base64-ish strings)

Ported from Cybersecurity Toolkit's web_recon() with the .title.string bug
fixed (uses .get_text() to handle nested elements) and the suspicious-JS
analysis added on top.
"""

from __future__ import annotations

import logging
import re

import httpx
from bs4 import BeautifulSoup

from atlas.core.config import AtlasConfig
from atlas.core.domain import normalize_url
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


# JavaScript patterns frequently seen in obfuscated / malicious pages.
# None of these are inherently bad — legitimate sites use them — but the
# combination + density is a useful signal.
SUSPICIOUS_JS_PATTERNS: dict[str, re.Pattern[str]] = {
    "eval_calls": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "atob_calls": re.compile(r"\batob\s*\(", re.IGNORECASE),
    "document_write": re.compile(r"document\.write\s*\(", re.IGNORECASE),
    "fromcharcode": re.compile(r"String\.fromCharCode\s*\(", re.IGNORECASE),
    # Long base64-looking strings (60+ chars of base64 alphabet)
    "long_base64_blobs": re.compile(r"['\"]([A-Za-z0-9+/]{60,}={0,2})['\"]"),
    # Hex-encoded strings (\x41\x42 style)
    "hex_escape_strings": re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}"),
}


class WebReconTool(ReconTool):
    name = "web_recon"
    display_name = "Web Recon"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.timeout = config.analysis.request_timeout

    def _run(self, target: str, **context: object) -> ReconResult:
        url = normalize_url(target)

        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            response = client.get(url)

        # Don't try to parse non-HTML responses — saves time and avoids errors.
        # Some hosts return JSON or plain text for the root path.
        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                data={
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "note": "non-HTML response, skipping content analysis",
                },
            )

        soup = BeautifulSoup(response.text, "html.parser")

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "url": str(response.url),
                "status_code": response.status_code,
                "title": self._extract_title(soup),
                "description": self._extract_meta(soup, "description"),
                "keywords": self._extract_meta(soup, "keywords"),
                "external_links": self._extract_external_links(soup),
                "forms": self._extract_forms(soup),
                "scripts": self._extract_scripts(soup),
                "suspicious_js": self._scan_for_suspicious_js(response.text),
                "page_size_bytes": len(response.content),
            },
        )

    # ── Private helpers ───────────────────────────────────────

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title. Uses get_text() to handle nested elements correctly."""
        if soup.title is None:
            return ""
        return soup.title.get_text(strip=True)

    def _extract_meta(self, soup: BeautifulSoup, name: str) -> str:
        """Extract a meta tag's content attribute by name."""
        tag = soup.find("meta", attrs={"name": name})
        if tag and tag.get("content"):
            return str(tag["content"]).strip()
        return ""

    def _extract_external_links(self, soup: BeautifulSoup) -> list[str]:
        """Return unique sorted list of all http(s) links on the page."""
        links = set()
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            if href.startswith(("http://", "https://")):
                links.add(href)
        return sorted(links)

    def _extract_forms(self, soup: BeautifulSoup) -> dict:
        """Summarize forms on the page — count, methods, action URLs."""
        forms = soup.find_all("form")
        actions = []
        for form in forms:
            action = form.get("action", "").strip()
            method = form.get("method", "get").lower()
            if action:
                actions.append({"action": action, "method": method})

        return {
            "count": len(forms),
            "actions": actions,
        }

    def _extract_scripts(self, soup: BeautifulSoup) -> dict:
        """Count inline scripts and list external script sources."""
        scripts = soup.find_all("script")
        inline = 0
        external = []
        for script in scripts:
            src = script.get("src")
            if src:
                external.append(str(src))
            elif script.string:  # Has inline content
                inline += 1

        return {
            "inline_count": inline,
            "external_count": len(external),
            "external_sources": external,
        }

    def _scan_for_suspicious_js(self, html: str) -> dict:
        """
        Count matches of suspicious JS patterns in the raw HTML.
        High counts (esp. across multiple patterns) suggest obfuscation
        or active code-loading techniques common in malicious pages.
        """
        findings = {}
        total = 0
        for pattern_name, regex in SUSPICIOUS_JS_PATTERNS.items():
            count = len(regex.findall(html))
            findings[pattern_name] = count
            total += count

        return {
            "patterns": findings,
            "total_matches": total,
            # A rough heuristic — not a verdict, just a signal worth surfacing
            "high_volume": total > 20,
        }
