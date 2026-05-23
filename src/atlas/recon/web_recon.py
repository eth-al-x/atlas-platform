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

import base64
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
import mmh3
from bs4 import BeautifulSoup

from atlas.core.config import AtlasConfig
from atlas.core.domain import normalize_url
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool


logger = logging.getLogger(__name__)


# Cap favicon download size — legitimate favicons are well under 100 KB.
# Anything bigger is either a non-favicon misconfiguration or a hostile
# response trying to waste our bandwidth.
MAX_FAVICON_BYTES = 1_048_576  # 1 MB hard ceiling

# Favicon link rels to scan the HTML for, in order of preference.
# We prefer the explicit "icon" rel over fallbacks like apple-touch-icon
# because that's what browsers actually use and what Shodan indexes.
FAVICON_REL_PREFERENCE: tuple[str, ...] = (
    "icon",
    "shortcut icon",
    "apple-touch-icon",
    "apple-touch-icon-precomposed",
)


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

        favicon = self._collect_favicon(soup, str(response.url), client_factory=httpx.Client)

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
                "favicon": favicon,
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

    # ── Favicon hashing (Shodan-compatible MMH3) ─────────────────────────
    #
    # The favicon is one of the highest-signal artifacts on a phishing page:
    # kits almost universally copy the target brand's icon and almost never
    # remember to swap it. Hashing it gives us a cheap, durable fingerprint
    # that pivots across operators, hosts, and domains.
    #
    # The recipe matches Shodan's published format exactly so our hashes
    # can be cross-referenced against `http.favicon.hash:<n>` searches:
    #     1. fetch the favicon bytes (find <link rel="icon"> or /favicon.ico)
    #     2. base64-encode with line breaks every 76 chars (encodebytes)
    #     3. MMH3 hash with default seed 0 → signed 32-bit int

    def _collect_favicon(
        self,
        soup: BeautifulSoup,
        page_url: str,
        client_factory: type[httpx.Client] = httpx.Client,
    ) -> dict:
        """
        Discover and fingerprint the favicon for the page. Always returns a
        dict — favicon failures must never abort the parent web scan.
        Pass a different client_factory to fully mock in unit tests.
        """
        try:
            favicon_url = self._discover_favicon_url(soup, page_url)
        except Exception as exc:
            logger.debug("Favicon URL discovery failed for %s: %s", page_url, exc)
            return {"error": f"discovery failed: {exc}"}

        if favicon_url is None:
            return {"error": "no favicon location found"}

        try:
            with client_factory(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(favicon_url)
        except httpx.HTTPError as exc:
            logger.debug("Favicon fetch failed for %s: %s", favicon_url, exc)
            return {"url": favicon_url, "error": f"fetch failed: {exc.__class__.__name__}"}

        if resp.status_code >= 400:
            return {
                "url": favicon_url,
                "status_code": resp.status_code,
                "error": f"HTTP {resp.status_code}",
            }

        content = resp.content
        if len(content) > MAX_FAVICON_BYTES:
            return {
                "url": favicon_url,
                "status_code": resp.status_code,
                "size_bytes": len(content),
                "error": "favicon exceeds size limit",
            }
        if len(content) == 0:
            return {
                "url": favicon_url,
                "status_code": resp.status_code,
                "error": "empty favicon body",
            }

        return {
            "url": favicon_url,
            "status_code": resp.status_code,
            "size_bytes": len(content),
            "content_type": resp.headers.get("content-type", ""),
            "mmh3_hash": self._compute_favicon_hash(content),
        }

    @staticmethod
    def _discover_favicon_url(soup: BeautifulSoup, page_url: str) -> str | None:
        """
        Find the best favicon URL. First check <link rel="icon"> variants
        in the parsed HTML (in our preference order), then fall back to
        /favicon.ico at the page's origin — the browser's default location.

        Returns an absolute URL or None if nothing resolvable was found.
        """
        # Index every link tag with an icon-related rel for fast lookup.
        # `link.get("rel")` returns a list (e.g. ["shortcut", "icon"]); we
        # join and lowercase it to a stable string for matching.
        icon_links: dict[str, str] = {}
        for link in soup.find_all("link", href=True):
            rel = link.get("rel")
            if not rel:
                continue
            rel_str = " ".join(rel).lower().strip() if isinstance(rel, list) else str(rel).lower()
            if rel_str in icon_links:
                continue  # first match wins per rel
            icon_links[rel_str] = link["href"]

        for preferred in FAVICON_REL_PREFERENCE:
            href = icon_links.get(preferred)
            if href:
                resolved = urljoin(page_url, href.strip())
                if WebReconTool._is_fetchable_url(resolved):
                    return resolved

        # No <link> found — fall back to the conventional /favicon.ico
        parsed = urlparse(page_url)
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

    @staticmethod
    def _is_fetchable_url(url: str) -> bool:
        """Reject data: URIs and other unfetchable schemes for the favicon."""
        try:
            scheme = urlparse(url).scheme.lower()
        except ValueError:
            return False
        return scheme in ("http", "https")

    @staticmethod
    def _compute_favicon_hash(content: bytes) -> int:
        """
        Compute MMH3 hash using the Shodan-compatible recipe:
        base64-encode the raw bytes with newlines every 76 chars, then
        hash the resulting ASCII text. Returns a signed 32-bit int.
        """
        b64 = base64.encodebytes(content)
        return mmh3.hash(b64)
