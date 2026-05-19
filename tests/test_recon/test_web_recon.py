"""
Tests for the web recon tool.
Uses respx to mock HTTP responses with synthetic HTML payloads.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from atlas.core.config import AtlasConfig
from atlas.recon.web_recon import WebReconTool


@pytest.fixture
def tool():
    """Create a web recon tool with default config."""
    return WebReconTool(AtlasConfig())


def _html_response(body: str, content_type: str = "text/html; charset=utf-8"):
    """Build a fake httpx response with the given HTML body."""
    return httpx.Response(
        200,
        content=body.encode("utf-8"),
        headers={"content-type": content_type},
    )


# A representative "normal" page with title, meta, links, one form, mixed scripts
NORMAL_HTML = """
<html>
<head>
    <title>Example Domain</title>
    <meta name="description" content="A test page for ATLAS web recon.">
    <meta name="keywords" content="test, recon, atlas">
</head>
<body>
    <h1>Welcome</h1>
    <a href="https://example.org/about">About us</a>
    <a href="https://github.com/test/repo">GitHub repo</a>
    <a href="/internal">Internal link</a>
    <form action="/submit" method="post">
        <input name="email">
    </form>
    <script src="https://cdn.example.com/lib.js"></script>
    <script>console.log("hello");</script>
</body>
</html>
"""

# A page using common obfuscation patterns
SUSPICIOUS_HTML = """
<html><head><title>Free Stuff</title></head>
<body>
<script>
  var payload = atob("dGVzdCBwYXlsb2FkIGZvciB0ZXN0aW5n");
  eval(atob("Y29uc29sZS5sb2coJ3JhbicpOw=="));
  document.write("<p>Loading...</p>");
  var data = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5QUJDREVGR0hJSktMTU4=";
</script>
</body></html>
"""


class TestWebReconTool:

    # ── Basic HTML parsing ───────────────────────────────────

    @respx.mock
    def test_extracts_title(self, tool):
        """Page title should be extracted cleanly."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        assert result.data["title"] == "Example Domain"

    @respx.mock
    def test_extracts_meta_description(self, tool):
        """Meta description should appear in the result."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        assert result.data["description"] == "A test page for ATLAS web recon."

    @respx.mock
    def test_extracts_keywords(self, tool):
        """Meta keywords should appear when present."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        assert "test" in result.data["keywords"]

    @respx.mock
    def test_extracts_external_links_only(self, tool):
        """Only http(s) external links should be collected (no internal/relative)."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        links = result.data["external_links"]

        assert "https://example.org/about" in links
        assert "https://github.com/test/repo" in links
        assert "/internal" not in links

    @respx.mock
    def test_external_links_are_unique(self, tool):
        """Duplicate links should be deduplicated."""
        html = '<a href="https://x.com">a</a><a href="https://x.com">b</a>'
        respx.get("https://example.com").mock(return_value=_html_response(html))

        result = tool.run("example.com")
        assert result.data["external_links"].count("https://x.com") == 1

    # ── Forms ───────────────────────────────────────────────

    @respx.mock
    def test_forms_counted(self, tool):
        """Form count should be reported accurately."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        assert result.data["forms"]["count"] == 1

    @respx.mock
    def test_form_actions_captured(self, tool):
        """Form action URLs and methods should be in the result."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        actions = result.data["forms"]["actions"]

        assert len(actions) == 1
        assert actions[0]["action"] == "/submit"
        assert actions[0]["method"] == "post"

    # ── Scripts ─────────────────────────────────────────────

    @respx.mock
    def test_scripts_classified(self, tool):
        """Inline and external scripts should be counted separately."""
        respx.get("https://example.com").mock(return_value=_html_response(NORMAL_HTML))

        result = tool.run("example.com")
        scripts = result.data["scripts"]

        assert scripts["inline_count"] == 1
        assert scripts["external_count"] == 1
        assert "https://cdn.example.com/lib.js" in scripts["external_sources"]

    # ── Suspicious JS detection ──────────────────────────────

    @respx.mock
    def test_suspicious_js_detected(self, tool):
        """Obfuscation patterns should be detected and counted."""
        respx.get("https://evil.com").mock(return_value=_html_response(SUSPICIOUS_HTML))

        result = tool.run("evil.com")
        suspicious = result.data["suspicious_js"]

        # The sample HTML has at least: 1 eval, 2 atob, 1 document_write, 1 long base64 blob
        assert suspicious["total_matches"] >= 4
        assert suspicious["patterns"]["atob_calls"] >= 1
        assert suspicious["patterns"]["eval_calls"] >= 1
        assert suspicious["patterns"]["document_write"] >= 1
        assert suspicious["patterns"]["long_base64_blobs"] >= 1

    @respx.mock
    def test_clean_page_no_suspicious_markers(self, tool):
        """A clean page should have zero suspicious matches."""
        clean_html = "<html><head><title>Clean</title></head><body>Hello</body></html>"
        respx.get("https://example.com").mock(return_value=_html_response(clean_html))

        result = tool.run("example.com")
        assert result.data["suspicious_js"]["total_matches"] == 0

    # ── Edge cases ──────────────────────────────────────────

    @respx.mock
    def test_title_with_nested_elements(self, tool):
        """Titles with nested HTML elements should still extract cleanly (the .title.string bug)."""
        html = "<html><head><title><span>Wrapped</span> Title</title></head><body></body></html>"
        respx.get("https://example.com").mock(return_value=_html_response(html))

        result = tool.run("example.com")
        # Should not crash, should produce some text
        assert "Title" in result.data["title"]

    @respx.mock
    def test_missing_title(self, tool):
        """Page with no title tag should return empty string, not crash."""
        html = "<html><body>No head section</body></html>"
        respx.get("https://example.com").mock(return_value=_html_response(html))

        result = tool.run("example.com")
        assert result.data["title"] == ""

    @respx.mock
    def test_non_html_response_skipped(self, tool):
        """JSON or plain-text responses should be detected and skip parsing."""
        respx.get("https://api.example.com").mock(
            return_value=httpx.Response(
                200,
                content=b'{"hello": "world"}',
                headers={"content-type": "application/json"},
            )
        )

        result = tool.run("api.example.com")
        assert "note" in result.data
        assert "non-HTML" in result.data["note"]
