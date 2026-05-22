# ATLAS

**A multi-layered defensive security analysis platform.**

ATLAS investigates suspicious URLs and domains by running them through a tiered threat-analysis pipeline alongside a suite of investigative recon tools and correlation engines. One command (`atlas investigate`) returns a complete picture: threat verdict, DNS records, WHOIS history, IP geolocation and exposure, certificate transparency log analysis, HTTP security headers, page content inspection, a sandboxed browser analysis from urlscan.io, and a synthesized correlation layer that maps everything to a composite risk score, domain timeline, and MITRE ATT&CK techniques.

Built as a consolidation of three earlier security projects, ATLAS is designed to be a unified platform with clear data flow, structured output, and an architecture that's easy to extend.

---

## Quick Start

```bash
# Install (editable mode for development)
pip install -e ".[all]"

# The flagship command — full investigation of a domain
atlas investigate github.com

# Scan a single URL through the threat pipeline only
atlas scan https://example.com

# Run individual recon tools
atlas recon dns example.com
atlas recon whois example.com
atlas recon ip example.com
atlas recon headers https://example.com
atlas recon web https://example.com
atlas recon crtsh example.com
atlas recon urlscan https://example.com

# Re-run correlations against a stored scan (without re-running recon)
atlas correlate <scan_id>

# Batch scan from a file
atlas scan --file urls.txt

# Review history and stats
atlas history --limit 10
atlas stats
```

---

## What's Inside

ATLAS is organized into three complementary capability layers: **tiers** that produce risk verdicts, **recon tools** that produce investigative information, and **correlators** that synthesize everything into higher-order insights.

### Analysis Tiers

Tiers run in sequence as part of the threat-analysis pipeline. Each produces a verdict component; high-confidence flags trigger early exit.

| # | Tier | What it checks | API key needed |
|---|------|----------------|----------------|
| 1 | Local Blocklist | StevenBlack hosts list (100K+ malicious domains, cached locally) | — |
| 2 | Heuristics | Shannon entropy (DGA detection) + WHOIS domain age | — |
| 3 | Typosquat Detection | Levenshtein distance against 30 high-value brand domains | — |
| 4 | DNSBL | Spamhaus DBL + SURBL (concurrent queries) | — |
| 5 | VirusTotal | Multi-engine reputation lookup with rate-limit retry | Free key |

### Recon Tools

Recon tools provide investigative information rather than verdicts. Run individually or together via `atlas investigate`.

| Tool | What it does | API key needed |
|------|--------------|----------------|
| `dns` | A, AAAA, MX, TXT, NS record lookups | — |
| `headers` | HTTP response headers with OWASP security scoring (HSTS, CSP, X-Frame-Options, etc.) | — |
| `web` | Page title, meta, external links, forms, scripts, suspicious JS markers (eval, atob, base64 blobs) | — |
| `whois` | Domain registration metadata, age, expiry status, name servers | — |
| `ip` | Geolocation, ISP, ASN (ip-api) + open ports and CVEs (Shodan InternetDB) | — |
| `crtsh` | Certificate Transparency log search — subdomain enumeration via cert history, issuer breakdown | — |
| `urlscan` | Sandboxed browser visit with screenshot, network capture, malicious-content scoring | Free key |

### Correlators

Correlators run after the pipeline and recon tools complete. They make zero network calls — they're pure computation over already-gathered data — and produce higher-order synthesis that no individual tool can on its own.

| Correlator | What it produces |
|------------|-----------------|
| `risk_score` | Composite 0–100 risk score aggregating tier flags, WHOIS age, HTTP header grade, urlscan verdict, and cert velocity — with a per-contribution breakdown |
| `timeline` | Chronological reconstruction of a domain's life from WHOIS registration, crt.sh cert history, and urlscan scan dates — surfaces anomalies like reused infrastructure or dormant domains |
| `mitre` | Maps tier flags and recon findings to MITRE ATT&CK technique IDs (e.g. T1566.002 Spearphishing Link, T1583.001 Acquire Infrastructure: Domains) using a rules-based engine |

---

## The `investigate` Command

The flagship workflow. One input, full output.

```bash
atlas investigate github.com
```

Runs the threat-analysis pipeline, all seven recon tools, and the full correlation layer sequentially, with section dividers and per-tool formatted output. Takes ~60-90 seconds for a typical domain (urlscan.io accounts for most of that). Use `--skip-slow` to omit urlscan, or `--skip-scan` to omit the threat pipeline.

The output combines:

- **Threat verdict** — Clean / Medium Risk / High Risk based on tier results
- **DNS records** — every record type for the apex and discovered subdomains
- **WHOIS** — registrar, age, expiry, name servers
- **IP intelligence** — where the domain resolves to, who hosts it, what's exposed
- **Certificate Transparency** — every subdomain a cert has ever been issued for
- **HTTP security headers** — graded based on OWASP Secure Headers recommendations
- **Web content** — what the page actually contains, including obfuscation markers
- **urlscan.io sandbox** — what happens when a real browser visits the URL
- **Correlations** — composite risk score, domain timeline, and MITRE ATT&CK mapping

---

## The `correlate` Command

Re-run correlations against any previously stored scan without re-paying the cost of fresh recon.

```bash
atlas correlate 42
```

Useful for re-analyzing past scans after adding new correlators, or for inspecting a scan's synthesis in isolation. Fetches the stored `ScanReport` by ID, runs the full `CorrelationPipeline` against it, persists the results, and renders them to the terminal.

---

## Architecture

```
atlas/
├── core/         Pipeline orchestration, Pydantic data models, YAML config
├── tiers/        Verdict-producing analysis modules (5 tiers + extensible base class)
├── recon/        Information-gathering investigative tools (7 tools + extensible base class)
├── correlate/    Synthesis layer (3 correlators + extensible base class)
├── storage/      SQLite persistence with scan history and aggregate statistics
├── cli/          Typer-based command-line interface with Rich-formatted output
└── api/          FastAPI service layer
```

**Three extensible base classes** define the common shape of the platform:
- `Tier` — verdict-producing modules; implement `_check()`
- `ReconTool` — information-gathering modules; implement `_run()`
- `Correlator` — synthesis modules; implement `_correlate()`

Each new module implements one method and is registered in its respective pipeline.

**Config-driven behavior.** All thresholds, timeouts, rate limits, and API endpoints live in `config/default.yaml`.

**Structured output everywhere.** Every tier returns a `TierResult`, every recon tool returns a `ReconResult`, every correlator returns a `CorrelationResult`, and every scan produces a `ScanReport`. These Pydantic models are the lingua franca — the same data shapes flow through the CLI, the storage layer, and the API.

---

## API

ATLAS incorporates a FastAPI service layer covering the full platform surface.

```bash
# Start the API server
atlas serve
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Run the threat-analysis pipeline against a URL |
| `POST` | `/api/v1/investigate` | Full investigation — pipeline + all recon + correlations |
| `POST` | `/api/v1/correlate/{scan_id}` | Re-run correlations against a stored scan |
| `GET` | `/api/v1/recon/{tool}/{target}` | Run a single recon tool |
| `GET` | `/api/v1/stats` | Aggregate platform statistics |

The `POST /api/v1/investigate` response includes a `correlations` field automatically. The `POST /api/v1/correlate/{scan_id}` endpoint is for re-running correlations against a stored scan without repeating the underlying scan and recon work.

---

## Configuration

`config/default.yaml` controls everything tunable. Highlights:

- Tier thresholds (entropy cutoff, domain-age threshold, VirusTotal danger %, etc.)
- Retry counts and timeouts per service
- Blocklist cache freshness window
- Database file path

API keys live in `.env` (not committed):

```
VIRUSTOTAL_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

Both services have free tiers with generous limits for personal use.

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[all]"

# Run the full test suite
pytest tests/ -v

# Lint
ruff check src/ tests/

# Type check
mypy src/

# Generate coverage report
pytest --cov=atlas tests/
```

External services are fully mocked in tests via `respx` (HTTP) and `unittest.mock` (DNS, WHOIS, file I/O), so the test suite runs in seconds and works offline. Correlators are pure computation and have no mocking requirements.

---

## Design Notes

**Tiers vs recon vs correlators are conceptually distinct.** Tiers produce a verdict — they answer "is this bad?". Recon tools produce structured information — they answer "what does this look like?". Correlators produce synthesis — they answer "what does this all mean?". All three share a similar timing-and-error-handling lifecycle but live in separate directories and implement different base classes.

**Correlators are pure computation.** They read already-gathered data and produce insights without making network calls. This makes them fast (milliseconds each), trivially testable, and safe to re-run against any stored scan at any time.

**Early exit in the pipeline.** Once a high-confidence tier flags a URL as High Risk, the pipeline stops running subsequent tiers. This saves time and avoids burning rate-limited API calls when the answer is already clear.

**Graceful degradation.** Any single tool or correlator can fail (network error, API rate limit, service outage) without bringing down the pipeline or `investigate` command. Errors are captured per-module with structured messages; everything else still runs.

**External services are isolated.** Network calls happen inside individual tier/recon modules. Tests mock at the HTTP layer so the core pipeline logic can be tested independently.

---

## Lineage

ATLAS consolidates three earlier academic projects into one platform:

- **ATLAS v1** — CLI cyber toolkit (IP intelligence, Hacker News scraping, header inspection)
- **URL Auditor** — Tiered URL analysis engine (became the core of this pipeline)
- **Cybersecurity Toolkit** — GUI-based security tools (DNS, hashing, ARP scan, web recon)

Each contributed components that were rebuilt and unified under the shared architecture documented above.

---

## License

MIT