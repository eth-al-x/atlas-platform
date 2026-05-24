# ATLAS

**A multi-layered defensive security analysis platform.**

ATLAS investigates suspicious URLs and domains by running them through a tiered threat-analysis pipeline alongside a suite of investigative recon tools and correlation engines. One command (`atlas investigate`) returns a complete picture: threat verdict, DNS records, WHOIS history, IP geolocation and exposure, certificate transparency log analysis, HTTP security headers, page content inspection (including a Shodan-compatible favicon hash), email/anti-spoofing posture, IP neighborhood enumeration, optional active subdomain discovery, a sandboxed browser analysis from urlscan.io, and a synthesized correlation layer that maps everything to a composite risk score, domain timeline, MITRE ATT&CK techniques, and cross-scan infrastructure pivots.

Built as a consolidation of three earlier security projects, ATLAS is designed to be a unified platform with clear data flow, structured output, an extensible architecture, a watch list for ongoing monitoring, pivot commands for analyst-driven investigation, an HTTP API, and a built-in web dashboard.

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
atlas recon email example.com
atlas recon neighbors example.com
atlas recon subdomains example.com        # active recon — see warning below

# Re-run correlations against a stored scan (without re-running recon)
atlas correlate <scan_id>

# Watch list — monitor domains for verdict changes
atlas watch add evil.example.com
atlas watch list
atlas watch run

# Pivot from a single piece of evidence to related scans
atlas pivot favicon 1234567890
atlas pivot subnet 203.0.113.0/24

# Batch scan from a file
atlas scan --file urls.txt

# Review history and stats
atlas history --limit 10
atlas stats

# Structured output (JSON or CSV) on any command
atlas investigate github.com --output json
atlas history --output csv
atlas stats --output json

# Start the API + web dashboard
atlas serve
# → API:        http://localhost:8000/api/v1
# → Dashboard:  http://localhost:8000/dashboard
# → Docs:       http://localhost:8000/docs
```

---

## What's Inside

ATLAS is organized into three complementary capability layers: **tiers** that produce risk verdicts, **recon tools** that produce investigative information, and **correlators** that synthesize everything into higher-order insights. On top of that sit analyst workflows: the watch list, pivot commands, the API, and the web dashboard.

### Analysis Tiers

Tiers run in sequence as part of the threat-analysis pipeline. Each produces a verdict component; high-confidence flags trigger early exit.

| # | Tier | What it checks | API key needed |
|---|------|----------------|----------------|
| 1 | Local Blocklist | StevenBlack hosts list (100K+ malicious domains, cached locally) | — |
| 2 | Heuristics | Six structural signals — Shannon entropy (DGA detection), WHOIS domain age, subdomain depth, consonant/vowel ratio, numeric character ratio, and known-DGA regex fingerprints (Conficker, hex strings, hyphen chains) — combined via a weighted confidence score | — |
| 3 | Typosquat Detection | Levenshtein distance against 30 high-value brand domains | — |
| 4 | DNSBL | Spamhaus DBL + SURBL (concurrent queries) | — |
| 5 | VirusTotal | Multi-engine reputation lookup with rate-limit retry | Free key |

### Recon Tools

Recon tools provide investigative information rather than verdicts. Run individually or together via `atlas investigate`.

| Tool | What it does | API key needed |
|------|--------------|----------------|
| `dns` | A, AAAA, MX, TXT, NS record lookups | — |
| `headers` | HTTP response headers with OWASP security scoring (HSTS, CSP, X-Frame-Options, etc.) | — |
| `web` | Page title, meta, external links, forms, scripts, suspicious JS markers (eval, atob, base64 blobs), and a Shodan-compatible MMH3 favicon hash | — |
| `whois` | Domain registration metadata, age, expiry status, name servers | — |
| `ip` | Geolocation, ISP, ASN (ip-api) + open ports and CVEs (Shodan InternetDB) | — |
| `crtsh` | Certificate Transparency log search — subdomain enumeration via cert history, issuer breakdown | — |
| `urlscan` | Sandboxed browser visit with screenshot, network capture, malicious-content scoring | Free key |
| `email` | MX + SPF + DMARC + DKIM (curated selector probe) parsed into a 0–100 anti-spoofing posture score with structured issues | — |
| `neighbors` | PTR-sweeps the CIDR block around the target's IP (default /28; configurable /24–/30) to surface other domains parked on the same shared host or in the same provider range | — |
| `subdomains` | **Active recon.** Bruteforces subdomains against a built-in 500-word list using rate-limited concurrent DNS lookups (~15s). Generates real DNS traffic against the target — only run against domains you own or have permission to test. A one-time acknowledgement is required on first use. | — |

### Correlators

Correlators run after the pipeline and recon tools complete. The first three are pure computation over already-gathered data; the cross-scan correlator additionally queries the local scan database. None make outbound network calls.

| Correlator | What it produces |
|------------|-----------------|
| `risk_score` | Composite 0–100 risk score aggregating tier flags, WHOIS age, HTTP header grade, urlscan verdict, and cert velocity — with a per-contribution breakdown |
| `timeline` | Chronological reconstruction of a domain's life from WHOIS registration, crt.sh cert history, and urlscan scan dates — surfaces anomalies like reused infrastructure or dormant domains |
| `mitre` | Maps tier flags and recon findings to MITRE ATT&CK technique IDs (e.g. T1566.002 Spearphishing Link, T1583.001 Acquire Infrastructure: Domains) using a rules-based engine |
| `cross_scan` | Pivots on the current scan's IP, ASN, registrar, favicon hash, and /24 prefix to find every previously-stored scan that shares any of those attributes — surfaces campaign infrastructure that a single-URL view would miss |

---

## The `investigate` Command

The flagship workflow. One input, full output.

```bash
atlas investigate github.com
atlas investigate github.com --skip-slow            # omit urlscan.io
atlas investigate github.com --skip-scan            # recon + correlation only
atlas investigate github.com --with-subdomains      # include active subdomain enumeration
atlas investigate github.com --output json          # structured output
```

Runs the threat-analysis pipeline, all passive recon tools, and the full correlation layer sequentially, with section dividers and per-tool formatted output. Takes ~60-90 seconds for a typical domain (urlscan.io accounts for most of that). Active subdomain enumeration is opt-in via `--with-subdomains` and prompts for a one-time acknowledgement.

The output combines:

- **Threat verdict** — Clean / Low Risk / Medium Risk / High Risk based on tier results
- **DNS records** — every record type for the apex and discovered subdomains
- **WHOIS** — registrar, age, expiry, name servers
- **IP intelligence** — where the domain resolves to, who hosts it, what's exposed
- **Certificate Transparency** — every subdomain a cert has ever been issued for
- **HTTP security headers** — graded based on OWASP Secure Headers recommendations
- **Web content** — what the page actually contains, including obfuscation markers and the favicon's MMH3 hash
- **Email infrastructure** — MX/SPF/DMARC/DKIM with an anti-spoofing posture score
- **IP neighborhood** — PTR sweep of nearby IPs to find shared-host neighbors
- **urlscan.io sandbox** — what happens when a real browser visits the URL
- **Correlations** — composite risk score, domain timeline, MITRE ATT&CK mapping, and cross-scan infrastructure pivots

---

## The `correlate` Command

Re-run correlations against any previously stored scan without re-paying the cost of fresh recon.

```bash
atlas correlate 42
```

Useful for re-analyzing past scans after adding new correlators, or for inspecting a scan's synthesis in isolation. Fetches the stored `ScanReport` by ID, runs the full `CorrelationPipeline` against it (including cross-scan pivots against the rest of the database), persists the results, and renders them to the terminal.

---

## The `watch` Command Group

A simple monitoring loop for domains you want to keep an eye on. Each watched domain gets re-scanned through the threat pipeline on demand, with verdict changes surfaced as alerts.

```bash
atlas watch add evil.example.com           # register a domain
atlas watch list                           # show all active watches
atlas watch list --all                     # include removed watches
atlas watch remove 7                       # deactivate (soft delete; history is kept)
atlas watch run                            # re-scan every active watch
atlas watch run --changed-only             # only show alerts where the verdict changed
```

The watch list and the analysis pipeline share the same SQLite store, so alerts are produced relative to whatever verdict was last recorded for each domain. Alerts include direction (`new`, `escalated`, `de-escalated`, `unchanged`), the new verdict, the previous verdict, and the scan ID of the freshly-stored scan. Recon is intentionally skipped during watch runs — the goal is fast verdict diffing, not full investigation; if a domain alert is interesting, follow up with `atlas investigate`.

---

## The `pivot` Command Group

Pivots take a single piece of evidence (a favicon hash, an IP, an ASN, a CIDR range) and answer *"what else have we scanned that shares this attribute?"*. This is the same machinery the cross-scan correlator uses, but exposed as direct investigative commands so an analyst can pivot from any signal — a Shodan result, a phishing report, a SIEM alert — without first having to scan a related domain.

```bash
atlas pivot favicon 1234567890             # every scan whose favicon hashed to this MMH3 value
atlas pivot subnet 203.0.113.0/24          # every scan with a resolved IP inside this CIDR
atlas pivot subnet 198.51.100.0/27 -n 50   # widen result limit
```

Both pivots accept `--output json` and `--output csv` for downstream tooling.

---

## Output Formats

Every CLI command that produces report-like data accepts `--output / -o`:

```
--output terminal   (default — Rich-formatted tables)
--output json       (full-fidelity JSON, suitable for piping into jq, SIEMs, dashboards)
--output csv        (flattened one-row-per-scan summary; lossy by design)
```

JSON output mirrors the API's `InvestigateResponse` shape (`{scan, recon, correlations}`), so CLI output and API responses can be ingested by the same parser. CSV is intentionally narrow — analyst-relevant columns only (verdict, risk score, flagged tiers, MITRE techniques, related-domain count). When you want everything, use JSON.

---

## Web Dashboard

`atlas serve` ships with a built-in single-page operations console served as plain static files (no build step required).

```
http://localhost:8000/dashboard
```

Sections:
- **Overview** — aggregate stats, recent activity, verdict breakdown
- **Scans** — paginated scan history with drill-down into stored recon and correlations
- **Watches** — manage the watch list and trigger `watch run` from the browser

The dashboard is served from `atlas/api/static/` and consumes the same `/api/v1/*` endpoints that any other client would, which makes it a reasonable reference implementation if you want to build your own UI.

---

## Architecture

```
atlas/
├── core/         Pipeline orchestration, Pydantic data models, YAML config, JSON/CSV export
├── tiers/        Verdict-producing analysis modules (5 tiers + extensible base class)
├── recon/        Information-gathering investigative tools (10 tools + extensible base class)
├── correlate/    Synthesis layer (4 correlators + extensible base class)
├── storage/      SQLite persistence with scan history, recon storage, watch list, aggregate stats
├── cli/          Typer-based command-line interface with Rich-formatted output
└── api/          FastAPI service layer + bundled static dashboard
```

**Three extensible base classes** define the common shape of the platform:
- `Tier` — verdict-producing modules; implement `_check()`
- `ReconTool` — information-gathering modules; implement `_run()`
- `Correlator` — synthesis modules; implement `_correlate()`

Each new module implements one method and is registered in its respective pipeline.

**Config-driven behavior.** All thresholds, timeouts, rate limits, and API endpoints live in `config/default.yaml`.

**Structured output everywhere.** Every tier returns a `TierResult`, every recon tool returns a `ReconResult`, every correlator returns a `CorrelationResult`, and every scan produces a `ScanReport`. Watches and alerts have their own `WatchEntry` / `WatchAlert` models. These Pydantic models are the lingua franca — the same data shapes flow through the CLI, the storage layer, the API, the dashboard, and the JSON/CSV exporters.

---

## API

ATLAS incorporates a FastAPI service layer covering the full platform surface, plus a static dashboard served from the same origin.

```bash
# Start the API server (also serves the dashboard at /dashboard)
atlas serve
atlas serve --host 0.0.0.0 --port 8080 --reload
```

### Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Run the threat-analysis pipeline against a URL |
| `POST` | `/api/v1/investigate` | Full investigation — pipeline + all recon + correlations |
| `POST` | `/api/v1/correlate/{scan_id}` | Re-run correlations against a stored scan |

### Scan history

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/scans` | List recent scans (paginated) |
| `GET` | `/api/v1/scans/{scan_id}` | Fetch a single stored scan report |
| `GET` | `/api/v1/scans/{scan_id}/recon` | Stored recon results keyed by tool name |

### Recon

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/recon/dns/{domain}` | DNS record lookup |
| `GET` | `/api/v1/recon/headers?url=...` | HTTP security headers |
| `GET` | `/api/v1/recon/web?url=...` | Web content recon |
| `GET` | `/api/v1/recon/whois/{domain}` | WHOIS lookup |
| `GET` | `/api/v1/recon/ip/{domain}` | IP intelligence |
| `GET` | `/api/v1/recon/crtsh/{domain}` | Certificate Transparency search |
| `GET` | `/api/v1/recon/urlscan?url=...` | urlscan.io sandbox analysis |
| `GET` | `/api/v1/recon/subdomains/{domain}` | Active subdomain enumeration |
| `GET` | `/api/v1/recon/email/{domain}` | Email infrastructure & anti-spoofing posture |
| `GET` | `/api/v1/recon/neighbors/{domain}` | IP neighborhood (PTR-sweep), `?cidr_bits=24..30` |

### Watches

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/watches` | List watch entries (`?active=true` to filter) |
| `POST` | `/api/v1/watches` | Add a domain to the watch list (idempotent) |
| `GET` | `/api/v1/watches/{watch_id}` | Get a single watch entry |
| `DELETE` | `/api/v1/watches/{watch_id}` | Remove (soft delete) a watch |
| `POST` | `/api/v1/watches/run` | Re-scan all active watches and return alerts |

### Pivots

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/pivot/favicon/{favicon_hash}` | Scans sharing an MMH3 favicon hash |
| `GET` | `/api/v1/pivot/subnet?cidr=...` | Scans whose resolved IP falls in a CIDR range |

### Platform

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/stats` | Aggregate platform statistics (`?days=` window) |
| `GET` | `/api/v1/health` | Health check — confirms loaded tiers and recon tools |
| `GET` | `/docs` | Auto-generated Swagger UI |
| `GET` | `/redoc` | Auto-generated ReDoc |
| `GET` | `/dashboard` | Bundled web dashboard (single-page app) |

The `POST /api/v1/investigate` response includes a `correlations` field automatically and persists recon results so they're retrievable via `GET /scans/{id}/recon`. The `POST /api/v1/correlate/{scan_id}` endpoint is for re-running correlations against a stored scan without repeating the underlying scan and recon work — and uses stored recon when available to produce full-fidelity correlations.

---

## Configuration

`config/default.yaml` controls everything tunable. Highlights:

- Tier thresholds (entropy cutoff, domain-age threshold, VirusTotal danger %, etc.)
- Retry counts and timeouts per service
- Blocklist cache freshness window
- Subdomain enumeration rate limits and worker count
- IP neighborhood default CIDR width
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

External services are fully mocked in tests via `respx` (HTTP) and `unittest.mock` (DNS, WHOIS, file I/O), so the test suite runs in seconds and works offline. Correlators are pure computation and have no mocking requirements; the cross-scan correlator is tested against an in-memory SQLite database.

---

## Design Notes

**Tiers vs recon vs correlators are conceptually distinct.** Tiers produce a verdict — they answer "is this bad?". Recon tools produce structured information — they answer "what does this look like?". Correlators produce synthesis — they answer "what does this all mean?". All three share a similar timing-and-error-handling lifecycle but live in separate directories and implement different base classes.

**Correlators are mostly pure computation.** Three of four (`risk_score`, `timeline`, `mitre`) read already-gathered data and produce insights without making network calls. The fourth (`cross_scan`) queries the local scan database to find related infrastructure — it makes no external calls either, and gracefully no-ops when no repository is wired in (e.g. in tests). This makes correlators fast (milliseconds each), trivially testable, and safe to re-run against any stored scan at any time.

**Cross-scan correlation turns ATLAS into a campaign-aware platform.** A domain may look clean in isolation but become obviously malicious when you see five other flagged domains on the same IP or sharing the same favicon. The `pivot` commands expose the same machinery as direct analyst tooling.

**Early exit in the pipeline.** Once a high-confidence tier flags a URL as High Risk, the pipeline stops running subsequent tiers. This saves time and avoids burning rate-limited API calls when the answer is already clear.

**Graceful degradation.** Any single tool or correlator can fail (network error, API rate limit, service outage) without bringing down the pipeline or `investigate` command. Errors are captured per-module with structured messages; everything else still runs.

**External services are isolated.** Network calls happen inside individual tier/recon modules. Tests mock at the HTTP layer so the core pipeline logic can be tested independently.

**Active recon is gated.** The `subdomains` tool is the only one in ATLAS that generates significant outbound traffic against external infrastructure. On first use it prompts for a one-time acknowledgement (stored at `~/.atlas/active_recon_acknowledged`); subsequent runs go straight to enumeration. Don't run it against domains you don't own or have permission to test.

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
