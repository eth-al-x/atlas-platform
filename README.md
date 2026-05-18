# ATLAS

**A multi-layered defensive security analysis platform.**

ATLAS passes URLs through a configurable pipeline of analysis tiers — from fast local blocklist lookups to DNS reputation checks, heuristic analysis, and external threat intelligence — producing a risk verdict with structured evidence at each step.

## Quick Start

```bash
# Install (editable mode for development)
pip install -e ".[all]"

# Scan a single URL
atlas scan https://example.com

# Verbose output with tier details
atlas scan https://example.com --verbose

# Batch scan from file
atlas scan --file urls.txt

# Interactive mode
atlas scan

# View scan history
atlas history --limit 10

# Aggregate statistics
atlas stats
```

## Architecture

```
atlas/
├── core/          Pipeline orchestration, data models, config
├── tiers/         Analysis modules (blocklist, heuristics, DNSBL, ...)
├── recon/         Investigative tools (DNS, HTTP headers, WHOIS, ARP, ...)
├── storage/       SQLite persistence and query interface
├── cli/           Typer-based command-line interface
└── api/           FastAPI service layer (coming soon)
```

## Analysis Tiers

| Tier | Module | What it checks |
|------|--------|----------------|
| 1 | Local Blocklist | StevenBlack hosts list (100K+ domains, cached locally) |
| 2 | Heuristics | Shannon entropy (DGA detection) + WHOIS domain age |
| 3 | DNSBL | Spamhaus DBL + SURBL (concurrent queries) |
| — | *Planned* | URLhaus, PhishTank, TLS analysis, VirusTotal, urlscan.io |

## Configuration

All thresholds and settings live in `config/default.yaml`. No magic numbers in code.

## Development

```bash
# Install with dev dependencies
pip install -e ".[all]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Lineage

ATLAS consolidates three earlier projects into one platform:
- **ATLAS v1** — CLI cyber toolkit (IP intelligence, Hacker News, headers)
- **URL Auditor** — Tiered URL analysis engine (the core of this pipeline)
- **Cybersecurity Toolkit** — GUI-based security tools (DNS, hashing, ARP, web recon)

## License

MIT
