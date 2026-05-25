"""
atlas.core.config
Loads and validates application configuration from YAML.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class AnalysisConfig(BaseModel):
    early_exit_on_high_risk: bool = True
    entropy_threshold: float = 3.8
    age_threshold_hours: int = 48
    virustotal_danger_threshold: float = 10.0
    max_retries: int = 3
    retry_wait_seconds: int = 60
    request_timeout: int = 10


class BlocklistConfig(BaseModel):
    source_url: str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    cache_filename: str = "malicious_host_cache.txt"
    max_cache_age_hours: int = 24


class DNSBLConfig(BaseModel):
    mirrors: list[str] = ["dbl.spamhaus.org", "multi.surbl.org"]
    timeout_seconds: float = 3.0


class StorageConfig(BaseModel):
    database_path: str = "atlas.db"


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class GreyNoiseConfig(BaseModel):
    # Base URL for the Community API — override for Enterprise
    community_url: str = "https://api.greynoise.io/v3/community/{ip}"
    timeout_seconds: int = 10
    # API key is read from GREYNOISE_API_KEY in .env, not stored here


class CensysConfig(BaseModel):
    search_url: str = "https://search.censys.io/api/v2/certificates/search"
    timeout_seconds: int = 15
    # Results per page — Censys max is 100
    per_page: int = 100
    # Max pages to walk per domain (each page = 1 API query against your quota)
    # Default 5 pages × 100 results = up to 500 certs per domain
    max_pages: int = 5
    # Credentials are read from CENSYS_API_ID / CENSYS_API_SECRET in .env


class JarmConfig(BaseModel):
    # Target port — JARM hashes are port-specific; 443 is the default for
    # HTTPS services. Could be overridden for SMTPS, IMAPS, etc.
    port: int = 443
    # Per-handshake timeout in seconds. Total scan time is bounded by
    # this × (10 packets / concurrency) ≈ this × 5 in the worst case.
    timeout_seconds: int = 10


class AtlasConfig(BaseModel):
    analysis: AnalysisConfig = AnalysisConfig()
    blocklist: BlocklistConfig = BlocklistConfig()
    dnsbl: DNSBLConfig = DNSBLConfig()
    storage: StorageConfig = StorageConfig()
    server: ServerConfig = ServerConfig()
    greynoise: GreyNoiseConfig = GreyNoiseConfig()
    censys: CensysConfig = CensysConfig()
    jarm: JarmConfig = JarmConfig()


def load_config(config_path: Path | None = None) -> AtlasConfig:
    """Load configuration from YAML file, falling back to defaults."""
    if config_path is None:
        # Search common locations
        candidates = [
            Path("config/default.yaml"),
            Path("default.yaml"),
            Path.home() / ".atlas" / "config.yaml",
        ]
        for candidate in candidates:
            if candidate.exists():
                config_path = candidate
                break

    raw: dict[str, Any] = {}
    if config_path and config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}

    return AtlasConfig(**raw)


# Module-level singleton — import this from anywhere
_config: AtlasConfig | None = None


def get_config() -> AtlasConfig:
    """Return the global config, loading it on first access."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
