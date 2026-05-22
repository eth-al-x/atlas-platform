"""
atlas.api.dependencies
FastAPI dependency injection for shared resources.

One AnalysisPipeline and one ScanRepository are created at API startup
and reused across all requests. These are injected via FastAPI's Depends()
system so routes stay clean and testable.

Usage in a route:
    @router.post("/scan")
    async def scan(
        body: ScanRequestBody,
        pipeline: AnalysisPipeline = Depends(get_pipeline),
        repo: ScanRepository = Depends(get_repo),
    ):
        ...
"""

from __future__ import annotations

from atlas.core.config import AtlasConfig, get_config
from atlas.core.pipeline import AnalysisPipeline
from atlas.storage.db import ScanRepository

# Module-level singletons — initialized once at startup via lifespan
_pipeline: AnalysisPipeline | None = None
_repo: ScanRepository | None = None
_config: AtlasConfig | None = None


def init_dependencies() -> None:
    """
    Initialize shared resources. Called once during API startup
    via the lifespan context manager in main.py.
    """
    global _pipeline, _repo, _config
    _config = get_config()
    _repo = ScanRepository()
    _pipeline = AnalysisPipeline(config=_config)


def get_pipeline() -> AnalysisPipeline:
    """FastAPI dependency: returns the shared analysis pipeline."""
    if _pipeline is None:
        raise RuntimeError("Pipeline not initialized. Call init_dependencies() first.")
    return _pipeline


def get_repo() -> ScanRepository:
    """FastAPI dependency: returns the shared scan repository."""
    if _repo is None:
        raise RuntimeError("Repository not initialized. Call init_dependencies() first.")
    return _repo


def get_atlas_config() -> AtlasConfig:
    """FastAPI dependency: returns the loaded config."""
    if _config is None:
        raise RuntimeError("Config not initialized. Call init_dependencies() first.")
    return _config
