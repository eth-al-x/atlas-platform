"""
atlas.api.main
FastAPI application factory.

Creates and configures the ATLAS API. All routes, middleware, and startup
logic live here. The app is created via create_app() so it can be
instantiated in tests without side effects.

Usage:
    # Start the server via the CLI:
    atlas serve

    # Or directly with uvicorn:
    uvicorn atlas.api.main:app --reload

    # Browse auto-generated docs:
    http://localhost:8000/docs
    http://localhost:8000/redoc
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from atlas.api.dependencies import init_dependencies
from atlas.api.routes.scan import router as scan_router
from atlas.api.routes.recon import router as recon_router
from atlas.api.routes.recon import investigate_router
from atlas.api.routes.stats import router as stats_router
from atlas.api.routes.correlate import router as correlate_router
from atlas.api.routes.watches import router as watches_router
from atlas.api.routes.pivot import router as pivot_router

logger = logging.getLogger(__name__)


# Resolve the static directory at import time relative to this file so the
# dashboard works regardless of the process's working directory.
_STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan — runs setup before the server starts accepting
    requests, and teardown when it shuts down.

    Using FastAPI's lifespan context manager (the modern replacement for
    @app.on_event("startup") / @app.on_event("shutdown")).
    """
    # ── Startup ───────────────────────────────────────────────
    logger.info("ATLAS API starting up...")
    init_dependencies()
    logger.info("Dependencies initialized. Ready to serve requests.")

    yield  # Server is running — handle requests here

    # ── Shutdown ──────────────────────────────────────────────
    logger.info("ATLAS API shutting down.")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Separated from module-level instantiation so tests can call
    create_app() without triggering uvicorn import side effects.
    """
    app = FastAPI(
        title="ATLAS",
        description=(
            "**A**dvanced **T**hreat and **L**ookup **A**nalysis **S**ystem.\n\n"
            "A multi-layered defensive security analysis platform. "
            "Submit URLs for threat analysis, run investigative recon tools, "
            "and query historical scan data.\n\n"
            "**Tiers** produce threat verdicts. "
            "**Recon tools** produce investigative intelligence. "
            "**Investigate** runs both together."
        ),
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # ── CORS ──────────────────────────────────────────────────
    # Allow the web dashboard (served separately during dev) to call the API.
    # Tighten this for production.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routes ────────────────────────────────────────────────
    app.include_router(scan_router, prefix="/api/v1")
    app.include_router(recon_router, prefix="/api/v1")
    app.include_router(investigate_router, prefix="/api/v1")
    app.include_router(correlate_router, prefix="/api/v1")
    app.include_router(stats_router, prefix="/api/v1")
    app.include_router(watches_router, prefix="/api/v1")
    app.include_router(pivot_router, prefix="/api/v1")

    # ── Dashboard (static files) ──────────────────────────────
    # The dashboard is a single-page app served as plain static files.
    # We mount it at /dashboard so /api/* and /docs remain unaffected.
    if _STATIC_DIR.exists():
        app.mount(
            "/dashboard",
            StaticFiles(directory=str(_STATIC_DIR), html=True),
            name="dashboard",
        )
    else:
        logger.warning(
            "Dashboard static directory not found at %s. The /dashboard "
            "route will be unavailable.", _STATIC_DIR,
        )

    # ── Root redirect ─────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    async def root():
        from fastapi.responses import RedirectResponse
        # Prefer the dashboard if it's available; fall back to API docs
        target = "/dashboard" if _STATIC_DIR.exists() else "/docs"
        return RedirectResponse(url=target)

    return app


# Module-level app instance — used by uvicorn and the CLI serve command
app = create_app()
