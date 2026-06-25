from __future__ import annotations

import logging
import os
from pathlib import Path

# Load .env before any other imports so NVD_API_KEY and CVE_MODE are set
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.scans import router as scans_router
from api.assets import router as assets_router
from api.cves import router as cves_router
from api.debug import router as debug_router
from api.network_scans import router as network_router
from utils.logger import get_logger

# Root logger config — applied before any module imports log anything.
logging.basicConfig(level=logging.INFO)
logger = get_logger(__name__)

app = FastAPI(
    title="Vectra Security Platform",
    description="Security scanning API — FastAPI + Nuclei",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ────────────────────────────────────────────────────────────
# allow_origins=["*"] is intentional for local development.
# In production, replace with the exact frontend origin, e.g.:
#   allow_origins=["https://app.vectra.io"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────────
app.include_router(scans_router)
app.include_router(assets_router)
app.include_router(cves_router)
app.include_router(debug_router)
app.include_router(network_router)


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("Vectra backend started — docs at /docs")
