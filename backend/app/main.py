"""AegisGemma — Autonomous Red-Teaming & Security Sandbox Agent.

FastAPI application entrypoint.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Load the environment BEFORE importing the application modules: the API
# layer builds the Gemma client at import time, so the provider key must
# already be in os.environ.
load_dotenv()

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from .api.v1.audit import get_store, router as audit_router  # noqa: E402
from .api.v1.websocket import router as websocket_router  # noqa: E402

app = FastAPI(
    title="AegisGemma",
    description=(
        "Autonomous red-teaming and security sandbox agent. Ingests source trees, "
        "OpenAPI specs and infrastructure config; performs static analysis, threat "
        "modeling, non-destructive PoC synthesis and remediation patch generation."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_origins=os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001",
    ).split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(audit_router)
app.include_router(websocket_router)

app.state.store = get_store()


@app.get("/health")
async def health() -> dict:
    from .core.gemma_client import GemmaClient

    client = GemmaClient()
    return {
        "status": "ok",
        "service": "aegisgemma-backend",
        "provider": client.provider,
        "model": client.model,
        "ai_available": client.available,
    }


@app.get("/")
async def root() -> dict:
    return {
        "name": "AegisGemma",
        "docs": "/docs",
        "health": "/health",
        "endpoints": [
            "POST /api/v1/audits",
            "GET /api/v1/audits/{id}",
            "GET /api/v1/audits/{id}/report",
            "WS /api/v1/audits/{id}/stream",
        ],
    }
