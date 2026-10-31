"""Audit REST endpoints: upload a target, run an audit, fetch reports."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from ...core.gemma_client import GemmaClient
from ...core.ingest import files_from_directory, files_from_upload
from ...core.orchestrator import AuditEvent, AuditOrchestrator
from ...core.security_engine import TargetFile
from ...core.session_store import SessionStore
from ...schemas.audit_schema import AuditReport

router = APIRouter(prefix="/api/v1", tags=["audit"])

store = SessionStore()
gemma_client = GemmaClient()
orchestrator = AuditOrchestrator(gemma_client=gemma_client)


def get_store() -> SessionStore:
    return store


async def _run_audit(session_id: str, target: str, files: list[TargetFile]) -> None:
    session = await store.get(session_id)
    if session is None:
        return
    session.status = "running"

    async def on_event(event: AuditEvent) -> None:
        payload = event.to_dict()
        await store.publish(session, payload)
        if event.kind == "complete":
            session.status = "completed"
            report_data = event.data.get("report")
            if report_data:
                session.report = AuditReport.model_validate(report_data)
            session.completed_at = time.time()
        elif event.kind == "error":
            session.status = "failed"

    try:
        report = await orchestrator.run(files, target, on_event=on_event)
        session.report = report
        session.status = "completed"
    except Exception as exc:  # pragma: no cover - defensive
        session.status = "failed"
        await store.publish(
            session,
            AuditEvent(
                kind="error",
                stage="Audit",
                message=f"{type(exc).__name__}: {exc}",
                progress=100,
            ).to_dict(),
        )


@router.post("/audits", status_code=202)
async def create_audit(
    files: list[UploadFile] = File(default=[]),
    target: str = Form(default="uploaded-target"),
    path: str | None = Form(default=None),
) -> dict:
    """Start an audit from uploaded files, a .zip archive, or a server path."""
    ingested: list[TargetFile] = []

    if path:
        if not os.path.isdir(path):
            raise HTTPException(status_code=400, detail=f"Not a directory: {path}")
        ingested = files_from_directory(path)
    else:
        for upload in files:
            if not upload.filename:
                continue
            data = await upload.read()
            if not data:
                continue
            ingested.extend(files_from_upload(upload.filename, data))

    if not ingested:
        raise HTTPException(
            status_code=400,
            detail=(
                "No readable text files found. Upload source files, a .zip archive, "
                "an OpenAPI spec, Docker/Kubernetes/Terraform config, or pass ?path=."
            ),
        )

    session = await store.create(target)
    session.task = asyncio.create_task(_run_audit(session.id, target, ingested))
    return {
        "id": session.id,
        "status": session.status,
        "target": target,
        "file_count": len(ingested),
        "ws_url": f"/api/v1/audits/{session.id}/stream",
    }


@router.get("/audits")
async def list_audits() -> list[dict]:
    return await store.list()


@router.get("/audits/{session_id}")
async def get_audit(session_id: str) -> dict:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    return session.snapshot()


@router.get("/audits/{session_id}/events")
async def get_audit_events(session_id: str) -> list[dict]:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    return session.events


@router.get("/audits/{session_id}/report", response_model=AuditReport)
async def get_audit_report(session_id: str) -> AuditReport:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    if session.report is None:
        raise HTTPException(status_code=409, detail="Audit is still running")
    return session.report


@router.post("/audits/{session_id}/rerun")
async def rerun_audit(session_id: str) -> dict:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    raise HTTPException(
        status_code=409,
        detail="Re-running requires the original upload payload; start a new audit instead.",
    )


@router.get("/config")
async def get_config() -> dict:
    """Expose non-secret runtime configuration for the UI."""
    return {
        "provider": gemma_client.provider,
        "model": gemma_client.model,
        "thinking_level": gemma_client.thinking_level,
        "ai_available": gemma_client.available,
        "specs": [
            "OWASP Top 10 (2021)",
            "CWE Top 25",
            "CVSS v3.1 base scoring",
        ],
    }
