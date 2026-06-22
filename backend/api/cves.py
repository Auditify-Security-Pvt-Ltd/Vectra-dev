from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from intelligence.cve_correlator import (
    CORRELATIONS, CVE_RESULTS, CORR_TASKS, ACTIVE_STATUSES,
    execute_correlation, make_correlation_id, _now_iso,
)
from models.cve import CorrelationRequest
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/cves")


# ── Routes ────────────────────────────────────────────────────────────

@router.post("/correlate", status_code=status.HTTP_202_ACCEPTED)
async def start_correlation(req: CorrelationRequest) -> dict:
    """Start a CVE correlation run for an asset's detected technologies."""
    corr_id = make_correlation_id()

    CORRELATIONS[corr_id] = {
        "correlationId": corr_id,
        "assetId":       req.assetId,
        "assetUrl":      req.assetUrl,
        "discoveryId":   req.discoveryId,
        "technologies":  req.technologies,
        "status":        "running",
        "currentStep":   "Starting",
        "totalFound":    0,
        "logs":          [],
        "createdAt":     _now_iso(),
        "completedAt":   None,
        "error":         None,
    }
    CVE_RESULTS[corr_id] = []

    task = asyncio.create_task(
        execute_correlation(
            corr_id,
            req.assetId,
            req.assetUrl,
            req.technologies,
            req.discoveryId,
        )
    )
    CORR_TASKS[corr_id] = task

    logger.info(f"[{corr_id}] CVE correlation started for asset {req.assetId}")
    return {"correlationId": corr_id, "status": "running"}


@router.get("/correlation/{corr_id}")
async def get_correlation(corr_id: str) -> dict:
    corr = CORRELATIONS.get(corr_id)
    if corr is None:
        raise HTTPException(status_code=404, detail="Correlation not found")
    return {**corr, "cves": CVE_RESULTS.get(corr_id, [])}


@router.get("/correlation/{corr_id}/stream")
async def stream_correlation(corr_id: str) -> StreamingResponse:
    """
    SSE stream — sends full snapshot every 500ms until terminal status.
    Each event payload contains:
      { status, currentStep, totalFound, cves: [...all CVEs so far...], logs, done? }
    """
    if corr_id not in CORRELATIONS:
        raise HTTPException(status_code=404, detail="Correlation not found")

    async def event_stream():
        last_cve_count = 0
        try:
            while True:
                corr = CORRELATIONS.get(corr_id)
                if corr is None:
                    return

                cves = CVE_RESULTS.get(corr_id, [])
                is_terminal = corr["status"] not in ACTIVE_STATUSES

                payload = json.dumps({
                    "status":      corr["status"],
                    "currentStep": corr["currentStep"],
                    "totalFound":  corr["totalFound"],
                    "cves":        cves,
                    "logs":        corr["logs"],
                    "error":       corr.get("error"),
                    "done":        is_terminal,
                })
                yield f"data: {payload}\n\n"
                last_cve_count = len(cves)

                if is_terminal:
                    return

                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/")
async def list_all_cves() -> dict:
    """All CVEs across all correlation runs."""
    all_cves = [c for cves in CVE_RESULTS.values() for c in cves]
    return {"cves": all_cves, "total": len(all_cves)}


@router.get("/{cve_doc_id}")
async def get_cve(cve_doc_id: str) -> dict:
    for cves in CVE_RESULTS.values():
        for c in cves:
            if c["id"] == cve_doc_id:
                return c
    raise HTTPException(status_code=404, detail="CVE not found")


@router.delete("/{cve_doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cve(cve_doc_id: str) -> None:
    for corr_id, cves in CVE_RESULTS.items():
        for i, c in enumerate(cves):
            if c["id"] == cve_doc_id:
                CVE_RESULTS[corr_id].pop(i)
                return
    raise HTTPException(status_code=404, detail="CVE not found")


@router.get("/correlations/list")
async def list_correlations() -> dict:
    return {
        "correlations": list(CORRELATIONS.values()),
        "total": len(CORRELATIONS),
    }
