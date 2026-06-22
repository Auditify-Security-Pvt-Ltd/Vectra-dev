from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from discovery.asset_discovery import (
    DISCOVERIES, ASSETS, DISC_TASKS, ACTIVE_STATUSES,
    execute_discovery, make_discovery_id, _now_iso, _now_hms,
)
from models.asset import DiscoveryRequest
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/assets")


# ── Routes ─────────────────────────────────────────────────────────────

@router.post("/discover", status_code=status.HTTP_202_ACCEPTED)
async def start_discovery(req: DiscoveryRequest):
    """Queue a new asset discovery for a domain."""
    discovery_id = make_discovery_id()
    DISCOVERIES[discovery_id] = {
        "discoveryId":    discovery_id,
        "domain":         req.target,
        "status":         "queued",
        "currentStep":    "Queued",
        "subdomainsFound": 0,
        "liveAssets":     0,
        "logs": [
            {"timestamp": _now_hms(), "message": f"Discovery queued for {req.target}"}
        ],
        "createdAt":   _now_iso(),
        "completedAt": None,
        "error":       None,
    }
    ASSETS[discovery_id] = []

    task = asyncio.create_task(execute_discovery(discovery_id, req.target))
    DISC_TASKS[discovery_id] = task

    logger.info(f"Discovery {discovery_id} queued for {req.target}")
    return {"discoveryId": discovery_id, "status": "queued", "domain": req.target}


@router.get("/discovery/{discovery_id}")
async def get_discovery(discovery_id: str):
    """Get full discovery state including all assets found so far."""
    disc = DISCOVERIES.get(discovery_id)
    if disc is None:
        raise HTTPException(status_code=404, detail="Discovery not found")
    return {**disc, "assets": ASSETS.get(discovery_id, [])}


@router.get("/discovery/{discovery_id}/stream")
async def stream_discovery(discovery_id: str):
    """SSE endpoint — sends full discovery snapshot every 500ms until terminal."""
    if discovery_id not in DISCOVERIES:
        raise HTTPException(status_code=404, detail="Discovery not found")

    async def event_stream():
        while True:
            disc = DISCOVERIES.get(discovery_id)
            if disc is None:
                return
            payload = json.dumps({**disc, "assets": ASSETS.get(discovery_id, [])})
            yield f"data: {payload}\n\n"
            if disc["status"] not in ACTIVE_STATUSES:
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/discovery/{discovery_id}/cancel")
async def cancel_discovery(discovery_id: str):
    """Cancel a running discovery."""
    disc = DISCOVERIES.get(discovery_id)
    if disc is None:
        raise HTTPException(status_code=404, detail="Discovery not found")
    task = DISC_TASKS.get(discovery_id)
    if task and not task.done():
        task.cancel()
    disc["status"] = "cancelled"
    disc["currentStep"] = "Cancelled"
    return {"discoveryId": discovery_id, "status": "cancelled"}


@router.get("/discoveries")
async def list_discoveries():
    """All discovery summaries (no assets payload)."""
    return {"discoveries": list(DISCOVERIES.values()), "total": len(DISCOVERIES)}


@router.get("/")
async def list_assets():
    """All discovered assets across all discoveries."""
    all_assets = [a for assets in ASSETS.values() for a in assets]
    return {"assets": all_assets, "total": len(all_assets)}


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str):
    """Delete an asset by ID."""
    for disc_id, assets in ASSETS.items():
        for i, a in enumerate(assets):
            if a["assetId"] == asset_id:
                ASSETS[disc_id].pop(i)
                return {"deleted": asset_id}
    raise HTTPException(status_code=404, detail="Asset not found")
