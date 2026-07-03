"""SAST Scan API — upload ZIP or source directory, stream results via SSE."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from scanners.sast_scanner import (
    analyze_owasp,
    collect_dependencies,
    correlate_dependency_cves,
    detect_language,
    scan_secrets,
)
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/sast", tags=["SAST"])

# ── In-memory state ───────────────────────────────────────────────────

_SAST_SCANS: Dict[str, dict] = {}
_SAST_TASKS: Dict[str, asyncio.Task] = {}

_TERMINAL = frozenset({"completed", "failed", "cancelled"})

_MAX_FILES    = 5_000
_MAX_ZIP_MB   = 100

# ── Internal helpers ──────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _blank(scan_id: str, project_name: str, upload_method: str, user_id: str) -> dict:
    return {
        "scanId":           scan_id,
        "projectName":      project_name,
        "uploadMethod":     upload_method,
        "userId":           user_id,
        "language":         "Unknown",
        "status":           "queued",
        "progress":         0,
        "currentStep":      "Queued — waiting to start",
        "totalFiles":       0,
        "scannedFiles":     0,
        "totalFindings":    0,
        "criticalFindings": 0,
        "highFindings":     0,
        "mediumFindings":   0,
        "lowFindings":      0,
        "secretFindings":   0,
        "dependencyVulns":  0,
        "findings":         [],
        "stages": {
            "language_detection": "pending",
            "secret_detection":   "pending",
            "dependency_analysis":"pending",
            "owasp_analysis":     "pending",
            "cwe_mapping":        "pending",
            "cve_correlation":    "pending",
        },
        "duration":     None,
        "error":        None,
        "createdAt":    _now(),
        "completedAt":  None,
    }


def _upd(scan_id: str, **kw) -> None:
    if scan_id in _SAST_SCANS:
        _SAST_SCANS[scan_id].update(kw)


def _stage(scan_id: str, key: str, val: str) -> None:
    if scan_id in _SAST_SCANS:
        _SAST_SCANS[scan_id]["stages"][key] = val


def _count(findings: List[dict]) -> dict:
    c = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0, "deps": 0}
    for f in findings:
        c["total"] += 1
        sev = f.get("severity", "info")
        if sev in c:
            c[sev] += 1
        if f.get("category") == "secret":
            c["secrets"] += 1
        if f.get("category") == "dependency":
            c["deps"] += 1
    return c


def _safe_extract_zip(zip_path: Path, dest: Path) -> None:
    """Extract ZIP with ZipSlip protection."""
    dest_str = str(dest.resolve())
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if not str(target).startswith(dest_str):
                logger.warning(f"[SAST] ZipSlip attempt blocked: {member.filename}")
                continue
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, 'wb') as out:
                    shutil.copyfileobj(src, out)


def _project_root(extract_dir: Path) -> Path:
    """
    If the ZIP had a single top-level directory, return it as the project root.
    Otherwise return extract_dir itself.
    """
    children = [c for c in extract_dir.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return extract_dir


# ── Scanner task ──────────────────────────────────────────────────────

async def _run_sast(scan_id: str, project_root: Path, temp_dir: str) -> None:
    start = time.monotonic()
    try:
        _upd(scan_id, status="running", progress=5, currentStep="Initializing scanner")
        await asyncio.sleep(0.1)

        # Count files
        all_files = [p for p in project_root.rglob('*') if p.is_file()]
        _upd(scan_id, totalFiles=len(all_files))

        # ── Stage 1: Language detection ──────────────────────────────
        _upd(scan_id, progress=10, currentStep="Detecting language and project structure")
        _stage(scan_id, "language_detection", "running")
        await asyncio.sleep(0.05)

        language = await asyncio.get_event_loop().run_in_executor(
            None, detect_language, project_root
        )
        _upd(scan_id, language=language)
        _stage(scan_id, "language_detection", "completed")
        logger.info(f"[SAST:{scan_id}] Language: {language}")

        # ── Stage 2: Secret detection ────────────────────────────────
        _upd(scan_id, progress=25, currentStep="Scanning for hardcoded secrets and credentials")
        _stage(scan_id, "secret_detection", "running")
        await asyncio.sleep(0.05)

        pname = _SAST_SCANS[scan_id]["projectName"]
        secret_findings: List[dict] = await asyncio.get_event_loop().run_in_executor(
            None, scan_secrets, project_root, scan_id, pname
        )
        _stage(scan_id, "secret_detection", "completed")
        logger.info(f"[SAST:{scan_id}] Secrets: {len(secret_findings)} findings")

        # ── Stage 3: Dependency analysis ─────────────────────────────
        _upd(scan_id, progress=42, currentStep="Parsing dependency manifests")
        _stage(scan_id, "dependency_analysis", "running")
        await asyncio.sleep(0.05)

        deps: List[dict] = await asyncio.get_event_loop().run_in_executor(
            None, collect_dependencies, project_root
        )
        _stage(scan_id, "dependency_analysis", "completed")
        logger.info(f"[SAST:{scan_id}] Dependencies: {len(deps)}")

        # ── Stage 4: OWASP static analysis ──────────────────────────
        _upd(scan_id, progress=58, currentStep=f"Running OWASP static analysis ({language})")
        _stage(scan_id, "owasp_analysis", "running")
        await asyncio.sleep(0.05)

        owasp_findings: List[dict] = await asyncio.get_event_loop().run_in_executor(
            None, analyze_owasp, project_root, language, scan_id, pname
        )
        _stage(scan_id, "owasp_analysis", "completed")
        logger.info(f"[SAST:{scan_id}] OWASP: {len(owasp_findings)} findings")

        # CWE mapping is applied inline during finding creation
        _stage(scan_id, "cwe_mapping", "completed")

        # ── Stage 5: CVE correlation ─────────────────────────────────
        _upd(scan_id, progress=78, currentStep="Correlating dependencies with CVE database")
        _stage(scan_id, "cve_correlation", "running")

        dep_findings: List[dict] = await correlate_dependency_cves(deps, scan_id, pname)
        _stage(scan_id, "cve_correlation", "completed")
        logger.info(f"[SAST:{scan_id}] CVEs: {len(dep_findings)} findings")

        # ── Finalize ─────────────────────────────────────────────────
        all_findings = secret_findings + owasp_findings + dep_findings
        c = _count(all_findings)
        elapsed = time.monotonic() - start
        mins, secs = divmod(int(elapsed), 60)
        dur = f"{mins}m {secs}s" if mins else f"{secs}s"

        _upd(
            scan_id,
            status="completed",
            progress=100,
            currentStep="Scan complete",
            findings=all_findings,
            totalFindings=c["total"],
            criticalFindings=c["critical"],
            highFindings=c["high"],
            mediumFindings=c["medium"],
            lowFindings=c["low"],
            secretFindings=c["secrets"],
            dependencyVulns=c["deps"],
            duration=dur,
            completedAt=_now(),
        )
        logger.info(f"[SAST:{scan_id}] Done in {dur} — {c['total']} findings")

    except asyncio.CancelledError:
        _upd(scan_id, status="cancelled", currentStep="Scan cancelled", completedAt=_now())
        logger.info(f"[SAST:{scan_id}] Cancelled")
        raise

    except Exception as exc:
        logger.error(f"[SAST:{scan_id}] Error: {exc}", exc_info=True)
        _upd(scan_id, status="failed", error=str(exc),
             currentStep="Scan failed", completedAt=_now())

    finally:
        _SAST_TASKS.pop(scan_id, None)
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.debug(f"[SAST:{scan_id}] Temp dir removed: {temp_dir}")


# ── Endpoints ─────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_sast_scan(
    projectName:  str           = Form(...),
    userId:       str           = Form(...),
    uploadMethod: str           = Form(...),   # 'zip' | 'directory'
    file:         Optional[UploadFile] = File(None),
    files:        List[UploadFile]     = File(default=[]),
) -> dict:
    """
    Accept a ZIP archive or a list of source files (directory upload).
    Returns {scanId, status} immediately; use /sast/scan/{scanId}/stream for progress.
    """
    scan_id  = str(uuid.uuid4())
    temp_dir = tempfile.mkdtemp(prefix=f"sast_{scan_id}_")

    try:
        if uploadMethod == 'zip':
            if file is None:
                raise HTTPException(status_code=400, detail="file is required for zip upload")

            content = await file.read()
            if len(content) > _MAX_ZIP_MB * 1024 * 1024:
                raise HTTPException(status_code=413, detail=f"ZIP file exceeds {_MAX_ZIP_MB} MB limit")

            zip_path = Path(temp_dir) / "upload.zip"
            zip_path.write_bytes(content)

            extract_dir = Path(temp_dir) / "extracted"
            extract_dir.mkdir()
            _safe_extract_zip(zip_path, extract_dir)
            zip_path.unlink()

            project_root = _project_root(extract_dir)

        elif uploadMethod == 'directory':
            if not files:
                raise HTTPException(status_code=400, detail="files list is empty for directory upload")
            if len(files) > _MAX_FILES:
                raise HTTPException(status_code=400, detail=f"Directory upload exceeds {_MAX_FILES} file limit")

            project_root = Path(temp_dir) / "project"
            project_root.mkdir()

            for f in files:
                filename = f.filename or f.filename or "unknown"
                # Strip top-level directory component (browser sets webkitRelativePath)
                parts = Path(filename).parts
                if len(parts) > 1:
                    rel = Path(*parts[1:])
                else:
                    rel = Path(parts[0]) if parts else Path("unknown")

                # ZipSlip-style protection
                dest = (project_root / rel).resolve()
                if not str(dest).startswith(str(project_root.resolve())):
                    logger.warning(f"[SAST] Path traversal blocked: {filename}")
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(await f.read())

        else:
            raise HTTPException(status_code=400, detail=f"Unknown uploadMethod: {uploadMethod}")

    except HTTPException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except zipfile.BadZipFile:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive")
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.error(f"[SAST] Upload failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process uploaded files")

    _SAST_SCANS[scan_id] = _blank(scan_id, projectName, uploadMethod, userId)
    task = asyncio.create_task(_run_sast(scan_id, project_root, temp_dir))
    _SAST_TASKS[scan_id] = task

    logger.info(f"[SAST] Scan {scan_id} started for project '{projectName}' (method={uploadMethod})")
    return {"scanId": scan_id, "status": "queued"}


@router.get("/scan/{scan_id}/stream")
async def stream_sast_scan(scan_id: str) -> StreamingResponse:
    """Server-Sent Events stream for live scan progress."""
    if scan_id not in _SAST_SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        while True:
            scan = _SAST_SCANS.get(scan_id)
            if scan is None:
                break

            payload = {
                "scanId":           scan["scanId"],
                "projectName":      scan["projectName"],
                "language":         scan["language"],
                "status":           scan["status"],
                "progress":         scan["progress"],
                "currentStep":      scan["currentStep"],
                "totalFiles":       scan["totalFiles"],
                "totalFindings":    scan["totalFindings"],
                "criticalFindings": scan["criticalFindings"],
                "highFindings":     scan["highFindings"],
                "mediumFindings":   scan["mediumFindings"],
                "lowFindings":      scan["lowFindings"],
                "secretFindings":   scan["secretFindings"],
                "dependencyVulns":  scan["dependencyVulns"],
                "stages":           scan["stages"],
                "findings":         scan["findings"],
                "duration":         scan["duration"],
                "error":            scan["error"],
                "done":             False,
            }
            yield f"data: {json.dumps(payload)}\n\n"

            if scan["status"] in _TERMINAL:
                final = {**payload, "done": True}
                yield f"data: {json.dumps(final)}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/scans")
async def list_sast_scans(userId: str = "") -> dict:
    """List all SAST scans, optionally filtered by userId."""
    scans = [
        {k: v for k, v in s.items() if k != "findings"}  # exclude large findings array
        for s in _SAST_SCANS.values()
        if not userId or s.get("userId") == userId
    ]
    scans.sort(key=lambda s: s.get("createdAt", ""), reverse=True)
    return {"scans": scans, "total": len(scans)}


@router.get("/scan/{scan_id}")
async def get_sast_scan(scan_id: str) -> dict:
    """Get current state of a scan (without findings array for performance)."""
    scan = _SAST_SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {k: v for k, v in scan.items() if k != "findings"}


@router.post("/scan/{scan_id}/cancel")
async def cancel_sast_scan(scan_id: str) -> dict:
    """Cancel a running or queued scan."""
    scan = _SAST_SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] in _TERMINAL:
        return {"success": False, "reason": f"Scan is already {scan['status']}"}

    task = _SAST_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
        return {"success": True, "scanId": scan_id, "status": "cancelled"}

    _upd(scan_id, status="cancelled", currentStep="Scan cancelled", completedAt=_now())
    return {"success": True, "scanId": scan_id, "status": "cancelled"}


@router.delete("/scan/{scan_id}")
async def delete_sast_scan(scan_id: str) -> dict:
    """Delete a scan from in-memory state."""
    if scan_id not in _SAST_SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    task = _SAST_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()

    _SAST_SCANS.pop(scan_id, None)
    _SAST_TASKS.pop(scan_id, None)
    return {"success": True, "scanId": scan_id}


# ── Repository scan (GitHub / GitLab via OAuth) ───────────────────────

class RepoScanRequest(BaseModel):
    userId:      str
    provider:    str   # 'github' | 'gitlab'
    owner:       str
    repo:        str
    branch:      str
    projectName: str


@router.post("/scan/repo")
async def start_repo_scan(body: RepoScanRequest) -> dict:
    """
    Download a GitHub/GitLab repository (using stored OAuth token) and run
    the SAST pipeline on it.  The cloned files are deleted after the scan.
    """
    # Import here to avoid circular dependency at module load time
    from api.sast_oauth import get_oauth_token, download_repo_zip, get_repo_commit

    if body.provider not in ("github", "gitlab"):
        raise HTTPException(400, f"Unknown provider: {body.provider}")

    token = get_oauth_token(body.provider, body.userId)
    if not token:
        raise HTTPException(401, f"Not connected to {body.provider}. Please reconnect your account.")

    scan_id  = str(uuid.uuid4())
    temp_dir = tempfile.mkdtemp(prefix=f"sast_{scan_id}_")

    try:
        # Resolve branch (use default if empty string passed)
        branch = body.branch.strip() or "main"

        # Fetch commit metadata
        commit = await get_repo_commit(body.provider, token, body.owner, body.repo, branch)

        # Download repo archive
        logger.info(f"[SAST:{scan_id}] Downloading {body.provider}/{body.owner}/{body.repo}@{branch}")
        zip_bytes = await download_repo_zip(body.provider, token, body.owner, body.repo, branch)
        if len(zip_bytes) > _MAX_ZIP_MB * 1024 * 1024:
            raise HTTPException(413, f"Repository exceeds {_MAX_ZIP_MB} MB size limit")

        zip_path = Path(temp_dir) / "repo.zip"
        zip_path.write_bytes(zip_bytes)

        extract_dir = Path(temp_dir) / "extracted"
        extract_dir.mkdir()
        _safe_extract_zip(zip_path, extract_dir)
        zip_path.unlink()

        project_root = _project_root(extract_dir)

    except HTTPException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except RuntimeError as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(400, str(exc))
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.error(f"[SAST:{scan_id}] Repo download failed: {exc}", exc_info=True)
        raise HTTPException(500, "Failed to download repository")

    # Build scan record with repo metadata
    scan_record = _blank(scan_id, body.projectName, body.provider, body.userId)
    scan_record.update({
        "repoProvider":    body.provider,
        "repoOwner":       body.owner,
        "repoName":        body.repo,
        "repoBranch":      branch,
        "repoCommitSha":   commit.get("sha", ""),
        "repoCommitAuthor": commit.get("author", ""),
        "repoCommitDate":  commit.get("date", ""),
        "repoCommitMessage": commit.get("message", ""),
    })
    _SAST_SCANS[scan_id] = scan_record

    task = asyncio.create_task(_run_sast(scan_id, project_root, temp_dir))
    _SAST_TASKS[scan_id] = task

    logger.info(
        f"[SAST] Repo scan {scan_id} started for "
        f"{body.provider}/{body.owner}/{body.repo}@{branch}"
    )
    return {"scanId": scan_id, "status": "queued"}
