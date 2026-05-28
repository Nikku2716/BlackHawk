"""
Z-Scanner API — FastAPI application serving the scanning endpoints and static frontend.
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

from scanner import ScanPhase, ScanStatus, ZapScanner

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("zscanner.api")

# ---------------------------------------------------------------------------
# In-memory scan store
# ---------------------------------------------------------------------------
scans: dict[str, ScanStatus] = {}

# ---------------------------------------------------------------------------
# ZAP scanner instance
# ---------------------------------------------------------------------------
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080")
scanner = ZapScanner(zap_base_url=ZAP_API_URL)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Z-Scanner API starting — ZAP endpoint: %s", ZAP_API_URL)
    yield
    logger.info("Z-Scanner API shutting down")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Z-Scanner API",
    version="1.0.0",
    description="Web Application Security Scanner powered by OWASP ZAP",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_mode: str = "fast"  # quick | fast | deep | stealth


class ScanResponse(BaseModel):
    scan_id: str
    message: str


class StatusResponse(BaseModel):
    scan_id: str
    target_url: str
    phase: str
    spider_progress: int
    active_scan_progress: int
    error: str | None = None


class AlertItem(BaseModel):
    id: str
    name: str
    risk: str
    confidence: str
    description: str
    url: str
    solution: str
    reference: str
    cweid: str
    wascid: str
    param: str
    evidence: str


class ResultsResponse(BaseModel):
    scan_id: str
    target_url: str
    phase: str
    total_alerts: int
    summary: dict[str, int]
    alerts: list[AlertItem]


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------
async def _run_scan(scan_id: str) -> None:
    """Background worker that drives the scanner."""
    status = scans.get(scan_id)
    if status is None:
        return
    await scanner.run_full_scan(status)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "Z-Scanner API"}


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    scan_id = uuid.uuid4().hex[:12]
    target = str(request.target_url)
    scan_mode = request.scan_mode if request.scan_mode in ("quick", "fast", "deep", "stealth") else "fast"

    # Prevent duplicate concurrent scans against the same target
    for existing in scans.values():
        if (
            existing.target_url == target
            and existing.phase not in (ScanPhase.COMPLETE, ScanPhase.ERROR)
        ):
            raise HTTPException(
                status_code=409,
                detail=f"A scan for {target} is already running (scan_id={existing.scan_id})",
            )

    status = ScanStatus(scan_id=scan_id, target_url=target, scan_mode=scan_mode)
    logger.info("Scan mode selected: %s", scan_mode)
    scans[scan_id] = status

    background_tasks.add_task(_run_scan, scan_id)
    logger.info("Scan queued: %s → %s", scan_id, target)

    return ScanResponse(scan_id=scan_id, message="Scan started successfully")


@app.get("/api/status/{scan_id}", response_model=StatusResponse)
async def get_status(scan_id: str) -> StatusResponse:
    status = scans.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return StatusResponse(
        scan_id=status.scan_id,
        target_url=status.target_url,
        phase=status.phase.value,
        spider_progress=status.spider_progress,
        active_scan_progress=status.active_scan_progress,
        error=status.error,
    )


@app.post("/api/stop/{scan_id}")
async def stop_scan(scan_id: str) -> dict[str, str]:
    status = scans.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if status.phase in (ScanPhase.COMPLETE, ScanPhase.ERROR, ScanPhase.STOPPED):
        raise HTTPException(status_code=400, detail="Scan is not running")

    await scanner.force_stop(status)
    logger.info("Force stop executed for scan %s", scan_id)
    return {"scan_id": scan_id, "message": "Scan stopped"}


@app.get("/api/results/{scan_id}", response_model=ResultsResponse)
async def get_results(scan_id: str) -> ResultsResponse:
    status = scans.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    summary: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
    for alert in status.alerts:
        risk = alert.get("risk", "")
        if risk in summary:
            summary[risk] += 1

    return ResultsResponse(
        scan_id=status.scan_id,
        target_url=status.target_url,
        phase=status.phase.value,
        total_alerts=len(status.alerts),
        summary=summary,
        alerts=[AlertItem(**a) for a in status.alerts],
    )


# ---------------------------------------------------------------------------
# Serve frontend static files
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if not os.path.isdir(FRONTEND_DIR):
    FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")


@app.get("/")
async def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(index_path, media_type="text/html")


# Mount static assets (CSS, JS) — must come after explicit routes
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR), name="frontend")
