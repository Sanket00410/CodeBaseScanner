from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.logging_config import configure_logging
from codesentinelx_engine.models import ScanStatusResponse, StartScanRequest, StartScanResponse
from codesentinelx_engine.scanner.engine import ScanEngine
from codesentinelx_engine.scanner.reporting.exporters import ReportExporter
from codesentinelx_engine.scanner.reporting.report_builder import build_report


@dataclass(slots=True)
class ScanJob:
    scan_id: str
    target_path: str
    status: str = "queued"
    stage: str = "queued"
    progress_percent: float = 0.0
    current_file: str | None = None
    message: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    findings_count: int = 0
    report: dict | None = None
    professional_html: str | None = None
    errors: list[str] = field(default_factory=list)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = Path(__file__).resolve().parent

CONFIG = ScannerConfig.from_env()
if not CONFIG.export_dir.is_absolute():
    CONFIG.export_dir = (PROJECT_ROOT / CONFIG.export_dir).resolve()
if not CONFIG.tools_dir.is_absolute():
    CONFIG.tools_dir = (PROJECT_ROOT / CONFIG.tools_dir).resolve()

configure_logging(CONFIG.log_level)
ENGINE = ScanEngine(CONFIG)
EXPORTER = ReportExporter(CONFIG.export_dir)

app = FastAPI(title="CodeSentinelX", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=[],
)
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

SCAN_JOBS: dict[str, ScanJob] = {}
SCAN_LOCK = threading.Lock()


def _get_scan_job(scan_id: str) -> ScanJob:
    with SCAN_LOCK:
        job = SCAN_JOBS.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


def _update_job(scan_id: str, **updates: object) -> None:
    with SCAN_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return
        for key, value in updates.items():
            setattr(job, key, value)


def _run_scan(scan_id: str) -> None:
    job = _get_scan_job(scan_id)

    def progress_callback(progress: float, stage: str, current_file: str | None, message: str | None) -> None:
        _update_job(
            scan_id,
            status="running",
            stage=stage,
            progress_percent=progress,
            current_file=current_file,
            message=message,
        )

    try:
        result = ENGINE.scan(job.target_path, progress_callback=progress_callback)
        from codesentinelx_engine.scanner.reporting.report_schema import ReportSchemaConverter
        from codesentinelx_engine.scanner.reporting.developer_report_renderer import DeveloperReportRenderer
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        from codesentinelx_engine.scanner.reporting.exporters import ReportExporter

        scan_meta = ScanMetadata(
            scan_id=result.target_path,
            scanner_version="2.0.0",
            target_path=result.target_path,
            files_scanned=result.files_scanned,
            duration_seconds=result.duration_seconds,
            started_at=result.started_at.isoformat() if result.started_at else "",
            completed_at=result.completed_at.isoformat() if result.completed_at else "",
            scan_environment="local",
            tools_used=list(result.toolchain_status.keys()) if result.toolchain_status else [],
            errors=result.errors,
        )
        converter = ReportSchemaConverter()
        dev_report = converter.build_developer_report(
            result.findings, result.target_path,
            project_name=job.target_path.rstrip("/\\").split("/")[-1].split("\\")[-1] or "CodeSentinelX Scan",
            scan_metadata=scan_meta,
        )
        renderer = DeveloperReportRenderer()
        professional_html = renderer.render_html(dev_report)
        report = build_report(result)
        _update_job(
            scan_id,
            status="completed",
            stage="completed",
            progress_percent=100.0,
            current_file=None,
            message="Scan completed",
            completed_at=datetime.now(timezone.utc),
            findings_count=len(result.findings),
            report=report,
            professional_html=professional_html,
            errors=result.errors,
        )
    except Exception as exc:  # pragma: no cover - operational safety branch
        _update_job(
            scan_id,
            status="failed",
            stage="failed",
            message=str(exc),
            completed_at=datetime.now(timezone.utc),
        )


@app.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"app_name": "CodeSentinel X"},
    )


@app.post("/api/scans", response_model=StartScanResponse)
def start_scan(payload: StartScanRequest) -> StartScanResponse:
    target = Path(payload.target_path).expanduser()
    if not target.exists() or (not target.is_dir() and not target.is_file()):
        raise HTTPException(status_code=400, detail="Provided path does not exist or is not a file or directory")

    scan_id = uuid.uuid4().hex
    job = ScanJob(scan_id=scan_id, target_path=str(target.resolve()))

    with SCAN_LOCK:
        SCAN_JOBS[scan_id] = job

    thread = threading.Thread(target=_run_scan, args=(scan_id,), daemon=True)
    thread.start()

    return StartScanResponse(scan_id=scan_id, status="queued")


@app.get("/api/scans/{scan_id}", response_model=ScanStatusResponse)
def scan_status(scan_id: str) -> ScanStatusResponse:
    job = _get_scan_job(scan_id)
    return ScanStatusResponse(
        scan_id=job.scan_id,
        status=job.status,
        stage=job.stage,
        progress_percent=job.progress_percent,
        current_file=job.current_file,
        message=job.message,
        completed_at=job.completed_at,
        findings_count=job.findings_count,
    )


@app.get("/api/scans/{scan_id}/results")
def scan_results(scan_id: str) -> dict:
    job = _get_scan_job(scan_id)
    if job.status != "completed" or job.report is None:
        raise HTTPException(status_code=409, detail="Scan is not complete yet")
    return job.report


@app.get("/api/scans/{scan_id}/professional-report", response_class=HTMLResponse)
def professional_report(scan_id: str) -> HTMLResponse:
    job = _get_scan_job(scan_id)
    if job.status != "completed":
        raise HTTPException(status_code=409, detail="Scan is not complete yet")
    if job.professional_html is None:
        raise HTTPException(status_code=404, detail="Professional report not available")
    return HTMLResponse(content=job.professional_html)


@app.get("/api/scans/{scan_id}/export")
def export_report(
    scan_id: str,
    fmt: str = Query(..., pattern="^(json|html|pdf|sarif)$"),
    report_type: str = Query("combined", pattern="^(combined|existing|vulnerability|fixes)$"),
) -> FileResponse:
    job = _get_scan_job(scan_id)
    if job.status != "completed" or job.report is None:
        raise HTTPException(status_code=409, detail="Scan is not complete yet")

    if fmt.lower() == "sarif" and report_type.lower() in {"existing", "fixes"}:
        raise HTTPException(status_code=400, detail="SARIF is available only for vulnerability or combined reports")

    suffix = "" if report_type.lower() == "combined" else f"_{report_type.lower()}"
    filename = f"security_report_{scan_id}{suffix}.{fmt.lower()}"
    output_path = CONFIG.export_dir / filename
    exported = EXPORTER.export(job.report, fmt.lower(), output_path, report_type=report_type.lower())

    media_types = {
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
        "sarif": "application/sarif+json",
    }
    return FileResponse(path=exported, filename=exported.name, media_type=media_types[fmt.lower()])


