from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="CodeSentinel X - Report Service", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/reports/{scan_id}")
def generate_report(scan_id: str, format: str = "pdf") -> dict:
    return {
        "scan_id": scan_id,
        "format": format,
        "status": "queued",
    }
