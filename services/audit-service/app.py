from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="CodeSentinel X - Audit Service", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/audit/events")
def list_audit_events(limit: int = 100) -> dict:
    return {
        "limit": limit,
        "events": [],
    }
