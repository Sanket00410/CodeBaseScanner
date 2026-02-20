from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CodeSentinel X - Finding Service", version="0.1.0")


class Finding(BaseModel):
    finding_id: str
    project_id: str
    severity: str
    title: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/findings")
def list_findings(project_id: str | None = None, severity: str | None = None) -> dict:
    return {
        "items": [],
        "filters": {"project_id": project_id, "severity": severity},
    }
