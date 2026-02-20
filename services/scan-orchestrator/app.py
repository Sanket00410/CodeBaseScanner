from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CodeSentinel X - Scan Orchestrator", version="0.1.0")


class CreateJobRequest(BaseModel):
    project_path: str
    branch: str | None = None
    commit_sha: str | None = None


class Job(BaseModel):
    job_id: str
    status: str
    created_at: datetime
    project_path: str


JOBS: dict[str, Job] = {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/jobs", response_model=Job)
def create_job(payload: CreateJobRequest) -> Job:
    job = Job(
        job_id=uuid4().hex,
        status="queued",
        created_at=datetime.now(timezone.utc),
        project_path=payload.project_path,
    )
    JOBS[job.job_id] = job
    return job


@app.get("/v1/jobs/{job_id}", response_model=Job)
def get_job(job_id: str) -> Job:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job
