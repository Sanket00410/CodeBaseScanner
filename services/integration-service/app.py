from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="CodeSentinel X - Integration Service", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/integrations")
def list_integrations() -> dict:
    return {
        "integrations": [
            "github",
            "gitlab",
            "jira",
            "splunk",
            "sentinel",
        ]
    }
