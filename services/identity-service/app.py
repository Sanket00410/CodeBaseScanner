from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="CodeSentinel X - Identity Service", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/sso/providers")
def list_sso_providers() -> dict:
    return {
        "providers": [
            "saml",
            "oauth2",
            "oidc",
        ]
    }
