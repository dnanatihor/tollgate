"""FastAPI webhooks. Signature checks happen before a job is queued."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from tollgate.server.signatures import verify_bitbucket, verify_github

jobs: asyncio.Queue[dict[str, Any]] = asyncio.Queue()


def create_app() -> FastAPI:
    app = FastAPI(title="Tollgate")

    @app.post("/github/webhook")
    async def github_webhook(request: Request) -> dict[str, bool]:
        body = await request.body()
        secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
        header = request.headers.get("x-hub-signature-256")
        if not verify_github(body, header, secret):
            raise HTTPException(status_code=401, detail="invalid signature")
        await jobs.put({"platform": "github", "body": body})
        return {"queued": True}

    @app.post("/bitbucket/webhook")
    async def bitbucket_webhook(request: Request) -> dict[str, bool]:
        body = await request.body()
        secret = os.environ.get("BITBUCKET_WEBHOOK_SECRET", "")
        header = request.headers.get("x-hub-signature")
        if not verify_bitbucket(body, header, secret):
            raise HTTPException(status_code=401, detail="invalid signature")
        await jobs.put({"platform": "bitbucket", "body": body})
        return {"queued": True}

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
