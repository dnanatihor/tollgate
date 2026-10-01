"""Webhook signatures must match before a job is queued."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

from tollgate.server.app import create_app, jobs
from tollgate.server.signatures import verify_bitbucket, verify_github


def _drain() -> None:
    while not jobs.empty():
        jobs.get_nowait()


def _sign(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_github_and_bitbucket_signatures() -> None:
    body = b'{"action":"opened"}'
    assert verify_github(body, _sign(body, "gh"), "gh")
    assert not verify_github(body, _sign(body, "other"), "gh")
    assert not verify_github(body, None, "gh")
    assert verify_bitbucket(body, _sign(body, "bb"), "bb")
    assert not verify_bitbucket(body, "sha256=00", "bb")


def test_bad_signature_is_not_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    _drain()
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh")
    client = TestClient(create_app())
    response = client.post(
        "/github/webhook",
        content=b"{}",
        headers={"X-Hub-Signature-256": "sha256=00"},
    )
    assert response.status_code == 401
    assert jobs.empty()


def test_valid_signature_is_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    _drain()
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh")
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb")
    client = TestClient(create_app())
    body = b'{"action":"opened"}'
    github = client.post(
        "/github/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body, "gh")},
    )
    bitbucket = client.post(
        "/bitbucket/webhook",
        content=body,
        headers={"X-Hub-Signature": _sign(body, "bb")},
    )
    assert github.status_code == 200
    assert bitbucket.status_code == 200
    assert jobs.get_nowait()["platform"] == "github"
    assert jobs.get_nowait()["platform"] == "bitbucket"
