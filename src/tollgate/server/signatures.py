"""Webhook HMAC checks. The raw body is signed; a parsed JSON object is not."""

from __future__ import annotations

import hashlib
import hmac


def verify_sha256(body: bytes, header: str | None, secret: str) -> bool:
    """Accept ``sha256=<hex hmac>`` and reject a missing or mismatched header."""
    if not header or not secret:
        return False
    scheme, _, digest = header.partition("=")
    if scheme != "sha256" or not digest:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, digest)


def verify_github(body: bytes, header: str | None, secret: str) -> bool:
    return verify_sha256(body, header, secret)


def verify_bitbucket(body: bytes, header: str | None, secret: str) -> bool:
    return verify_sha256(body, header, secret)
