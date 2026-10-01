"""Mocked Bitbucket Cloud comments, summary upsert, and Code Insights batches."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from tollgate.models import Finding, Verdict
from tollgate.scm.bitbucket_cloud import ANNOTATION_BATCH, BitbucketCloudProvider
from tollgate.scm.state import SUMMARY_MARKER
from tollgate.verify import fingerprint


def _finding(index: int) -> Finding:
    evidence = f"query = {index}"
    return Finding(
        fingerprint=fingerprint("security", "app/orders.py", evidence, "CWE-89"),
        lens="security",
        title="SQL injection",
        severity="high",
        confidence="high",
        file="app/orders.py",
        start_line=2,
        end_line=2,
        evidence=evidence,
        explanation="Concatenated SQL.",
        recommendation="Parameterise the query.",
        standards=("CWE-89",),
        sources=("llm:security",),
        corroborated=False,
        status="active",
    )


@pytest.mark.asyncio
async def test_summary_inline_and_annotation_batches() -> None:
    stored: list[dict[str, object]] = []
    annotations: list[list[object]] = []
    verdict = Verdict(outcome="block")
    findings = tuple(_finding(index) for index in range(ANNOTATION_BATCH + 1))
    base = "https://api.bitbucket.org/2.0/repositories/acme/billing"
    async with httpx.AsyncClient() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(f"{base}/pullrequests/7/comments").mock(
                side_effect=lambda request: httpx.Response(200, json={"values": list(stored)})
            )
            router.post(f"{base}/pullrequests/7/comments").mock(
                side_effect=lambda request: _save(stored, request)
            )
            router.put(url__regex=r".*/pullrequests/7/comments/\d+$").mock(
                return_value=httpx.Response(200, json={})
            )
            router.put(url__startswith=f"{base}/commit/").mock(
                return_value=httpx.Response(200, json={})
            )
            router.post(url__startswith=f"{base}/commit/").mock(
                side_effect=lambda request: _save_annotations(annotations, request)
            )
            provider = BitbucketCloudProvider(client, workspace="acme", repo="billing")
            first = await provider.publish(
                number="7",
                commit="abc",
                findings=(_finding(0),),
                verdict=verdict,
                markdown="# Tollgate\n",
                config_hash="hash",
            )
            second = await provider.publish(
                number="7",
                commit="abc",
                findings=(_finding(0),),
                verdict=verdict,
                markdown="# Tollgate\n",
                config_hash="hash",
            )
            await provider.publish_report("abc", verdict, findings)
    assert first == 1
    assert second == 0
    summary = stored[0]["content"]
    assert isinstance(summary, dict)
    assert SUMMARY_MARKER in str(summary["raw"])
    assert any(item.get("inline") for item in stored)
    sizes = [len(batch) for batch in annotations]
    assert ANNOTATION_BATCH in sizes
    assert 1 in sizes


def _save(stored: list[dict[str, object]], request: httpx.Request) -> httpx.Response:
    payload = json.loads(request.content)
    stored.append(
        {
            "id": len(stored) + 1,
            "content": {"raw": payload["content"]["raw"]},
            "inline": payload.get("inline"),
        }
    )
    return httpx.Response(201, json=stored[-1])


def _save_annotations(batches: list[list[object]], request: httpx.Request) -> httpx.Response:
    payload = json.loads(request.content)
    assert isinstance(payload, list)
    batches.append(payload)
    return httpx.Response(200, json=[])
