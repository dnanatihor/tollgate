"""Mocked Data Center anchors include lineType, and summary updates send version."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from tollgate.models import Finding, Verdict
from tollgate.scm.bitbucket_dc import BitbucketDataCenterProvider, line_type_for
from tollgate.verify import fingerprint


def _finding() -> Finding:
    evidence = 'query = "SELECT" + order_id'
    return Finding(
        fingerprint=fingerprint("security", "app/orders.py", evidence, "CWE-89"),
        lens="security",
        title="SQL injection",
        severity="high",
        confidence="high",
        file="app/orders.py",
        start_line=4,
        end_line=4,
        evidence=evidence,
        explanation="Concatenated SQL.",
        recommendation="Parameterise the query.",
        standards=("CWE-89",),
        sources=("llm:security",),
        corroborated=False,
        status="active",
    )


@pytest.mark.asyncio
async def test_anchor_line_type_and_summary_version() -> None:
    seen: list[dict[str, object]] = []
    finding = _finding()
    base = "https://bitbucket.example/rest/api/1.0/projects/PAY/repos/billing/pull-requests/9"
    async with httpx.AsyncClient() as client:
        with respx.mock(assert_all_called=False) as router:
            empty = httpx.Response(200, json={"values": []})
            router.get(f"{base}/comments").mock(return_value=empty)
            posted = router.post(f"{base}/comments")
            posted.mock(side_effect=lambda request: _capture(seen, request))
            ok = httpx.Response(200, json={})
            router.put(url__regex=r".*/reports/tollgate$").mock(return_value=ok)
            router.post(url__regex=r".*/build-status/1.0/commits/abc$").mock(
                return_value=httpx.Response(204)
            )
            provider = BitbucketDataCenterProvider(
                client,
                base_url="https://bitbucket.example",
                project="PAY",
                repo="billing",
            )
            await provider.post_inline("9", finding, line_type=line_type_for("+"))
            await provider.post_inline("9", finding, line_type=line_type_for(" "))
            await provider.publish(
                number="9",
                commit="abc",
                findings=(finding,),
                verdict=Verdict(outcome="concerns"),
                markdown="# Tollgate\n",
                config_hash="hash",
                line_types={finding.fingerprint: "ADDED"},
            )
    anchors = [item["anchor"] for item in seen if "anchor" in item]
    added = anchors[0]
    context = anchors[1]
    assert isinstance(added, dict)
    assert isinstance(context, dict)
    assert added["lineType"] == "ADDED"
    assert context["lineType"] == "CONTEXT"
    assert added["fileType"] == "TO"
    assert added["diffType"] == "EFFECTIVE"
    assert line_type_for("+") == "ADDED"
    assert line_type_for(" ") == "CONTEXT"


@pytest.mark.asyncio
async def test_summary_update_sends_version() -> None:
    seen: list[dict[str, object]] = []
    comment = {
        "id": 3,
        "version": 4,
        "text": "<!-- tollgate:summary -->\nprevious",
    }
    base = "https://bitbucket.example/rest/api/1.0/projects/PAY/repos/billing/pull-requests/9"
    async with httpx.AsyncClient() as client:
        with respx.mock(assert_all_called=False) as router:
            router.get(f"{base}/comments").mock(
                return_value=httpx.Response(200, json={"values": [comment]})
            )
            route = router.put(f"{base}/comments/3")
            route.mock(side_effect=lambda request: _capture(seen, request))
            provider = BitbucketDataCenterProvider(
                client,
                base_url="https://bitbucket.example",
                project="PAY",
                repo="billing",
            )
            await provider.upsert_summary("9", "<!-- tollgate:summary -->\nnext")
    assert seen[0]["version"] == 4


def _capture(seen: list[dict[str, object]], request: httpx.Request) -> httpx.Response:
    payload = json.loads(request.content)
    seen.append(payload)
    body = {"id": len(seen), "version": 0, "text": payload.get("text", "")}
    return httpx.Response(201, json=body)
