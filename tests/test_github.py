"""Mocked GitHub publishing: batch review, fallback, forks, and state."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from tollgate.config import TollgateConfig
from tollgate.models import Finding, Verdict
from tollgate.render.sarif import validate_sarif
from tollgate.scm.github import GitHubProvider, checkout_mode, is_fork_event
from tollgate.scm.state import decode_state, files_for_incremental
from tollgate.scm.types import neutralize
from tollgate.verify import fingerprint


def _finding(title: str = "SQL injection", line: int = 2) -> Finding:
    evidence = 'query = "SELECT * FROM orders WHERE id=" + order_id'
    return Finding(
        fingerprint=fingerprint("security", "app/orders.py", evidence, "CWE-89"),
        lens="security",
        title=title,
        severity="high",
        confidence="high",
        file="app/orders.py",
        start_line=line,
        end_line=line,
        evidence=evidence,
        explanation="Concatenated SQL. Ping @octocat <b>now</b>.",
        recommendation="Parameterise the query.",
        suggested_patch="query = select(order_id)",
        standards=("CWE-89",),
        sources=("llm:security",),
        corroborated=False,
        status="active",
    )


@pytest.mark.asyncio
async def test_batch_review_and_second_run_posts_no_duplicate() -> None:
    comments: list[dict[str, object]] = []
    finding = _finding()
    async with httpx.AsyncClient(base_url="https://api.github.com") as client:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/repos/acme/billing/issues/7/comments").mock(
                side_effect=lambda request: httpx.Response(200, json=list(comments))
            )
            router.post("https://api.github.com/repos/acme/billing/issues/7/comments").mock(
                side_effect=lambda request: _store(comments, request)
            )
            router.patch("https://api.github.com/repos/acme/billing/issues/comments/4").mock(
                return_value=httpx.Response(200, json={"id": 4})
            )
            review = router.post("https://api.github.com/repos/acme/billing/pulls/7/reviews").mock(
                return_value=httpx.Response(200, json={"id": 9})
            )
            provider = GitHubProvider(client, owner="acme", repo="billing")
            verdict = Verdict(outcome="concerns")
            await provider.publish(
                number="7",
                head_sha="abc123",
                findings=(finding,),
                verdict=verdict,
                markdown="# Tollgate\n",
                config_hash="hash",
                mode="comment",
            )
            await provider.publish(
                number="7",
                head_sha="abc123",
                findings=(finding,),
                verdict=verdict,
                markdown="# Tollgate\n",
                config_hash="hash",
                mode="comment",
            )
    assert review.call_count == 1
    body = str(comments[0]["body"])
    assert "<!-- tollgate:summary -->" in body
    state = decode_state(body)
    assert state is not None
    assert state.findings[0].fp == finding.fingerprint
    assert "```suggestion" in review.calls[0].request.read().decode()


@pytest.mark.asyncio
async def test_invalid_batch_falls_back_to_single_comments() -> None:
    finding = _finding()
    async with httpx.AsyncClient(base_url="https://api.github.com") as client:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/repos/acme/billing/issues/7/comments").mock(
                return_value=httpx.Response(200, json=[])
            )
            router.post("https://api.github.com/repos/acme/billing/issues/7/comments").mock(
                return_value=httpx.Response(201, json={"id": 4})
            )
            router.post("https://api.github.com/repos/acme/billing/pulls/7/reviews").mock(
                return_value=httpx.Response(422, json={"message": "line not in diff"})
            )
            single = router.post("https://api.github.com/repos/acme/billing/pulls/7/comments").mock(
                return_value=httpx.Response(201, json={"id": 5})
            )
            provider = GitHubProvider(client, owner="acme", repo="billing")
            result = await provider.publish(
                number="7",
                head_sha="abc123",
                findings=(finding,),
                verdict=Verdict(outcome="concerns"),
                markdown="# Tollgate\n",
                config_hash="hash",
                mode="comment",
            )
    assert single.called
    assert result.posted == ("app/orders.py",)
    assert result.failed == ()


@pytest.mark.asyncio
async def test_fork_pull_request_makes_no_write_calls() -> None:
    async with httpx.AsyncClient(base_url="https://api.github.com") as client:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/repos/acme/billing/issues/7/comments").mock(
                return_value=httpx.Response(200, json=[])
            )
            writing = router.post(url__regex=r"https://api.github.com/.*").mock(
                return_value=httpx.Response(500)
            )
            provider = GitHubProvider(client, owner="acme", repo="billing", read_only=True)
            await provider.publish(
                number="7",
                head_sha="abc123",
                findings=(_finding(),),
                verdict=Verdict(outcome="concerns"),
                markdown="# Tollgate\n",
                config_hash="hash",
                mode="status",
            )
    assert provider.write_calls == []
    assert writing.call_count == 0


def test_sarif_file_checkout_mode_and_mentions(tmp_path: Path) -> None:
    finding = _finding()
    provider = GitHubProvider(httpx.AsyncClient(), owner="acme", repo="billing", read_only=True)
    path = tmp_path / "tollgate.sarif"
    provider.write_sarif(path, [finding], Verdict(outcome="concerns"))
    validate_sarif(path.read_text(encoding="utf-8"))
    assert checkout_mode("pull_request") == "local"
    assert checkout_mode("pull_request_target") == "api"
    event = {"head": {"repo": {"fork": True, "full_name": "a/b"}}, "base": {"repo": {}}}
    assert is_fork_event({"pull_request": event})
    text = neutralize("hi @octocat <script>alert(1)</script>")
    assert "@octocat" not in text.replace("`@octocat`", "")
    assert "<script>" not in text
    previous = decode_state("<!-- tollgate:state e30= -->")
    assert previous is None or previous.v == 1
    limited = files_for_incremental(
        {"app/orders.py"},
        None,
        enabled=True,
        config_hash="same",
        force_full=False,
    )
    assert limited is None


def _store(comments: list[dict[str, object]], request: httpx.Request) -> httpx.Response:
    comments.append({"id": 4, "body": json.loads(request.content)["body"]})
    return httpx.Response(201, json={"id": 4})


def test_incremental_carry_is_disabled_when_config_changes() -> None:
    from tollgate.models import ReviewState

    previous = ReviewState(last_reviewed_head="aaa", config_hash="old", findings=())
    same = files_for_incremental(
        {"app/orders.py"},
        previous,
        enabled=True,
        config_hash="old",
        force_full=False,
    )
    changed = files_for_incremental(
        {"app/orders.py"},
        previous,
        enabled=True,
        config_hash="new",
        force_full=False,
    )
    assert same == {"app/orders.py"}
    assert changed is None
    assert TollgateConfig().incremental is False
