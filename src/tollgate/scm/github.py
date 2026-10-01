"""GitHub pull-request publishing (SPEC.md §11.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import httpx

from tollgate.models import Finding, PullRequest, Verdict
from tollgate.render.sarif import render_sarif
from tollgate.scm.state import (
    SUMMARY_MARKER,
    build_state,
    decode_state,
    new_fingerprints,
    resolved_titles,
    summary_body,
)
from tollgate.scm.types import (
    ExistingComment,
    InlineComment,
    PostResult,
    ProviderLimits,
    inline_for,
)

CheckoutMode = Literal["local", "api"]


def checkout_mode(event_name: str) -> CheckoutMode:
    """``pull_request_target`` must not check out the pull request head."""
    if event_name == "pull_request_target":
        return "api"
    return "local"


def is_fork_event(event: dict[str, Any]) -> bool:
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        return False
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        return False
    head_repo = head.get("repo") if isinstance(head.get("repo"), dict) else {}
    base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
    if not isinstance(head_repo, dict) or not isinstance(base_repo, dict):
        return False
    if head_repo.get("fork") is True:
        return True
    return head_repo.get("full_name") != base_repo.get("full_name")


class GitHubProvider:
    """Writes reviews through the GitHub API. Fork runs record no write calls."""

    name: Literal["github"] = "github"

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        owner: str,
        repo: str,
        read_only: bool = False,
    ) -> None:
        self._client = client
        self.owner = owner
        self.repo = repo
        self.read_only = read_only
        self.write_calls: list[str] = []

    def limits(self) -> ProviderLimits:
        return ProviderLimits()

    async def get_pull_request(self, number: str) -> PullRequest:
        payload = await self._json("GET", f"/pulls/{number}", write=False)
        base = payload.get("base", {})
        head = payload.get("head", {})
        head_repo = head.get("repo", {}) if isinstance(head, dict) else {}
        return PullRequest(
            platform="github",
            repo=f"{self.owner}/{self.repo}",
            number=str(payload.get("number", number)),
            title=str(payload.get("title", "")),
            description=str(payload.get("body") or ""),
            base_ref=str(base.get("ref", "main")) if isinstance(base, dict) else "main",
            base_sha=str(base.get("sha", "")) if isinstance(base, dict) else "",
            head_ref=str(head.get("ref", "head")) if isinstance(head, dict) else "head",
            head_sha=str(head.get("sha", "")) if isinstance(head, dict) else "",
            author=str((payload.get("user") or {}).get("login", "")),
            is_fork=bool(head_repo.get("fork")) if isinstance(head_repo, dict) else False,
        )

    async def find_summary(self, number: str) -> ExistingComment | None:
        comments = await self._json("GET", f"/issues/{number}/comments", write=False)
        if not isinstance(comments, list):
            return None
        for item in comments:
            if isinstance(item, dict) and SUMMARY_MARKER in str(item.get("body", "")):
                return ExistingComment(id=int(item["id"]), body=str(item.get("body", "")))
        return None

    async def upsert_summary(self, number: str, body: str) -> None:
        existing = await self.find_summary(number)
        if existing is None:
            await self._json("POST", f"/issues/{number}/comments", write=True, json={"body": body})
            return
        await self._json(
            "PATCH",
            f"/issues/comments/{existing.id}",
            write=True,
            json={"body": body},
        )

    async def post_inline(
        self,
        number: str,
        head_sha: str,
        comments: list[InlineComment],
        *,
        event: str = "COMMENT",
    ) -> PostResult:
        if not comments:
            return PostResult(posted=(), failed=())
        payload = {
            "commit_id": head_sha,
            "event": event,
            "comments": [_comment(item) for item in comments],
        }
        response = await self._send("POST", f"/pulls/{number}/reviews", write=True, json=payload)
        if response is None:
            return PostResult(posted=(), failed=())
        if response.status_code != 422:
            response.raise_for_status()
            return PostResult(posted=tuple(item.path for item in comments), failed=())
        posted: list[str] = []
        failed: list[str] = []
        for item in comments:
            single = await self._send(
                "POST",
                f"/pulls/{number}/comments",
                write=True,
                json={
                    "commit_id": head_sha,
                    "path": item.path,
                    "line": item.line,
                    "side": "RIGHT",
                    "body": item.body,
                },
            )
            if single is not None and single.status_code < 400:
                posted.append(item.path)
            else:
                failed.append(item.path)
        return PostResult(posted=tuple(posted), failed=tuple(failed))

    async def set_status(self, head_sha: str, verdict: Verdict, summary: str, *, mode: str) -> None:
        conclusion = _conclusion(verdict, mode)
        annotations: list[dict[str, str]] = []
        await self._json(
            "POST",
            "/check-runs",
            write=True,
            json={
                "name": "Tollgate",
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": f"Tollgate {verdict.outcome}",
                    "summary": summary[:65000],
                    "annotations": annotations,
                },
            },
        )

    async def publish(
        self,
        *,
        number: str,
        head_sha: str,
        findings: tuple[Finding, ...],
        verdict: Verdict,
        markdown: str,
        config_hash: str,
        mode: str,
        eligible_lines: dict[str, set[int]] | None = None,
    ) -> PostResult:
        previous_comment = None if self.read_only else await self.find_summary(number)
        previous = None if previous_comment is None else decode_state(previous_comment.body)
        state, _overflow = build_state(
            head_sha=head_sha,
            config_hash=config_hash,
            findings=findings,
        )
        fresh = new_fingerprints(findings, previous)
        resolved = resolved_titles(findings, previous)
        body = summary_body(markdown, state, resolved)
        await self.upsert_summary(number, body)
        comments: list[InlineComment] = []
        for finding in fresh:
            path = finding.file or ""
            lines = None if eligible_lines is None else eligible_lines.get(path, set())
            comment = inline_for(finding, eligible_lines=lines)
            if comment is not None:
                comments.append(comment)
        event = "COMMENT"
        if mode == "request_changes" and verdict.outcome == "block":
            event = "REQUEST_CHANGES"
        result = await self.post_inline(number, head_sha, comments, event=event)
        if mode != "comment":
            await self.set_status(head_sha, verdict, body, mode=mode)
        return result

    def write_sarif(self, path: Path, findings: list[Finding], verdict: Verdict) -> None:
        path.write_text(render_sarif(findings, verdict), encoding="utf-8")

    async def _json(
        self,
        method: str,
        path: str,
        *,
        write: bool,
        json: dict[str, Any] | None = None,
    ) -> Any:
        response = await self._send(method, path, write=write, json=json)
        if response is None:
            return {} if method != "GET" else []
        response.raise_for_status()
        return response.json()

    async def _send(
        self,
        method: str,
        path: str,
        *,
        write: bool,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response | None:
        if write and self.read_only:
            return None
        if write:
            self.write_calls.append(f"{method} {path}")
        url = f"/repos/{self.owner}/{self.repo}{path}"
        return await self._client.request(
            method,
            url,
            json=json,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )


def _comment(item: InlineComment) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "path": item.path,
        "line": item.line,
        "side": "RIGHT",
        "body": item.body[:65000],
    }
    if item.start_line is not None:
        payload["start_line"] = item.start_line
    return payload


def _conclusion(verdict: Verdict, mode: str) -> str:
    if mode == "comment":
        return "success"
    if verdict.outcome == "block":
        return "failure"
    return "success"
