"""Bitbucket Data Center 8.19 publishing (SPEC.md §11.4, ADR 0005)."""

from __future__ import annotations

from typing import Any, Literal

import httpx

from tollgate.models import DiffFile, Finding, Verdict
from tollgate.scm.state import SUMMARY_MARKER, build_state, summary_body
from tollgate.scm.types import neutralize


def finding_line_types(
    diffs: tuple[DiffFile, ...],
    findings: tuple[Finding, ...],
) -> dict[str, Literal["ADDED", "CONTEXT"]]:
    """Map each finding to ``ADDED`` or ``CONTEXT`` from the parsed diff."""
    kinds: dict[tuple[str, int], Literal["ADDED", "CONTEXT"]] = {}
    for diff in diffs:
        path = getattr(diff, "path", "")
        for hunk in getattr(diff, "hunks", ()):
            for line in hunk.lines:
                if line.new_line is None or line.kind not in {"+", " "}:
                    continue
                kinds[(path, line.new_line)] = line_type_for(line.kind)
    mapped: dict[str, Literal["ADDED", "CONTEXT"]] = {}
    for finding in findings:
        if finding.file is None or finding.start_line is None:
            continue
        mapped[finding.fingerprint] = kinds.get((finding.file, finding.start_line), "ADDED")
    return mapped


def line_type_for(kind: str) -> Literal["ADDED", "CONTEXT"]:
    """Map a diff line to the Data Center anchor `lineType`."""
    if kind == "+":
        return "ADDED"
    if kind == " ":
        return "CONTEXT"
    raise ValueError(f"unsupported line kind {kind!r}")


class BitbucketDataCenterProvider:
    name: Literal["bitbucket_dc"] = "bitbucket_dc"

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        base_url: str,
        project: str,
        repo: str,
    ) -> None:
        self._client = client
        self.base_url = base_url.rstrip("/")
        self.project = project
        self.repo = repo
        self.write_calls: list[str] = []

    async def post_inline(
        self,
        number: str,
        finding: Finding,
        *,
        line_type: Literal["ADDED", "CONTEXT"],
    ) -> dict[str, Any]:
        anchor = {
            "path": finding.file,
            "line": finding.start_line,
            "lineType": line_type,
            "fileType": "TO",
            "diffType": "EFFECTIVE",
        }
        payload = await self._json(
            "POST",
            self._pr(number, "comments"),
            json={"text": _text(finding), "anchor": anchor},
        )
        if not isinstance(payload, dict):
            return {}
        return payload

    async def upsert_summary(self, number: str, body: str) -> None:
        existing = await self._find_summary(number)
        if existing is None:
            await self._json("POST", self._pr(number, "comments"), json={"text": body})
            return
        comment_id, version = existing
        await self._json(
            "PUT",
            self._pr(number, f"comments/{comment_id}"),
            json={"text": body, "version": version},
        )

    async def publish_report(self, commit: str, verdict: Verdict) -> None:
        result = "FAIL" if verdict.outcome == "block" else "PASS"
        report = (
            f"{self.base_url}/rest/insights/1.0/projects/{self.project}"
            f"/repos/{self.repo}/commits/{commit}/reports/tollgate"
        )
        await self._json(
            "PUT",
            report,
            json={"title": "Tollgate", "result": result, "reporter": "tollgate"},
        )
        state = "FAILED" if verdict.outcome == "block" else "SUCCESSFUL"
        await self._json(
            "POST",
            f"{self.base_url}/rest/build-status/1.0/commits/{commit}",
            json={"key": "tollgate", "state": state, "url": report},
        )

    async def publish(
        self,
        *,
        number: str,
        commit: str,
        findings: tuple[Finding, ...],
        verdict: Verdict,
        markdown: str,
        config_hash: str,
        line_types: dict[str, Literal["ADDED", "CONTEXT"]],
    ) -> None:
        state, _overflow = build_state(
            head_sha=commit,
            config_hash=config_hash,
            findings=findings,
        )
        await self.upsert_summary(number, summary_body(markdown, state, ()))
        for finding in findings:
            if finding.file is None or finding.fingerprint not in line_types:
                continue
            await self.post_inline(number, finding, line_type=line_types[finding.fingerprint])
        await self.publish_report(commit, verdict)

    def _pr(self, number: str, suffix: str) -> str:
        return (
            f"{self.base_url}/rest/api/1.0/projects/{self.project}"
            f"/repos/{self.repo}/pull-requests/{number}/{suffix}"
        )

    async def _find_summary(self, number: str) -> tuple[int, int] | None:
        payload = await self._json("GET", self._pr(number, "comments"))
        values = payload.get("values", []) if isinstance(payload, dict) else []
        if not isinstance(values, list):
            return None
        for item in values:
            if isinstance(item, dict) and SUMMARY_MARKER in str(item.get("text", "")):
                return int(item["id"]), int(item.get("version", 0))
        return None

    async def _json(self, method: str, url: str, json: Any = None) -> Any:
        if method != "GET":
            self.write_calls.append(f"{method} {url}")
        response = await self._client.request(
            method,
            url,
            json=json,
            headers={"Authorization": "Bearer redacted"},
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()


def _text(finding: Finding) -> str:
    return "\n".join((neutralize(finding.title), neutralize(finding.explanation)))
