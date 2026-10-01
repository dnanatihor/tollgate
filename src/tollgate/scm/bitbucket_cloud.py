"""Bitbucket Cloud pull-request publishing (SPEC.md §11.3, ADR 0004)."""

from __future__ import annotations

from typing import Any, Literal

import httpx

from tollgate.models import Finding, Verdict
from tollgate.scm.state import (
    SUMMARY_MARKER,
    build_state,
    decode_state,
    new_fingerprints,
    summary_body,
)
from tollgate.scm.types import neutralize

ANNOTATION_BATCH = 100
_API = "https://api.bitbucket.org/2.0"


class BitbucketCloudProvider:
    name: Literal["bitbucket_cloud"] = "bitbucket_cloud"

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        workspace: str,
        repo: str,
        insights_base: str = _API,
    ) -> None:
        self._client = client
        self.workspace = workspace
        self.repo = repo
        self.insights_base = insights_base.rstrip("/")
        self.write_calls: list[str] = []

    async def upsert_summary(self, number: str, body: str) -> None:
        existing = await self._find_summary(number)
        if existing is None:
            await self._json(
                "POST",
                self._pr(number, "comments"),
                json={"content": {"raw": body}},
            )
            return
        await self._json(
            "PUT",
            self._pr(number, f"comments/{existing}"),
            json={"content": {"raw": body}},
        )

    async def post_inline(self, number: str, finding: Finding) -> bool:
        if finding.file is None or finding.start_line is None:
            return False
        body = _comment(finding)
        await self._json(
            "POST",
            self._pr(number, "comments"),
            json={
                "content": {"raw": body},
                "inline": {"path": finding.file, "to": finding.start_line},
            },
        )
        return True

    async def publish_report(
        self,
        commit: str,
        verdict: Verdict,
        findings: tuple[Finding, ...],
    ) -> None:
        report = (
            f"{self.insights_base}/repositories/{self.workspace}/{self.repo}"
            f"/commit/{commit}/reports/tollgate"
        )
        result = "FAILED" if verdict.outcome == "block" else "PASSED"
        await self._json(
            "PUT",
            report,
            json={
                "title": "Tollgate",
                "details": "Tollgate review",
                "report_type": "SECURITY",
                "result": result,
            },
        )
        annotations = [_annotation(item) for item in findings if item.file and item.start_line]
        for offset in range(0, len(annotations), ANNOTATION_BATCH):
            batch = annotations[offset : offset + ANNOTATION_BATCH]
            if not batch:
                continue
            await self._json("POST", f"{report}/annotations", json=batch)

    async def publish(
        self,
        *,
        number: str,
        commit: str,
        findings: tuple[Finding, ...],
        verdict: Verdict,
        markdown: str,
        config_hash: str,
    ) -> int:
        comments = await self._comments(number)
        previous_body = next((item for item in comments if SUMMARY_MARKER in item), None)
        previous = None if previous_body is None else decode_state(previous_body)
        state, _overflow = build_state(
            head_sha=commit,
            config_hash=config_hash,
            findings=findings,
        )
        await self.upsert_summary(number, summary_body(markdown, state, ()))
        posted = 0
        for finding in new_fingerprints(findings, previous):
            if await self.post_inline(number, finding):
                posted += 1
        await self.publish_report(commit, verdict, findings)
        return posted

    def _pr(self, number: str, suffix: str) -> str:
        return (
            f"{_API}/repositories/{self.workspace}/{self.repo}/pullrequests/{number}/{suffix}"
        )

    async def _find_summary(self, number: str) -> int | None:
        payload = await self._json("GET", self._pr(number, "comments"))
        values = payload.get("values", []) if isinstance(payload, dict) else []
        if not isinstance(values, list):
            return None
        for item in values:
            if isinstance(item, dict) and SUMMARY_MARKER in str(_raw(item)):
                return int(item["id"])
        return None

    async def _comments(self, number: str) -> list[str]:
        payload = await self._json("GET", self._pr(number, "comments"))
        values = payload.get("values", []) if isinstance(payload, dict) else []
        if not isinstance(values, list):
            return []
        return [str(_raw(item)) for item in values if isinstance(item, dict)]

    async def _json(self, method: str, url: str, json: Any = None) -> Any:
        if method != "GET":
            self.write_calls.append(f"{method} {url}")
        response = await self._client.request(method, url, json=json)
        response.raise_for_status()
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()


def _raw(item: dict[str, Any]) -> str:
    content = item.get("content")
    if isinstance(content, dict):
        return str(content.get("raw", ""))
    return ""


def _comment(finding: Finding) -> str:
    lines = [neutralize(finding.title), "", neutralize(finding.explanation)]
    if finding.suggested_patch:
        lines.extend(["", "Suggested change:", "```", finding.suggested_patch.rstrip("\n"), "```"])
    return "\n".join(lines)


def _annotation(finding: Finding) -> dict[str, Any]:
    severity = "HIGH" if finding.severity in {"critical", "high"} else "MEDIUM"
    return {
        "external_id": f"tollgate-{finding.fingerprint}",
        "path": finding.file,
        "line": finding.start_line,
        "summary": neutralize(finding.title)[:450],
        "details": neutralize(finding.explanation)[:4000],
        "severity": severity,
        "annotation_type": "CODE_SMELL",
    }
