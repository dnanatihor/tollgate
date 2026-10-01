"""Parse Semgrep JSON and keep results on changed lines."""

from __future__ import annotations

import json
from typing import Any

from tollgate.analyzers.findings import rule_finding
from tollgate.models import DiffFile, Finding
from tollgate.standards import load_catalogs
from tollgate.verify import known_ids_from_catalogs


def parse_semgrep(payload: str, diffs: tuple[DiffFile, ...]) -> tuple[Finding, ...]:
    document = _load(payload)
    results = document.get("results", [])
    if not isinstance(results, list):
        return ()
    known = known_ids_from_catalogs(load_catalogs(), ())
    changed = {diff.path: _changed(diff) for diff in diffs}
    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", ""))
        start = _line(item.get("start"))
        if start is None or start not in changed.get(path, set()):
            continue
        end = _line(item.get("end")) or start
        standards = _standards(item, known)
        if not standards:
            continue
        extra = item.get("extra", {})
        message = "Semgrep finding"
        if isinstance(extra, dict):
            message = str(extra.get("message", item.get("check_id", message)))
        evidence = _evidence(diffs, path, start)
        findings.append(
            rule_finding(
                lens="security",
                title=str(message)[:90] or "Semgrep finding",
                severity="high",
                confidence="medium",
                file=path,
                start_line=start,
                end_line=end,
                evidence=evidence,
                explanation=(
                    "Semgrep reported this on a changed line. Triage still has to confirm it."
                ),
                recommendation="Confirm the finding against the changed lines before publishing.",
                standards=standards,
                source=f"semgrep:{item.get('check_id', 'rule')}",
            )
        )
    return tuple(findings)


def _standards(item: dict[str, Any], known: set[str]) -> tuple[str, ...]:
    extra = item.get("extra", {})
    metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
    raw: list[str] = []
    if isinstance(metadata, dict):
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [cwe]
        if isinstance(cwe, list):
            for entry in cwe:
                text = str(entry)
                match = text.split(":")[0].strip()
                if match.startswith("CWE-"):
                    raw.append(match)
    return tuple(item for item in raw if item in known)


def _evidence(diffs: tuple[DiffFile, ...], path: str, line_no: int) -> str:
    for diff in diffs:
        if diff.path != path:
            continue
        for hunk in diff.hunks:
            for line in hunk.lines:
                if line.new_line == line_no:
                    return line.text.strip() or path
    return path


def _changed(diff: DiffFile) -> set[int]:
    return {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }


def _line(value: Any) -> int | None:
    if isinstance(value, dict) and isinstance(value.get("line"), int):
        return int(value["line"])
    return None


def _load(payload: str) -> dict[str, Any]:
    loaded = json.loads(payload or "{}")
    if not isinstance(loaded, dict):
        return {}
    return loaded
