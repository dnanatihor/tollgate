"""TG-ARCH-006: breaking OpenAPI, protobuf, and migration changes."""

from __future__ import annotations

import re
from typing import Any

import yaml

from tollgate.analyzers.findings import rule_finding
from tollgate.models import DiffFile, Finding

_DESTRUCTIVE = re.compile(
    r"(?i)\b(drop\s+table|drop\s+column|truncate\s+table|alter\s+table\s+\w+\s+drop)\b"
)
_PROTO_FIELD = re.compile(
    r"^\s*(?:repeated\s+|optional\s+)?[\w.]+\s+(\w+)\s*=\s*(\d+)\s*;",
    re.MULTILINE,
)


def contract_findings(
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
    base_texts: dict[str, str],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for diff in diffs:
        head = head_texts.get(diff.path, "")
        base = base_texts.get(diff.path, "")
        if _looks_openapi(head) or _looks_openapi(base):
            findings.extend(_openapi(diff.path, base, head))
        if diff.path.endswith(".proto"):
            findings.extend(_protobuf(diff.path, base, head))
        if diff.path.endswith(".sql"):
            findings.extend(_migration(diff, head))
    return tuple(findings)


def _looks_openapi(text: str) -> bool:
    return text.lstrip().startswith("openapi:") or "\nopenapi:" in text[:200]


def _openapi(path: str, base: str, head: str) -> list[Finding]:
    before = _load(base)
    after = _load(head)
    if not isinstance(before, dict):
        return []
    after_map = after if isinstance(after, dict) else {}
    findings: list[Finding] = []
    for route, methods in _paths(before).items():
        current = _paths(after_map).get(route, {})
        if not current:
            findings.append(_break(path, head, route, f"Removed API path {route}"))
            continue
        for method in methods:
            if method not in current:
                findings.append(_break(path, head, route, f"Removed {method.upper()} {route}"))
    for route, methods in _paths(before).items():
        current = _paths(after_map).get(route, {})
        for method, body in methods.items():
            if method not in current:
                continue
            findings.extend(_schema_breaks(path, head, route, body, current[method]))
    return findings


def _schema_breaks(
    path: str,
    head: str,
    route: str,
    before: Any,
    after: Any,
) -> list[Finding]:
    old = _properties(before)
    new = _properties(after)
    findings: list[Finding] = []
    for name in old.keys() - new.keys():
        findings.append(_break(path, head, name, f"Removed request property {name} on {route}"))
    for name, schema in old.items():
        if name in new and schema.get("type") != new[name].get("type"):
            findings.append(_break(path, head, name, f"Changed type of {name} on {route}"))
    required_before = set(_required(before))
    for name in set(_required(after)) - required_before:
        findings.append(_break(path, head, name, f"Newly required field {name} on {route}"))
    return findings


def _protobuf(path: str, base: str, head: str) -> list[Finding]:
    before = {int(number): name for name, number in _PROTO_FIELD.findall(base)}
    after = {int(number): name for name, number in _PROTO_FIELD.findall(head)}
    findings: list[Finding] = []
    for number, name in before.items():
        if number not in after:
            findings.append(_break(path, head, name, f"Removed protobuf field {name} = {number}"))
        elif after[number] != name:
            findings.append(
                _break(path, head, after[number], f"Renumbered protobuf field {number}")
            )
    return findings


def _migration(diff: DiffFile, head: str) -> list[Finding]:
    added = {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }
    findings: list[Finding] = []
    for number, line in enumerate(head.splitlines(), start=1):
        if number not in added or _DESTRUCTIVE.search(line) is None:
            continue
        findings.append(
            rule_finding(
                title="Destructive database migration",
                severity="high",
                confidence="high",
                file=diff.path,
                start_line=number,
                end_line=number,
                evidence=line.strip(),
                explanation=(
                    "The migration drops or truncates data that existing clients may rely on."
                ),
                recommendation="Ship an expand-and-contract migration and document the break.",
                standards=("TG-ARCH-006",),
                source="rule:TG-ARCH-006",
            )
        )
    return findings


def _break(path: str, head: str, needle: str, title: str) -> Finding:
    line_no = 1
    evidence = needle
    for number, line in enumerate(head.splitlines(), start=1):
        if needle in line:
            line_no = number
            evidence = line.strip()
            break
    return rule_finding(
        title=title,
        severity="high",
        confidence="high",
        file=path,
        start_line=line_no,
        end_line=line_no,
        evidence=evidence or title,
        explanation="The public contract no longer accepts a request that previously succeeded.",
        recommendation="Keep the old operation until clients migrate, or ship a new version.",
        standards=("TG-ARCH-006",),
        source="rule:TG-ARCH-006",
    )


def _load(text: str) -> Any:
    if not text.strip():
        return {}
    loaded = yaml.safe_load(text)
    return loaded if loaded is not None else {}


def _paths(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = document.get("paths", {})
    if not isinstance(raw, dict):
        return {}
    paths: dict[str, dict[str, Any]] = {}
    for route, methods in raw.items():
        if isinstance(methods, dict):
            paths[str(route)] = {
                str(method): body
                for method, body in methods.items()
                if str(method) in {"get", "post", "put", "patch", "delete"}
            }
    return paths


def _properties(operation: Any) -> dict[str, dict[str, Any]]:
    schema = _request_schema(operation)
    raw = schema.get("properties", {}) if isinstance(schema, dict) else {}
    if not isinstance(raw, dict):
        return {}
    return {str(key): value for key, value in raw.items() if isinstance(value, dict)}


def _required(operation: Any) -> list[str]:
    schema = _request_schema(operation)
    raw = schema.get("required", []) if isinstance(schema, dict) else []
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw]


def _request_schema(operation: Any) -> dict[str, Any]:
    if not isinstance(operation, dict):
        return {}
    body = operation.get("requestBody", {})
    if not isinstance(body, dict):
        return {}
    content = body.get("content", {})
    if not isinstance(content, dict):
        return {}
    json_body = content.get("application/json", {})
    if not isinstance(json_body, dict):
        return {}
    schema = json_body.get("schema", {})
    return schema if isinstance(schema, dict) else {}
