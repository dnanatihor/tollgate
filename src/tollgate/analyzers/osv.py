"""Parse OSV-Scanner JSON for dependencies this pull request adds or upgrades."""

from __future__ import annotations

import json
from typing import Any

from tollgate.analyzers.findings import rule_finding
from tollgate.models import Finding


def parse_osv(
    payload: str,
    *,
    added_names: set[str],
    files: dict[str, str],
) -> tuple[Finding, ...]:
    document = json.loads(payload or "{}")
    if not isinstance(document, dict):
        return ()
    results = document.get("results", [])
    if not isinstance(results, list):
        return ()
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source", {})
        path = "dependencies"
        if isinstance(source, dict):
            path = str(source.get("path", path))
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            continue
        for package in packages:
            finding = _package_finding(package, path, added_names, files.get(path, ""))
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def _package_finding(
    package: Any,
    path: str,
    added_names: set[str],
    text: str,
) -> Finding | None:
    if not isinstance(package, dict):
        return None
    info = package.get("package", {})
    name = str(info.get("name", "")) if isinstance(info, dict) else ""
    if name.lower() not in added_names and name.split("/")[-1].lower() not in added_names:
        return None
    vulns = package.get("vulnerabilities", [])
    if not isinstance(vulns, list) or not vulns:
        return None
    advisory = str(vulns[0].get("id", "advisory")) if isinstance(vulns[0], dict) else "advisory"
    line_no, evidence = _line_for(text, name)
    return rule_finding(
        lens="security",
        title=f"Vulnerable dependency {name}",
        severity="high",
        confidence="high",
        file=path,
        start_line=line_no,
        end_line=line_no,
        evidence=evidence,
        explanation=f"OSV reports {advisory} in {name}, which this pull request adds or upgrades.",
        recommendation="Upgrade to a patched release or remove the dependency.",
        standards=("OWASP-WEB-2025:A03",),
        source=f"osv:{advisory}",
    )


def _line_for(text: str, name: str) -> tuple[int, str]:
    for number, line in enumerate(text.splitlines(), start=1):
        if name.lower() in line.lower():
            return number, line.strip()
    return 1, name
