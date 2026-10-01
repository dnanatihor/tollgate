"""TG-ARCH-003: significance triggers require an ADR in the pull request."""

from __future__ import annotations

import re

from tollgate.analyzers.deps import added_dependency_names
from tollgate.analyzers.findings import rule_finding
from tollgate.config import ArchitectureConfig
from tollgate.globs import matches_any
from tollgate.models import DiffFile, Finding

_DATASTORE = re.compile(
    r"(?i)\b(redis|postgres|postgresql|mysql|mongodb|dynamodb|elasticsearch|aws_db_instance)\b"
)
_OPENAPI_PATH = re.compile(r"^\s{2}/[^\s:]+:")


def significance_findings(
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
    architecture: ArchitectureConfig,
    *,
    adr_present: bool,
) -> tuple[Finding, ...]:
    if adr_present:
        return ()
    triggers = architecture.significance_triggers
    findings: list[Finding] = []
    if triggers.new_dependency and added_dependency_names(diffs, head_texts):
        findings.extend(_for_manifests(diffs, head_texts, "new_dependency"))
    for diff in diffs:
        text = head_texts.get(diff.path, "")
        if triggers.new_datastore and _added_match(diff, text, _DATASTORE):
            findings.append(_one(diff, text, _DATASTORE, "new_datastore"))
        if triggers.new_public_endpoint and (
            text.lstrip().startswith("openapi:") or "openapi:" in text[:80]
        ):
            match_line = _first_added(diff, text, _OPENAPI_PATH)
            if match_line is not None:
                findings.append(_one(diff, text, _OPENAPI_PATH, "new_public_endpoint"))
        if _matches_prefix(diff.path, triggers.new_service_paths):
            findings.append(_path_finding(diff, "new_service"))
        if _matches_prefix(diff.path, triggers.infra_paths):
            findings.append(_path_finding(diff, "infrastructure"))
    return tuple(findings)


def adr_in_diff(diffs: tuple[DiffFile, ...], patterns: list[str]) -> bool:
    return any(
        diff.status != "deleted" and matches_any(diff.path, patterns or ["docs/adr/**"])
        for diff in diffs
    )


def _for_manifests(
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
    trigger: str,
) -> list[Finding]:
    found: list[Finding] = []
    names = added_dependency_names(diffs, head_texts)
    for diff in diffs:
        if diff.path.rsplit("/", 1)[-1] not in {
            "requirements.txt",
            "package.json",
            "pyproject.toml",
            "go.mod",
        } and not diff.path.endswith("requirements.txt"):
            continue
        text = head_texts.get(diff.path, "")
        for number, line in enumerate(text.splitlines(), start=1):
            if any(name in line.lower() for name in names):
                found.append(
                    rule_finding(
                        title=f"Significant change ({trigger}) without an ADR",
                        severity="medium",
                        confidence="high",
                        file=diff.path,
                        start_line=number,
                        end_line=number,
                        evidence=line.strip(),
                        explanation=(
                            "This change matches a significance trigger and the pull request "
                            "does not add an architecture decision record."
                        ),
                        recommendation="Add an ADR under the configured adr paths.",
                        standards=("TG-ARCH-003",),
                        source="rule:TG-ARCH-003",
                    )
                )
                return found
    return found


def _one(diff: DiffFile, text: str, pattern: re.Pattern[str], trigger: str) -> Finding:
    number = 1
    evidence = trigger
    for line_no, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            number = line_no
            evidence = line.strip()
            break
    return rule_finding(
        title=f"Significant change ({trigger}) without an ADR",
        severity="medium",
        confidence="high",
        file=diff.path,
        start_line=number,
        end_line=number,
        evidence=evidence,
        explanation=(
            "This change matches a significance trigger and the pull request "
            "does not add an architecture decision record."
        ),
        recommendation="Add an ADR under the configured adr paths.",
        standards=("TG-ARCH-003",),
        source="rule:TG-ARCH-003",
    )


def _path_finding(diff: DiffFile, trigger: str) -> Finding:
    return rule_finding(
        title=f"Significant change ({trigger}) without an ADR",
        severity="medium",
        confidence="high",
        file=diff.path,
        start_line=1,
        end_line=1,
        evidence=diff.path,
        explanation=(
            "This path matches a significance trigger and the pull request "
            "does not add an architecture decision record."
        ),
        recommendation="Add an ADR under the configured adr paths.",
        standards=("TG-ARCH-003",),
        source="rule:TG-ARCH-003",
    )


def _added_match(diff: DiffFile, text: str, pattern: re.Pattern[str]) -> bool:
    added = {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }
    return any(
        number in added and pattern.search(line)
        for number, line in enumerate(text.splitlines(), start=1)
    )


def _first_added(diff: DiffFile, text: str, pattern: re.Pattern[str]) -> int | None:
    added = {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }
    for number, line in enumerate(text.splitlines(), start=1):
        if number in added and pattern.search(line):
            return number
    return None


def _matches_prefix(path: str, patterns: list[str]) -> bool:
    expanded = [item + "**" if item.endswith("/") else item for item in patterns]
    return matches_any(path, expanded)
