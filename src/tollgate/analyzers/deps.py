"""TG-ARCH-002: new or changed dependencies versus the tech radar."""

from __future__ import annotations

import fnmatch
import re

from tollgate.analyzers.findings import rule_finding
from tollgate.config import ArchitectureConfig
from tollgate.models import DiffFile, Finding

_REQUIREMENT = re.compile(
    r"""^\s*["']?([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|!=|>|<)?\s*["']?([A-Za-z0-9_.*-]*)"""
)
_JSON_DEP = re.compile(r"""["']([A-Za-z0-9_.@/-]+)["']\s*:\s*["']([^"']+)["']""")
_GO_DEP = re.compile(r"^\s*([A-Za-z0-9_./-]+)\s+v?([0-9][A-Za-z0-9_.*-]*)")
_MANIFESTS = {
    "requirements.txt",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Pipfile",
    "Gemfile",
    "composer.json",
    "Cargo.toml",
}


def dependency_findings(
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
    architecture: ArchitectureConfig,
    *,
    adr_present: bool,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for diff in diffs:
        if not _is_manifest(diff.path):
            continue
        text = head_texts.get(diff.path, "")
        added = _added_lines(diff)
        for number, line in enumerate(text.splitlines(), start=1):
            if number not in added:
                continue
            parsed = _dependency(diff.path, line)
            if parsed is None:
                continue
            name, version = parsed
            ring = _ring(name, version, architecture)
            if ring is None:
                continue
            if ring == "assess" and adr_present:
                continue
            findings.append(
                rule_finding(
                    title=f"Dependency {name} is on {ring}",
                    severity="high" if ring == "hold" else "medium",
                    confidence="high",
                    file=diff.path,
                    start_line=number,
                    end_line=number,
                    evidence=line.strip(),
                    explanation=(
                        f"{name} {version} matches tech radar {ring}. "
                        "Hold dependencies are not accepted. Assess dependencies need an ADR."
                    ),
                    recommendation="Remove the dependency or record an ADR before adopting it.",
                    standards=("TG-ARCH-002",),
                    source="rule:TG-ARCH-002",
                )
            )
    return tuple(findings)


def added_dependency_names(diffs: tuple[DiffFile, ...], head_texts: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for diff in diffs:
        if not _is_manifest(diff.path):
            continue
        text = head_texts.get(diff.path, "")
        added = _added_lines(diff)
        for number, line in enumerate(text.splitlines(), start=1):
            if number not in added:
                continue
            parsed = _dependency(diff.path, line)
            if parsed is not None:
                names.add(parsed[0].lower())
    return names


def _is_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in _MANIFESTS or name.startswith("requirements"):
        return True
    return name in {"pom.xml", "build.gradle", "build.gradle.kts"} or name.endswith(".csproj")


def _dependency(path: str, line: str) -> tuple[str, str] | None:
    stripped = line.strip().lstrip("+- ")
    if not stripped or stripped.startswith(("#", "//")):
        return None
    name = path.rsplit("/", 1)[-1]
    if name == "package.json" or name == "composer.json":
        match = _JSON_DEP.search(stripped)
    elif name == "go.mod":
        match = _GO_DEP.match(stripped)
    else:
        match = _REQUIREMENT.match(stripped)
    if match is None:
        return None
    dep_name = match.group(1)
    if dep_name.lower() in {"dependencies", "require", "devdependencies"}:
        return None
    version = match.group(2) or ""
    return dep_name, version


def _ring(name: str, version: str, architecture: ArchitectureConfig) -> str | None:
    label = f"{name}:{version}" if version else name
    for ring, entries in (
        ("hold", architecture.tech_radar.hold),
        ("assess", architecture.tech_radar.assess),
    ):
        for entry in entries:
            if fnmatch.fnmatch(label, entry) or fnmatch.fnmatch(name, entry):
                return ring
    return None


def _added_lines(diff: DiffFile) -> set[int]:
    return {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }
