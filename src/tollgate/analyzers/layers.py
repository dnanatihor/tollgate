"""TG-ARCH-001: a layer may not import a layer outside ``may_depend_on``."""

from __future__ import annotations

import re

from tollgate.analyzers.findings import rule_finding
from tollgate.config import ArchitectureConfig, LayerRule
from tollgate.globs import matches_any
from tollgate.models import DiffFile, Finding

_PYTHON_IMPORT = re.compile(r"^\s*(?:from\s+(\S+)\s+import|import\s+(\S+))")


def layer_findings(
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
    architecture: ArchitectureConfig,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for diff in diffs:
        layer = _layer_for(diff.path, architecture)
        if layer is None:
            continue
        text = head_texts.get(diff.path, "")
        for number, line in enumerate(text.splitlines(), start=1):
            if number not in _added(diff):
                continue
            module = _imported_module(line)
            if module is None:
                continue
            target = _layer_for(_module_path(module), architecture)
            allowed = set(layer.may_depend_on) | {layer.name}
            if target is None or target.name in allowed:
                continue
            findings.append(
                rule_finding(
                    title=f"Layer {layer.name} imports {target.name}",
                    severity="high",
                    confidence="high",
                    file=diff.path,
                    start_line=number,
                    end_line=number,
                    evidence=line.strip(),
                    explanation=(
                        f"{diff.path} is in the {layer.name} layer, which may depend on "
                        f"{layer.may_depend_on or 'nothing'}, but this import resolves to "
                        f"the {target.name} layer."
                    ),
                    recommendation="Depend only on layers listed in may_depend_on.",
                    standards=("TG-ARCH-001",),
                    source="rule:TG-ARCH-001",
                )
            )
    return tuple(findings)


def _layer_for(path: str, architecture: ArchitectureConfig) -> LayerRule | None:
    for layer in architecture.layers:
        if matches_any(path, layer.paths):
            return layer
    return None


def _imported_module(line: str) -> str | None:
    match = _PYTHON_IMPORT.match(line)
    if match is None:
        return None
    module = match.group(1) or match.group(2)
    if module.startswith("."):
        return None
    return module.partition(",")[0]


def _module_path(module: str) -> str:
    return module.replace(".", "/") + ".py"


def _added(diff: DiffFile) -> set[int]:
    return {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }
