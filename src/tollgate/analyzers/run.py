"""Run built-in rules and report missing scanner binaries."""

from __future__ import annotations

import shutil
from collections.abc import Callable

from tollgate.analyzers.contracts import contract_findings
from tollgate.analyzers.deps import added_dependency_names, dependency_findings
from tollgate.analyzers.gitleaks import parse_gitleaks
from tollgate.analyzers.layers import layer_findings
from tollgate.analyzers.notes import Analysis, CoverageNote, binary_note
from tollgate.analyzers.osv import parse_osv
from tollgate.analyzers.retrieval import retrieve
from tollgate.analyzers.secrets import builtin_secret_findings
from tollgate.analyzers.semgrep import parse_semgrep
from tollgate.analyzers.significance import adr_in_diff, significance_findings
from tollgate.config import ArchitectureConfig, TollgateConfig
from tollgate.models import DiffFile, Finding


def analyze(
    diffs: tuple[DiffFile, ...],
    *,
    head_texts: dict[str, str],
    base_texts: dict[str, str],
    architecture: ArchitectureConfig,
    config: TollgateConfig,
    documents: tuple[tuple[str, str], ...] = (),
    semgrep_json: str | None = None,
    gitleaks_json: str | None = None,
    osv_json: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> Analysis:
    coverage: list[CoverageNote] = []
    findings: list[Finding] = []
    present = adr_in_diff(diffs, architecture.docs.adr)
    findings.extend(layer_findings(diffs, head_texts, architecture))
    findings.extend(dependency_findings(diffs, head_texts, architecture, adr_present=present))
    findings.extend(significance_findings(diffs, head_texts, architecture, adr_present=present))
    findings.extend(contract_findings(diffs, head_texts, base_texts))
    findings.extend(
        _scanner(
            "semgrep",
            config.analyzers.semgrep,
            semgrep_json,
            lambda payload: parse_semgrep(payload, diffs),
            coverage,
            which,
        )
    )
    gitleaks_findings = _scanner(
        "gitleaks",
        config.analyzers.gitleaks,
        gitleaks_json,
        lambda payload: parse_gitleaks(payload, diffs),
        coverage,
        which,
    )
    if gitleaks_findings:
        findings.extend(gitleaks_findings)
    elif gitleaks_json is None:
        findings.extend(builtin_secret_findings(diffs, head_texts))
    findings.extend(
        _scanner(
            "osv-scanner",
            config.analyzers.osv,
            osv_json,
            lambda payload: parse_osv(
                payload,
                added_names=added_dependency_names(diffs, head_texts),
                files=head_texts,
            ),
            coverage,
            which,
        )
    )
    query = " ".join(diff.path for diff in diffs)
    retrieved = retrieve(query, documents)
    return Analysis(findings=tuple(findings), coverage=tuple(coverage), retrieved=retrieved)


def _scanner(
    name: str,
    mode: str,
    payload: str | None,
    parse: Callable[[str], tuple[Finding, ...]],
    coverage: list[CoverageNote],
    which: Callable[[str], str | None],
) -> tuple[Finding, ...]:
    if payload is not None:
        coverage.append(CoverageNote(name, "ran", "parsed supplied output"))
        return parse(payload)
    note = binary_note(name, mode, which=which)
    if note is not None:
        coverage.append(note)
        return ()
    coverage.append(CoverageNote(name, "skipped", "binary present; no scanner output supplied"))
    return ()
