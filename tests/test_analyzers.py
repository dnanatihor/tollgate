"""Deterministic rules, scanner coverage, and secret-free prompts."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from tests.git_repo import commit, git, init_repo

from tollgate.analyzers.contracts import contract_findings
from tollgate.analyzers.deps import dependency_findings
from tollgate.analyzers.retrieval import retrieve
from tollgate.analyzers.run import analyze
from tollgate.analyzers.triage import triage_semgrep
from tollgate.classify import classify_changes
from tollgate.config import ArchitectureConfig, TollgateConfig
from tollgate.diff import parse_unified_diff
from tollgate.llm.scripted import ScriptedChat
from tollgate.models import DiffFile, DiffLine, Finding, Hunk
from tollgate.planner import build_plan
from tollgate.sources.local_git import load_local_git

SECRET = "s3cr3t-value-should-not-leak"
_SEVERITY = ("info", "low", "medium", "high", "critical")
CASES = (
    "arch-layer",
    "tech-radar-hold",
    "significance-no-adr",
    "openapi-break",
    "migration-drop",
    "semgrep-sqli",
    "secret-added",
    "osv-added",
)
ROOT = Path(__file__).resolve().parents[1] / "eval" / "cases"


@pytest.mark.asyncio
@pytest.mark.parametrize("case_name", CASES)
async def test_eval_case_produces_expected_finding(tmp_path: Path, case_name: str) -> None:
    case = ROOT / case_name
    repo = _materialize(tmp_path, case)
    snapshot = load_local_git(repo, base_ref="main", head_ref="pr")
    diffs = parse_unified_diff(snapshot.diff_text)
    head = {item.path: snapshot.read_text(item.path, snapshot.head_sha) for item in diffs}
    base = {item.path: snapshot.read_text(item.path, snapshot.merge_base) for item in diffs}
    architecture = ArchitectureConfig.model_validate(
        yaml.safe_load((case / "base" / ".tollgate" / "architecture.yaml").read_text())
    )
    analysis = analyze(
        diffs,
        head_texts=head,
        base_texts=base,
        architecture=architecture,
        config=TollgateConfig(),
        semgrep_json=_optional(case / "semgrep.json"),
        osv_json=_optional(case / "osv.json"),
        which=lambda _name: None,
    )
    semgrep = [item for item in analysis.findings if item.sources[0].startswith("semgrep:")]
    reply = {
        "decisions": [
            {"fingerprint": item.fingerprint, "decision": "confirm", "reason": "anchored"}
            for item in semgrep
        ]
    }
    model = ScriptedChat([json.dumps(reply), "masked"])
    findings: tuple[Finding, ...]
    if semgrep:
        findings = await triage_semgrep(tuple(analysis.findings), model=model, annotated=head)
    else:
        findings = analysis.findings
        await model.complete("reviewer", "deterministic rules already decided")
    if case_name == "secret-added":
        classified = classify_changes(diffs, config=TollgateConfig(), attributes="", sources=head)
        plan = build_plan(classified, TollgateConfig())
        blob = "\n".join(unit.annotated_hunks + unit.structural_context for unit in plan.units)
        assert SECRET not in blob
        await model.complete("reviewer", blob)
    assert model.structured_calls or model.completions
    captured = " ".join(model.structured_calls)
    captured += " ".join(user for _system, user in model.completions)
    assert SECRET not in captured
    expected = yaml.safe_load((case / "expected.yaml").read_text())
    for item in expected["expect"]:
        assert _matched(findings, item), findings


def test_missing_binaries_are_coverage_notes() -> None:
    diff = _added("app.py", "print('ok')\n")
    analysis = analyze(
        (diff,),
        head_texts={"app.py": "print('ok')\n"},
        base_texts={},
        architecture=ArchitectureConfig(),
        config=TollgateConfig(),
        which=lambda _name: None,
    )
    assert {note.analyzer for note in analysis.coverage} == {"semgrep", "gitleaks", "osv-scanner"}
    assert {note.status for note in analysis.coverage} == {"missing"}
    assert analysis.findings == ()


@pytest.mark.asyncio
async def test_triage_rejection_does_not_block() -> None:
    diff = _added("app/orders.py", 'query = "SELECT" + user\n')
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.sqli",
                    "path": "app/orders.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "SQL injection", "metadata": {"cwe": ["CWE-89"]}},
                }
            ]
        }
    )
    analysis = analyze(
        (diff,),
        head_texts={"app/orders.py": 'query = "SELECT" + user\n'},
        base_texts={},
        architecture=ArchitectureConfig(),
        config=TollgateConfig(),
        semgrep_json=payload,
        which=lambda _name: None,
    )
    finding = analysis.findings[0]
    model = ScriptedChat(
        [
            json.dumps(
                {
                    "decisions": [
                        {
                            "fingerprint": finding.fingerprint,
                            "decision": "reject",
                            "reason": "test double, not production",
                        }
                    ]
                }
            )
        ]
    )
    triaged = await triage_semgrep(analysis.findings, model=model, annotated={})
    assert triaged[0].status == "dismissed_by_triage"
    from tollgate.verdict import decide

    assert decide(list(triaged), TollgateConfig()).outcome == "pass"


def test_assess_without_adr_and_protobuf_renumber() -> None:
    architecture = ArchitectureConfig.model_validate(
        {"tech_radar": {"assess": ["some-new-orm"], "hold": []}}
    )
    text = "some-new-orm==1.0\n"
    diff = _added("requirements.txt", text)
    found = dependency_findings(
        (diff,),
        {"requirements.txt": text},
        architecture,
        adr_present=False,
    )
    assert found[0].standards == ("TG-ARCH-002",)
    cleared = dependency_findings(
        (diff,),
        {"requirements.txt": text},
        architecture,
        adr_present=True,
    )
    assert cleared == ()
    before = 'syntax = "proto3";\nmessage Order {\n  string id = 1;\n}\n'
    after = 'syntax = "proto3";\nmessage Order {\n  string name = 1;\n}\n'
    renamed = _added("api.proto", after)
    breaks = contract_findings((renamed,), {"api.proto": after}, {"api.proto": before})
    assert breaks[0].standards == ("TG-ARCH-006",)


def test_bm25_retrieves_the_matching_adr() -> None:
    documents = (
        (
            "docs/adr/0007-events.md",
            "services integrate through events and avoid synchronous cross service calls",
        ),
        ("docs/adr/0001-database.md", "postgres stores orders and inventory"),
    )
    found = retrieve("synchronous event integration between services", documents)
    assert found[0] == "docs/adr/0007-events.md"


def _matched(findings: tuple[Finding, ...], expected: dict[str, object]) -> bool:
    standards = set(expected["standards_any"])  # type: ignore[arg-type]
    floor = str(expected["min_severity"])
    start, end = expected["lines"]  # type: ignore[misc]
    assert isinstance(start, int)
    assert isinstance(end, int)
    for finding in findings:
        if finding.status != "active" or finding.file != expected["file"]:
            continue
        if not standards.intersection(finding.standards):
            continue
        if _SEVERITY.index(finding.severity) < _SEVERITY.index(floor):
            continue
        line = finding.start_line or 0
        if line >= start - 3 and line <= end + 3:
            return True
    return False


def _materialize(tmp_path: Path, case: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(case / "base", repo)
    init_repo(repo)
    commit(repo, "base")
    git(repo, "checkout", "-b", "pr")
    completed = subprocess.run(
        ["git", "-c", "user.email=dev@example.com", "-c", "user.name=Tollgate Dev", "apply", "-"],
        cwd=repo,
        input=(case / "change.patch").read_text(encoding="utf-8"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    commit(repo, "change")
    git(repo, "rev-parse", "HEAD")
    return repo


def _optional(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _added(path: str, text: str) -> DiffFile:
    lines = tuple(
        DiffLine(kind="+", text=line, new_line=index, old_line=None)
        for index, line in enumerate(text.splitlines(), start=1)
    )
    return DiffFile(
        path=path,
        status="added",
        hunks=(Hunk(old_start=0, old_lines=0, new_start=1, new_lines=len(lines), lines=lines),),
    )
