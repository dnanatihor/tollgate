"""Spec gaps that do not need a live platform or a real model."""

from __future__ import annotations

import json
import math

import httpx
import pytest

from tollgate.analyzers.run import analyze
from tollgate.architecture_pr import ArchitectureAssessment, keep_known_paths
from tollgate.config import ArchitectureConfig, TollgateConfig
from tollgate.models import DiffFile, DiffLine, Finding, Hunk, Verdict
from tollgate.planner import estimate_tokens
from tollgate.rank import rank_findings
from tollgate.render.summary import render_markdown
from tollgate.scm.bitbucket_dc import finding_line_types
from tollgate.scm.github import GitHubProvider
from tollgate.suppress import apply_suppressions
from tollgate.verify import fingerprint


def _finding(
    *,
    evidence: str = "query = q",
    line: int = 2,
    severity: str = "high",
    status: str = "active",
    reason: str | None = None,
    path: str = "app/orders.py",
) -> Finding:
    return Finding(
        fingerprint=fingerprint("security", path, evidence, "CWE-89"),
        lens="security",
        title="SQL injection",
        severity=severity,  # type: ignore[arg-type]
        confidence="high",
        file=path,
        start_line=line,
        end_line=line,
        evidence=evidence,
        explanation="Concatenated SQL.",
        recommendation="Parameterise the query.",
        standards=("CWE-89",),
        sources=("llm:security",),
        corroborated=False,
        status=status,  # type: ignore[arg-type]
        status_reason=reason,
    )


def test_dismissed_findings_stay_in_the_report_and_do_not_block() -> None:
    active = _finding(evidence="active line")
    dismissed = _finding(
        evidence="dismissed line",
        status="dismissed_by_critic",
        reason="not introduced by this change",
    )
    ranked = rank_findings([active, dismissed], TollgateConfig())
    text = render_markdown(ranked, Verdict(outcome="concerns"))
    assert "Dismissed" in text
    assert "not introduced by this change" in text
    assert ranked.findings == (active,)


def test_new_ignore_is_capped_and_base_ignore_is_not() -> None:
    added = _finding(severity="critical")
    kept = apply_suppressions(
        [added],
        head_texts={"app/orders.py": "query = q  # tollgate-ignore: CWE-89 accepted risk\n"},
        base_texts={"app/orders.py": "query = q\n"},
        baseline=set(),
        config=TollgateConfig(),
    )
    assert kept[0].status == "active"
    medium = _finding(severity="medium", evidence="page = n")
    limited = apply_suppressions(
        [medium],
        head_texts={"app/orders.py": "page = n  # tollgate-ignore: CWE-89 accepted risk\n"},
        base_texts={},
        baseline=set(),
        config=TollgateConfig(),
    )
    assert limited[0].status_reason == "suppressed in this PR"
    listed = rank_findings(limited, TollgateConfig())
    assert listed.suppressed_in_pr == (limited[0],)
    based = apply_suppressions(
        [_finding(severity="critical")],
        head_texts={"app/orders.py": "query = q  # tollgate-ignore: CWE-89 existing\n"},
        base_texts={"app/orders.py": "query = q  # tollgate-ignore: CWE-89 existing\n"},
        baseline=set(),
        config=TollgateConfig(),
    )
    assert based[0].status == "suppressed"
    assert based[0].status_reason == "baseline"


def test_baseline_fingerprint_suppresses() -> None:
    finding = _finding()
    updated = apply_suppressions(
        [finding],
        head_texts={},
        base_texts={},
        baseline={finding.fingerprint},
        config=TollgateConfig(),
    )
    assert updated[0].status == "suppressed"


def test_architecture_drops_unknown_paths_and_caps_questions() -> None:
    raw = ArchitectureAssessment.model_validate(
        {
            "intent": "Add a store.",
            "significant_changes": [
                {
                    "description": "db",
                    "files": ["app/db.py", "missing.py"],
                    "trigger": "new_datastore",
                }
            ],
            "adr": {
                "required": True,
                "present_in_pr": False,
                "conflicts": [{"adr_path": "docs/nope.md", "explanation": "gone"}],
            },
            "principle_concerns": [
                {"standard": "ORG:P02", "explanation": "sync", "files": ["app/db.py", "nope.py"]}
            ],
            "risks": [],
            "questions_for_author": ["one", "two", "three", "four"],
        }
    )
    kept = keep_known_paths(raw, files={"app/db.py"}, documents={"docs/adr/0001.md"})
    assert kept.significant_changes[0].files == ["app/db.py"]
    assert kept.adr.conflicts == []
    assert kept.principle_concerns[0].files == ["app/db.py"]
    assert kept.questions_for_author == ["one", "two", "three"]


def test_line_type_comes_from_the_diff() -> None:
    added = _finding(line=2, evidence="added")
    context = _finding(line=3, evidence="context", path="app/orders.py")
    # Fingerprints differ by evidence, so both can sit on the same path.
    diff = DiffFile(
        path="app/orders.py",
        status="modified",
        hunks=(
            Hunk(
                old_start=1,
                old_lines=2,
                new_start=1,
                new_lines=3,
                lines=(
                    DiffLine(kind=" ", text="def charge():", old_line=1, new_line=1),
                    DiffLine(kind="+", text="added", old_line=None, new_line=2),
                    DiffLine(kind=" ", text="context", old_line=2, new_line=3),
                ),
            ),
        ),
    )
    kinds = finding_line_types((diff,), (added, context))
    assert kinds[added.fingerprint] == "ADDED"
    assert kinds[context.fingerprint] == "CONTEXT"


@pytest.mark.asyncio
async def test_check_annotations_are_batched_at_50() -> None:
    findings = tuple(
        _finding(evidence=f"line {index}", line=index + 1, path=f"app/{index}.py")
        for index in range(51)
    )
    bodies: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(201, json={"id": 1})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="https://api.github.com") as client:
        provider = GitHubProvider(client, owner="acme", repo="app", read_only=False)
        await provider.set_status(
            "abc", Verdict(outcome="block"), "summary", mode="status", findings=findings
        )
    assert len(bodies) == 2
    assert isinstance(bodies[0], dict)
    assert isinstance(bodies[1], dict)
    first = bodies[0]["output"]["annotations"]
    second = bodies[1]["output"]["annotations"]
    assert len(first) == 50
    assert len(second) == 1


def test_scanner_output_is_parsed_when_the_binary_exists() -> None:
    diff = DiffFile(
        path="app/orders.py",
        status="added",
        hunks=(
            Hunk(
                old_start=0,
                old_lines=0,
                new_start=1,
                new_lines=1,
                lines=(DiffLine(kind="+", text='query = "SELECT" + user', new_line=1),),
            ),
        ),
    )
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

    def execute(name: str, _diffs: tuple[DiffFile, ...], _texts: dict[str, str]) -> str | None:
        return payload if name == "semgrep" else "[]"

    analysis = analyze(
        (diff,),
        head_texts={"app/orders.py": 'query = "SELECT" + user\n'},
        base_texts={},
        architecture=ArchitectureConfig(),
        config=TollgateConfig(),
        which=lambda _name: "/usr/bin/" + _name,
        execute=execute,
    )
    assert any(item.sources[0].startswith("semgrep:") for item in analysis.findings)
    assert any(note.status == "ran" and note.analyzer == "semgrep" for note in analysis.coverage)


def test_tiktoken_count_is_used_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tollgate.planner._tiktoken_count", lambda _text, _model: 10)
    assert estimate_tokens("abcd", model="openai:gpt-4o") == math.ceil(10 * 1.15)
