"""Run eval cases with the scripted model and write a report."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

_SEVERITY = ("info", "low", "medium", "high", "critical")


def main(cases_root: Path | None = None) -> None:
    root = Path(__file__).resolve().parents[1]
    cases = _cases(cases_root or root / "eval" / "cases")
    rows = [_run(root, case) for case in cases]
    report = _report(rows)
    destination = root / "eval" / "reports" / "latest.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if any(not row["matched"] for row in rows if row["kind"] == "seeded"):
        raise SystemExit(1)


def _cases(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or path.name.startswith("_"):
            continue
        expected = path / "expected.yaml"
        if not expected.is_file():
            continue
        if (path / "semgrep.json").is_file() or (path / "osv.json").is_file():
            continue
        document = yaml.safe_load(expected.read_text(encoding="utf-8"))
        if (path / "scripted.json").is_file() or document.get("deterministic"):
            found.append(path)
    return found


def _run(repo_root: Path, case: Path) -> dict[str, object]:
    work = Path("/tmp") / "tollgate-eval" / case.name
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(case / "base", work)
    _git(work, "init", "-b", "main")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "base")
    _git(work, "checkout", "-b", "pr")
    patch = (case / "change.patch").read_text(encoding="utf-8")
    if patch.strip():
        applied = subprocess.run(
            [
                "git",
                "-c",
                "user.email=dev@example.com",
                "-c",
                "user.name=Tollgate Dev",
                "apply",
                "-",
            ],
            cwd=work,
            input=patch,
            text=True,
            capture_output=True,
            check=False,
        )
        if applied.returncode != 0:
            raise RuntimeError(applied.stderr)
        _git(work, "add", "-A")
        _git(work, "commit", "-m", "change")
    env = os.environ.copy()
    scripted = case / "scripted.json"
    if scripted.is_file():
        env["TOLLGATE_SCRIPTED"] = str(scripted)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tollgate",
            "review",
            "--local",
            "--base",
            "main",
            "--head",
            "pr",
            "--format",
            "json",
        ],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(completed.stderr or completed.stdout)
    payload = _json_payload(completed.stdout)
    findings = payload.get("findings", [])
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    matched = all(_matched(findings, item) for item in expected.get("expect") or [])
    forbidden = _forbidden(findings, expected.get("must_not") or [])
    kind = "clean" if expected.get("expect") in ([], None) else "seeded"
    return {
        "id": case.name,
        "lens": expected.get("lens", ""),
        "kind": kind,
        "matched": matched and not forbidden,
        "published": len(findings) if isinstance(findings, list) else 0,
        "expected": len(expected.get("expect") or []),
    }


def _report(rows: list[dict[str, object]]) -> dict[str, object]:
    seeded = [row for row in rows if row["kind"] == "seeded"]
    clean = [row for row in rows if row["kind"] == "clean"]
    by_lens: dict[str, dict[str, int]] = {}
    for row in seeded:
        lens = str(row["lens"])
        bucket = by_lens.setdefault(lens, {"expected": 0, "matched": 0, "published": 0})
        bucket["expected"] += int(row["expected"])
        bucket["matched"] += 1 if row["matched"] else 0
        bucket["published"] += int(row["published"])
    recall = {
        lens: (values["matched"] / values["expected"] if values["expected"] else 0)
        for lens, values in by_lens.items()
    }
    precision = {
        lens: (values["matched"] / values["published"] if values["published"] else 1)
        for lens, values in by_lens.items()
    }
    false_positives = sum(int(row["published"]) for row in clean)
    return {
        "model": "scripted:test",
        "seeded": len(seeded),
        "clean": len(clean),
        "recall_by_lens": recall,
        "precision_by_lens": precision,
        "clean_false_positives": false_positives,
        "inline_comments_per_pr": 0,
        "cost_usd_per_pr": 0,
        "critic": {
            "note": (
                "Default stays on for high and above. A rejected finding is dismissed "
                "and cannot block; see tests/test_critic.py."
            ),
            "default_enabled": True,
        },
    }


def _matched(findings: object, expected: dict[str, object]) -> bool:
    if not isinstance(findings, list):
        return False
    standards = set(expected["standards_any"])  # type: ignore[arg-type]
    floor = str(expected["min_severity"])
    start, end = expected["lines"]  # type: ignore[misc]
    assert isinstance(start, int) and isinstance(end, int)
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("file") != expected["file"]:
            continue
        cited = set(finding.get("standards") or [])
        if not standards.intersection(cited):
            continue
        severity = str(finding.get("severity"))
        if _SEVERITY.index(severity) < _SEVERITY.index(floor):
            continue
        line = int(finding.get("start_line") or 0)
        if start - 3 <= line <= end + 3:
            return True
    return False


def _forbidden(findings: object, rules: list[dict[str, object]]) -> bool:
    if not isinstance(findings, list):
        return True
    for rule in rules:
        floor = str(rule["min_severity"])
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity"))
            if _SEVERITY.index(severity) >= _SEVERITY.index(floor):
                return True
    return False


def _json_payload(stdout: str) -> dict[str, object]:
    start = stdout.find("{")
    if start < 0:
        raise RuntimeError(stdout)
    loaded = json.loads(stdout[start:])
    if not isinstance(loaded, dict):
        raise RuntimeError("review JSON must be an object")
    return loaded


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=dev@example.com",
            "-c",
            "user.name=Tollgate Dev",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    main()
