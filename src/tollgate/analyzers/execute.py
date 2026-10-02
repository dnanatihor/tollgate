"""Run Semgrep, gitleaks, and OSV-Scanner when the binary is installed.

The pull request's own code is never built or executed. A scanner failure is a
coverage note from the caller, not a review failure.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from tollgate.models import DiffFile

Scanner = Callable[[str, tuple[DiffFile, ...], dict[str, str]], str | None]


def execute_scanner(
    name: str,
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
) -> str | None:
    command = _command(name, diffs, head_texts)
    if command is None:
        return None
    stdin = _diff_text(diffs) if name == "gitleaks" else None
    try:
        completed = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in {0, 1} and not completed.stdout.strip():
        return None
    return completed.stdout


def _command(
    name: str,
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
) -> list[str] | None:
    paths = [diff.path for diff in diffs if diff.status != "deleted" and diff.path in head_texts]
    if name == "semgrep":
        if not paths:
            return None
        return [
            "semgrep",
            "scan",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            "--json",
            "--config",
            "p/owasp",
            *paths,
        ]
    if name == "gitleaks":
        return ["gitleaks", "detect", "--pipe", "--report-format", "json", "--report-path", "-"]
    if name == "osv-scanner":
        manifests = [path for path in paths if _is_manifest(path)]
        if not manifests:
            return None
        command = ["osv-scanner", "scan", "--format", "json"]
        for path in manifests:
            command.extend(["-L", path])
        return command
    return None


def _is_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in {"requirements.txt", "package.json", "pyproject.toml", "go.mod", "Cargo.lock"}


def _diff_text(diffs: tuple[DiffFile, ...]) -> str:
    chunks: list[str] = []
    for diff in diffs:
        chunks.append(f"diff --git a/{diff.path} b/{diff.path}")
        for hunk in diff.hunks:
            chunks.append(
                f"@@ -{hunk.old_start},{hunk.old_lines} +{hunk.new_start},{hunk.new_lines} @@"
            )
            chunks.extend(f"{line.kind}{line.text}" for line in hunk.lines)
    return "\n".join(chunks) + "\n"
