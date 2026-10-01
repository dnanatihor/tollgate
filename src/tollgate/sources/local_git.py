"""Read a diff and file bytes from a local git checkout (SPEC.md §7.1)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class LocalGitSource:
    repo: Path
    base_ref: str
    head_ref: str
    merge_base: str
    head_sha: str
    diff_text: str

    def read_bytes(self, path: str, ref: str) -> bytes | None:
        result = _git(self.repo, "show", f"{ref}:{path}")
        if result.returncode != 0:
            return None
        return result.stdout

    def read_text(self, path: str, ref: str) -> str:
        payload = self.read_bytes(path, ref)
        if payload is None:
            return ""
        return payload.decode("utf-8", errors="replace")

    def gitattributes(self) -> str:
        return self.read_text(".gitattributes", self.base_ref)


def load_local_git(repo: Path, *, base_ref: str, head_ref: str) -> LocalGitSource:
    """Diff ``merge-base(base, head)`` to ``head``. Configuration stays on ``base_ref``."""
    root = repo.resolve()
    base_sha = _rev(root, base_ref)
    head_sha = _rev(root, head_ref)
    merge = _git(root, "merge-base", base_sha, head_sha)
    if merge.returncode != 0 or not merge.stdout.strip():
        merge_base = base_sha
    else:
        merge_base = merge.stdout.decode().strip()
    diff = _git(
        root,
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.quotepath=false",
        "diff",
        "--no-ext-diff",
        "--no-color",
        "-M",
        merge_base,
        head_sha,
    )
    if diff.returncode != 0:
        message = diff.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or "git diff failed")
    return LocalGitSource(
        repo=root,
        base_ref=base_ref,
        head_ref=head_ref,
        merge_base=merge_base,
        head_sha=head_sha,
        diff_text=diff.stdout.decode("utf-8", errors="replace"),
    )


def _rev(repo: Path, ref: str) -> str:
    result = _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"git ref not found: {ref}")
    return result.stdout.decode().strip()


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        check=False,
    )
