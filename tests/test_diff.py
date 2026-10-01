"""Diff edge cases from SPEC.md §15."""

from __future__ import annotations

import subprocess
from pathlib import Path

from tests.git_repo import commit, git, init_repo, write

from tollgate.diff import parse_unified_diff
from tollgate.models import DiffFile


def _diff(repo: Path, base: str = "HEAD~1", head: str = "HEAD") -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "-c",
            "core.autocrlf=false",
            "diff",
            "--no-color",
            "-M",
            base,
            head,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return completed.stdout.decode("utf-8")


def _file(files: tuple[DiffFile, ...], path: str) -> DiffFile:
    return next(item for item in files if item.path == path)


def test_rename_deletion_binary_and_multiple_hunks(tmp_path: Path) -> None:
    init_repo(tmp_path)
    write(tmp_path, "old.py", "\n".join(f"line {index}" for index in range(40)) + "\n")
    write(tmp_path, "drop.py", "gone\n")
    write(tmp_path, "wide.py", "\n".join(f"row {index}" for index in range(80)) + "\n")
    commit(tmp_path, "base")

    git(tmp_path, "mv", "old.py", "renamed.py")
    write(
        tmp_path,
        "renamed.py",
        "\n".join(f"line {index}" for index in range(40)).replace("line 10", "line ten") + "\n",
    )
    (tmp_path / "drop.py").unlink()
    git(tmp_path, "add", "-A")
    wide = "\n".join(f"row {index}" for index in range(80))
    wide = wide.replace("row 2", "row two").replace("row 70", "row seventy")
    write(tmp_path, "wide.py", wide + "\n")
    write(tmp_path, "blob.bin", b"\x00\x01\x02not-text")
    commit(tmp_path, "head")

    files = parse_unified_diff(_diff(tmp_path))
    renamed = _file(files, "renamed.py")
    assert renamed.status == "renamed"
    assert renamed.old_path == "old.py"
    assert any(
        line.kind == "+" and "line ten" in line.text
        for hunk in renamed.hunks
        for line in hunk.lines
    )

    deleted = _file(files, "drop.py")
    assert deleted.status == "deleted"

    wide = _file(files, "wide.py")
    assert len(wide.hunks) >= 2

    binary = _file(files, "blob.bin")
    assert binary.status == "binary"
    assert binary.hunks == ()


def test_no_newline_crlf_and_long_line(tmp_path: Path) -> None:
    init_repo(tmp_path)
    write(tmp_path, "note.txt", "hello\n")
    write(tmp_path, "crlf.txt", "alpha\r\nbeta\r\n")
    commit(tmp_path, "base")

    (tmp_path / "note.txt").write_bytes(b"hello")
    long_line = "L" * 20000
    write(tmp_path, "crlf.txt", "alpha\r\nbeta-2\r\n")
    write(tmp_path, "long.py", f"value = '{long_line}'\n")
    commit(tmp_path, "head")

    files = parse_unified_diff(_diff(tmp_path))
    note = _file(files, "note.txt")
    texts = [line.text for hunk in note.hunks for line in hunk.lines]
    assert any(text == "hello" for text in texts)
    assert all("No newline" not in text for text in texts)

    crlf = _file(files, "crlf.txt")
    crlf_text = "\n".join(line.text for hunk in crlf.hunks for line in hunk.lines)
    assert "beta-2" in crlf_text
    assert "\r" in crlf_text

    long_file = _file(files, "long.py")
    joined = "".join(line.text for hunk in long_file.hunks for line in hunk.lines)
    assert long_line in joined
