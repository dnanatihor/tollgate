"""Normalise a unified diff into the review model."""

from __future__ import annotations

from unidiff.patch import PatchedFile, PatchSet

from tollgate.models import DiffFile, DiffLine, Hunk


def parse_unified_diff(text: str) -> tuple[DiffFile, ...]:
    """Parse git's unified diff, including rename, binary, and deletion headers."""
    if not text.strip():
        return ()
    binary_paths = _binary_paths(text)
    patch = PatchSet(text)
    files: list[DiffFile] = []
    for patched in patch:
        path, old_path = _paths(patched)
        if path in binary_paths or old_path in binary_paths:
            files.append(
                DiffFile(
                    path=path,
                    old_path=old_path,
                    status="binary",
                    binary=True,
                )
            )
            continue
        if patched.is_removed_file:
            status = "deleted"
        elif patched.is_rename:
            status = "renamed"
        elif patched.is_added_file:
            status = "added"
        else:
            status = "modified"
        files.append(
            DiffFile(
                path=path,
                old_path=old_path if old_path != path else None,
                status=status,  # type: ignore[arg-type]
                hunks=tuple(_hunks(patched)),
            )
        )
    return tuple(files)


def _binary_paths(text: str) -> set[str]:
    paths: set[str] = set()
    sections = text.split("diff --git ")
    for section in sections[1:]:
        if "GIT binary patch" not in section and not section.startswith("Binary files"):
            header, _, body = section.partition("\n")
            if "Binary files " not in body and not body.startswith("Binary files"):
                continue
        header = section.split("\n", 1)[0]
        quoted = header.split()
        if len(quoted) >= 2:
            paths.add(_strip_prefix(quoted[-1]))
            paths.add(_strip_prefix(quoted[0]))
    return {path for path in paths if path and path != "/dev/null"}


def _paths(patched: PatchedFile) -> tuple[str, str | None]:
    target = _strip_prefix(patched.target_file or patched.path)
    source = _strip_prefix(patched.source_file or "")
    if target in {"", "/dev/null"}:
        target = source
    old: str | None = source if source not in {"", "/dev/null", target} else None
    return target, old


def _strip_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _hunks(patched: PatchedFile) -> list[Hunk]:
    hunks: list[Hunk] = []
    for hunk in patched:
        lines: list[DiffLine] = []
        for line in hunk:
            kind = line.line_type
            if kind not in {"+", "-", " "}:
                continue
            text = line.value[:-1] if line.value.endswith("\n") else line.value
            lines.append(
                DiffLine(
                    kind=kind,  # type: ignore[arg-type]
                    text=text,
                    old_line=line.source_line_no,
                    new_line=line.target_line_no,
                )
            )
        hunks.append(
            Hunk(
                old_start=hunk.source_start,
                old_lines=hunk.source_length,
                new_start=hunk.target_start,
                new_lines=hunk.target_length,
                lines=tuple(lines),
            )
        )
    return hunks
