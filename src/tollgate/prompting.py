"""Render versioned Jinja2 lens prompts."""

from __future__ import annotations

from pathlib import Path

from jinja2 import StrictUndefined, Template

from tollgate.models import ReviewUnit
from tollgate.standards import CatalogEntry

CHECKLISTS: dict[str, str] = {
    "security": (
        "Broken access control; injection; SSRF; path traversal; insecure deserialisation; "
        "authentication and session flaws; cryptographic failures; security misconfiguration; "
        "software supply chain; integrity failures; logging failures; mishandled errors; "
        "unrestricted resource consumption."
    ),
    "llm_security": (
        "Prompt injection; sensitive data sent to a model; unpinned or remote model loading; "
        "unvalidated training or retrieval data; model output passed to a sink; tools that "
        "write or delete without confirmation; secrets in system prompts; retrieval without "
        "an access filter; ungrounded high-stakes output; model calls without limits."
    ),
    "architecture": (
        "Layer violations; hold or assess dependencies; missing ADRs; API guideline breaks; "
        "breaking contracts; outbound calls without timeout; missing operational signals; "
        "hard-coded configuration; crossed tenant or classification boundaries."
    ),
    "performance": (
        "N+1 queries; unbounded queries; blocking work on an event loop; quadratic scans; "
        "catastrophic regular expressions; whole-resource loads; repeated expensive calls; "
        "heavy logging on hot paths; unindexed predicates; synchronous remote call chains."
    ),
}

PROMPT_NAMES = {
    "security": "security.v1.md",
    "llm_security": "llm_security.v1.md",
    "architecture": "architecture_unit.v1.md",
    "performance": "performance.v1.md",
}


def prompts_directory() -> Path:
    packaged = Path(__file__).resolve().parent / "prompts_data"
    if (packaged / "security.v1.md").is_file():
        return packaged
    repo = Path(__file__).resolve().parents[2] / "prompts"
    if (repo / "security.v1.md").is_file():
        return repo
    cwd = Path.cwd()
    for parent in (cwd, *cwd.parents):
        candidate = parent / "prompts"
        if (candidate / "security.v1.md").is_file():
            return candidate
    raise FileNotFoundError("prompts directory")


def render_named(name: str, values: dict[str, str]) -> tuple[str, str]:
    text = (prompts_directory() / f"{name}.v1.md").read_text(encoding="utf-8")
    system, user = _split(text)
    return _render(system, values), _render(user, values)


def render_lens_prompt(
    lens: str,
    unit: ReviewUnit,
    *,
    entries: tuple[CatalogEntry, ...],
    extra_ids: tuple[str, ...] = (),
    pr_title: str = "",
    pr_description: str = "",
    analyzer_results_json: str = "[]",
) -> tuple[str, str]:
    text = (prompts_directory() / PROMPT_NAMES[lens]).read_text(encoding="utf-8")
    system, user = _split(text)
    values = {
        "checklist": CHECKLISTS[lens],
        "allowed_ids": _ids(entries, extra_ids),
        "pr_title": pr_title,
        "pr_description": pr_description,
        "path": unit.path,
        "language": unit.language,
        "role": unit.role,
        "annotated_hunks": unit.annotated_hunks,
        "structural_context": unit.structural_context,
        "analyzer_results_json": analyzer_results_json,
    }
    return _render(system, values), _render(user, values)


def _ids(entries: tuple[CatalogEntry, ...], extra: tuple[str, ...]) -> str:
    names = [f"{entry.qualified_id} {entry.name}" for entry in entries]
    names.extend(extra)
    return ", ".join(names)


def _split(text: str) -> tuple[str, str]:
    system, _, user = text.partition("\n## user\n")
    system = system.removeprefix("## system\n")
    return system.strip(), user.strip()


def _render(text: str, values: dict[str, str]) -> str:
    rendered = Template(text, undefined=StrictUndefined).render(**values)
    return str(rendered)
