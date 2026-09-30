"""Load and validate the versioned catalogs in ``standards/`` (SPEC.md §6)."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tollgate.errors import ConfigError

PREFIXES: dict[str, str] = {
    "owasp-web-2025": "OWASP-WEB-2025",
    "owasp-web-2021": "OWASP-WEB-2021",
    "owasp-api-2023": "OWASP-API-2023",
    "owasp-llm-2025": "OWASP-LLM-2025",
}

ID_PATTERNS: dict[str, str] = {
    "owasp-web-2025": r"A(0[1-9]|10)",
    "owasp-web-2021": r"A(0[1-9]|10)",
    "owasp-api-2023": r"API([1-9]|10)",
    "owasp-llm-2025": r"LLM(0[1-9]|10)",
    "cwe": r"CWE-[1-9][0-9]*",
    "tollgate-perf": r"TG-PERF-[0-9]{3}",
    "tollgate-arch": r"TG-ARCH-[0-9]{3}",
}

_REQUIRED = ("id", "name", "summary", "related_cwe", "source_url", "retrieved")


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    catalog: str
    id: str
    qualified_id: str
    name: str
    summary: str
    related_cwe: tuple[str, ...]
    source_url: str
    retrieved: dt.date


def standards_directory() -> Path:
    """Locate catalogs for an editable checkout or an installed wheel."""
    packaged = Path(__file__).resolve().parent / "standards_data"
    if (packaged / "owasp-web-2025.yaml").is_file():
        return packaged
    repo = Path(__file__).resolve().parents[2] / "standards"
    if (repo / "owasp-web-2025.yaml").is_file():
        return repo
    cwd = Path.cwd()
    for parent in (cwd, *cwd.parents):
        candidate = parent / "standards"
        if (candidate / "owasp-web-2025.yaml").is_file():
            return candidate
    raise ConfigError("standards", "standards catalogs were not found")


def qualified_id(catalog: str, entry_id: str) -> str:
    prefix = PREFIXES.get(catalog)
    if prefix is None:
        return entry_id
    return f"{prefix}:{entry_id}"


def parse_catalog(catalog: str, raw: Any) -> tuple[CatalogEntry, ...]:
    if catalog not in ID_PATTERNS:
        raise ConfigError("catalog", f"unknown catalog {catalog!r}")
    if not isinstance(raw, list):
        raise ConfigError(catalog, "catalog file must be a list of entries")
    entries: list[CatalogEntry] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        key = f"{catalog}[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(key, "entry must be a mapping")
        extra = sorted(set(item) - set(_REQUIRED))
        missing = [field for field in _REQUIRED if field not in item]
        if missing:
            raise ConfigError(f"{key}.{missing[0]}", "required field is missing")
        if extra:
            raise ConfigError(f"{key}.{extra[0]}", "unknown field")
        entry_id = _require_str(item["id"], f"{key}.id")
        pattern = ID_PATTERNS[catalog]
        if re.fullmatch(pattern, entry_id) is None:
            raise ConfigError(f"{key}.id", f"{entry_id!r} does not match {pattern}")
        if entry_id in seen:
            raise ConfigError(f"{key}.id", f"duplicate id {entry_id}")
        seen.add(entry_id)
        name = _require_str(item["name"], f"{key}.name")
        summary = _require_str(item["summary"], f"{key}.summary")
        source_url = _require_str(item["source_url"], f"{key}.source_url")
        if not source_url.startswith("https://"):
            raise ConfigError(f"{key}.source_url", "source_url must be an https URL")
        related = _require_cwe_list(item["related_cwe"], f"{key}.related_cwe")
        retrieved = _require_date(item["retrieved"], f"{key}.retrieved")
        entries.append(
            CatalogEntry(
                catalog=catalog,
                id=entry_id,
                qualified_id=qualified_id(catalog, entry_id),
                name=name,
                summary=summary,
                related_cwe=related,
                source_url=source_url,
                retrieved=retrieved,
            )
        )
    return tuple(entries)


def load_catalogs(directory: Path | None = None) -> dict[str, tuple[CatalogEntry, ...]]:
    root = directory if directory is not None else standards_directory()
    catalogs: dict[str, tuple[CatalogEntry, ...]] = {}
    seen_qualified: set[str] = set()
    for path in sorted(root.glob("*.yaml")):
        catalog = path.stem
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = parse_catalog(catalog, raw)
        for entry in entries:
            if entry.qualified_id in seen_qualified:
                raise ConfigError(entry.qualified_id, "duplicate qualified id")
            seen_qualified.add(entry.qualified_id)
        catalogs[catalog] = entries
    if not catalogs:
        raise ConfigError("standards", f"no catalog files in {root}")
    _require_related_cwe_exist(catalogs)
    return catalogs


def render_standards_list(
    catalogs: dict[str, tuple[CatalogEntry, ...]],
    *,
    organisation: tuple[str, ...] = (),
    only: str | None = None,
) -> str:
    names = list(catalogs)
    if only is not None:
        if only != "organisation" and only not in catalogs:
            raise ConfigError("catalog", f"unknown catalog {only!r}")
        names = [only] if only in catalogs else []
    lines: list[str] = []
    for name in names:
        entries = catalogs[name]
        lines.append(f"{name} ({len(entries)})")
        for entry in entries:
            lines.append(f"  {entry.qualified_id}  {entry.name}")
    if only is None or only == "organisation":
        lines.append(f"organisation ({len(organisation)})")
        for org_id in organisation:
            lines.append(f"  {org_id}")
    return "\n".join(lines) + "\n"


def _require_related_cwe_exist(catalogs: dict[str, tuple[CatalogEntry, ...]]) -> None:
    known = {entry.id for entry in catalogs.get("cwe", ())}
    for entries in catalogs.values():
        for entry in entries:
            for cwe in entry.related_cwe:
                if cwe not in known:
                    raise ConfigError(
                        f"{entry.qualified_id}.related_cwe",
                        f"{cwe} is not in cwe.yaml",
                    )


def _require_str(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(key, "must be a non-empty string")
    return value.strip()


def _require_cwe_list(value: Any, key: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(key, "must be a list")
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.startswith("CWE-"):
            raise ConfigError(f"{key}[{index}]", "must be a CWE id")
        items.append(item)
    return tuple(items)


def _require_date(value: Any, key: str) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError as exc:
            raise ConfigError(key, "must be YYYY-MM-DD") from exc
    raise ConfigError(key, "must be YYYY-MM-DD")
