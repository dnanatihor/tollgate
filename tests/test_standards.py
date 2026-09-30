"""Catalog validation and ``tollgate standards list`` (SPEC.md §6, Phase 0)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tollgate.errors import ConfigError
from tollgate.standards import (
    load_catalogs,
    parse_catalog,
    render_standards_list,
    standards_directory,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ("id", "name", "summary", "related_cwe", "source_url", "retrieved")


def test_shipped_catalogs_have_unique_ids_and_required_fields() -> None:
    catalogs = load_catalogs()
    assert set(catalogs) == {
        "cwe",
        "owasp-api-2023",
        "owasp-llm-2025",
        "owasp-web-2021",
        "owasp-web-2025",
        "tollgate-arch",
        "tollgate-perf",
    }
    qualified: set[str] = set()
    for catalog, entries in catalogs.items():
        raw = yaml.safe_load(
            (standards_directory() / f"{catalog}.yaml").read_text(encoding="utf-8")
        )
        assert isinstance(raw, list)
        ids: set[str] = set()
        for item in raw:
            assert isinstance(item, dict)
            for field in REQUIRED:
                assert field in item
                if field == "related_cwe":
                    assert isinstance(item[field], list)
                else:
                    assert item[field] not in (None, "")
        for entry in entries:
            assert entry.id not in ids
            ids.add(entry.id)
            assert entry.qualified_id not in qualified
            qualified.add(entry.qualified_id)
            assert entry.summary
            assert entry.source_url.startswith("https://")
    assert "OWASP-WEB-2025:A05" in qualified
    assert "OWASP-WEB-2021:A03" in qualified
    assert "OWASP-API-2023:API1" in qualified
    assert "OWASP-LLM-2025:LLM01" in qualified
    assert "CWE-89" in qualified
    assert "TG-PERF-001" in qualified
    assert "TG-ARCH-001" in qualified


def test_duplicate_catalog_id_is_rejected() -> None:
    raw = [
        {
            "id": "A01",
            "name": "One",
            "summary": "First.",
            "related_cwe": [],
            "source_url": "https://owasp.org/Top10/2025/",
            "retrieved": "2026-09-30",
        },
        {
            "id": "A01",
            "name": "Again",
            "summary": "Second.",
            "related_cwe": [],
            "source_url": "https://owasp.org/Top10/2025/",
            "retrieved": "2026-09-30",
        },
    ]
    with pytest.raises(ConfigError, match="duplicate id") as caught:
        parse_catalog("owasp-web-2025", raw)
    assert caught.value.key.endswith(".id")


def test_standards_list_prints_every_catalog() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "tollgate", "standards", "list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout
    for name in (
        "owasp-web-2025",
        "owasp-web-2021",
        "owasp-api-2023",
        "owasp-llm-2025",
        "cwe",
        "tollgate-perf",
        "tollgate-arch",
        "organisation",
    ):
        assert name in output
    assert "OWASP-WEB-2025:A05" in output
    assert "ORG:P02" in output
    assert "ORG:G01" in output


def test_standards_list_can_filter_one_catalog() -> None:
    catalogs = load_catalogs()
    text = render_standards_list(catalogs, only="owasp-web-2025")
    assert "OWASP-WEB-2025:A01" in text
    assert "OWASP-API-2023" not in text
    assert "organisation" not in text


def test_unknown_catalog_names_the_key() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "tollgate", "standards", "list", "--catalog", "missing"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "catalog" in completed.stderr
    assert "missing" in completed.stderr
