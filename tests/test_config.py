"""Configuration loading from the base ref, org merge, and exit code 2."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from tollgate.config import load_config, organisation_ids, parse_config_document
from tollgate.errors import ConfigError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "invalid_configs"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=dev@example.com",
            "-c",
            "user.name=Tollgate Dev",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(tmp: Path, config: str, architecture: str | None = None) -> None:
    _git(tmp, "init", "-b", "main")
    (tmp / ".tollgate.yml").write_text(config, encoding="utf-8")
    if architecture is not None:
        arch = tmp / ".tollgate"
        arch.mkdir()
        (arch / "architecture.yaml").write_text(architecture, encoding="utf-8")
    _git(tmp, "add", ".")
    _git(tmp, "commit", "-m", "config")


def _example_config() -> str:
    return (ROOT / ".tollgate.yml").read_text(encoding="utf-8")


def _example_architecture() -> str:
    return (ROOT / ".tollgate" / "architecture.yaml").read_text(encoding="utf-8")


def test_example_configs_validate(tmp_path: Path) -> None:
    _init_repo(tmp_path, _example_config(), _example_architecture())
    # A pull request head must not change the configuration that is reviewed.
    (tmp_path / ".tollgate.yml").write_text("fail_on: low\n", encoding="utf-8")
    loaded = load_config(tmp_path, base_ref="main")
    assert loaded.tollgate.fail_on == "critical"
    assert loaded.tollgate.mode == "comment"
    assert loaded.tollgate.llm.roles.review.model == "anthropic:claude-sonnet-4-5"
    assert "ORG:P02" in organisation_ids(loaded.architecture)
    assert loaded.architecture.layers[0].name == "domain"


def test_invalid_config_exits_2_and_names_the_key(tmp_path: Path) -> None:
    cases = {
        "unknown_key.yml": "not_a_setting",
        "bad_fail_on.yml": "fail_on",
    }
    for filename, key in cases.items():
        repo = tmp_path / filename
        repo.mkdir()
        text = (FIXTURES / filename).read_text(encoding="utf-8")
        _init_repo(repo, text)
        completed = subprocess.run(
            [sys.executable, "-m", "tollgate", "review", "--local", "--base", "main"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 2, completed.stderr
        assert key in completed.stderr
        assert "configuration error:" in completed.stderr


def test_valid_example_exits_0(tmp_path: Path) -> None:
    _init_repo(tmp_path, _example_config(), _example_architecture())
    completed = subprocess.run(
        [sys.executable, "-m", "tollgate", "review", "--local", "--base", "main"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "configuration ok" in completed.stdout


def test_org_defaults_apply_and_locked_keys_are_named(tmp_path: Path) -> None:
    org = tmp_path / "org.yml"
    org.write_text(
        textwrap.dedent(
            """
            fail_on: critical
            max_inline_comments: 3
            locked:
              - fail_on
            """
        ),
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo, "max_inline_comments: 9\n", _example_architecture())
    loaded = load_config(repo, base_ref="main", org_config=str(org))
    assert loaded.tollgate.max_inline_comments == 9
    assert loaded.tollgate.fail_on == "critical"

    _git(repo, "rm", ".tollgate.yml")
    (repo / ".tollgate.yml").write_text("fail_on: low\n", encoding="utf-8")
    _git(repo, "add", ".tollgate.yml")
    _git(repo, "commit", "-m", "override locked fail_on")
    with pytest.raises(ConfigError, match="locked") as caught:
        load_config(repo, base_ref="main", org_config=str(org))
    assert caught.value.key == "fail_on"

    env = {**os.environ, "TOLLGATE_ORG_CONFIG": str(org)}
    completed = subprocess.run(
        [sys.executable, "-m", "tollgate", "review", "--local", "--base", "main"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert completed.returncode == 2
    assert "fail_on" in completed.stderr


def test_nested_org_merge_keeps_unlocked_repository_values(tmp_path: Path) -> None:
    document = yaml.safe_load(_example_config())
    assert isinstance(document, dict)
    parsed = parse_config_document(document)
    assert parsed.standards.owasp_web == "2025"
    org = tmp_path / "org.yml"
    org.write_text(
        "llm:\n  local_only: true\nlocked:\n  - llm.local_only\n",
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(
        repo,
        "llm:\n  local_only: false\n  temperature: 0\n",
        _example_architecture(),
    )
    with pytest.raises(ConfigError) as caught:
        load_config(repo, base_ref="main", org_config=str(org))
    assert caught.value.key == "llm.local_only"
