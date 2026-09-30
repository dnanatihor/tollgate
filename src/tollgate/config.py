"""Load ``.tollgate.yml`` and ``.tollgate/architecture.yaml`` (SPEC.md §5).

Repository configuration is always read from a git base ref, never from the
working tree or the pull request head. See ADR 0001 for merge rules.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any, Literal, TypeVar

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tollgate.errors import ConfigError

_CONFIG_PATH = ".tollgate.yml"
_ARCH_PATH = ".tollgate/architecture.yaml"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MinInline(_Model):
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    confidence: Literal["high", "medium", "low"] = "medium"


class LensToggles(_Model):
    security: bool = True
    llm_security: bool | Literal["auto"] = "auto"
    architecture: bool = True
    performance: bool = True


class PathFilters(_Model):
    exclude: list[str] = [
        "**/vendor/**",
        "**/node_modules/**",
        "**/*.min.js",
        "**/dist/**",
        "**/*.lock",
        "**/generated/**",
    ]
    exclude_from_llm: list[str] = ["**/*.pem", "**/*.key", "config/prod/**"]
    review_tests: bool = False


class Limits(_Model):
    max_files: int = Field(default=150, ge=1)
    max_changed_lines: int = Field(default=5000, ge=1)


class Analyzers(_Model):
    semgrep: Literal["auto", "on", "off"] = "auto"
    gitleaks: Literal["auto", "on", "off"] = "auto"
    osv: Literal["auto", "on", "off"] = "auto"


class StandardsSelection(_Model):
    owasp_web: Literal["2025", "2021"] = "2025"


class Suppressions(_Model):
    allow_new_in_pr_max_severity: Literal["critical", "high", "medium", "low", "info"] = "medium"


class Critic(_Model):
    enabled: bool = True
    min_severity: Literal["critical", "high", "medium", "low"] = "high"


class ModelRole(_Model):
    model: str = Field(pattern=r"^[^:\s]+:\S+$")


def _default_triage() -> ModelRole:
    return ModelRole(model="openai:gpt-4.1-mini")


def _default_review_model() -> ModelRole:
    return ModelRole(model="anthropic:claude-sonnet-4-5")


class LLMRoles(_Model):
    # Concrete models are placeholders for SPEC.md §18 item 2. Organisations set llm.roles.
    triage: ModelRole = Field(default_factory=_default_triage)
    review: ModelRole = Field(default_factory=_default_review_model)
    critic: ModelRole = Field(default_factory=_default_review_model)


class LLMBudget(_Model):
    max_input_tokens_per_pr: int = Field(default=400_000, ge=1)
    max_usd_per_pr: float = Field(default=2.00, ge=0)


class LLMSettings(_Model):
    roles: LLMRoles = LLMRoles()
    base_url: str | None = None
    temperature: float = Field(default=0, ge=0, le=2)
    structured_output: Literal["auto", "native", "json_prompt"] = "auto"
    context_window: int | None = Field(default=None, ge=1)
    budget: LLMBudget = LLMBudget()
    local_only: bool = False
    allowed_providers: list[str] = []


class TollgateConfig(_Model):
    mode: Literal["comment", "status", "request_changes"] = "comment"
    fail_on: Literal["critical", "high", "medium", "low"] = "critical"
    min_inline: MinInline = MinInline()
    max_inline_comments: int = Field(default=12, ge=0)
    lenses: LensToggles = LensToggles()
    paths: PathFilters = PathFilters()
    limits: Limits = Limits()
    analyzers: Analyzers = Analyzers()
    standards: StandardsSelection = StandardsSelection()
    suppressions: Suppressions = Suppressions()
    incremental: bool = False
    critic: Critic = Critic()
    llm: LLMSettings = LLMSettings()

    def fingerprint(self) -> str:
        payload = self.model_dump_json().encode()
        return hashlib.sha256(payload).hexdigest()


class Principle(_Model):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    guidance: str = Field(min_length=1)


class LayerRule(_Model):
    name: str = Field(min_length=1)
    paths: list[str]
    may_depend_on: list[str]


class TechRadar(_Model):
    hold: list[str] = []
    assess: list[str] = []


class ApiGuideline(_Model):
    id: str = Field(min_length=1)
    rule: str = Field(min_length=1)


class SignificanceTriggers(_Model):
    new_dependency: bool = True
    new_datastore: bool = True
    new_public_endpoint: bool = True
    new_service_paths: list[str] = ["services/*/", "apps/*/"]
    infra_paths: list[str] = ["terraform/**", "k8s/**", "helm/**"]


class ArchitectureDocs(_Model):
    adr: list[str] = ["docs/adr/**/*.md"]
    architecture: list[str] = ["docs/architecture/**/*.md"]


class ArchitectureConfig(_Model):
    principles: list[Principle] = []
    layers: list[LayerRule] = []
    tech_radar: TechRadar = TechRadar()
    api_guidelines: list[ApiGuideline] = []
    significance_triggers: SignificanceTriggers = SignificanceTriggers()
    docs: ArchitectureDocs = ArchitectureDocs()


class LoadedConfig(_Model):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tollgate: TollgateConfig
    architecture: ArchitectureConfig
    base_ref: str
    base_sha: str


def organisation_ids(architecture: ArchitectureConfig) -> tuple[str, ...]:
    """Standard ids for principles and API guidelines (``ORG:P02``, ``ORG:G01``)."""
    ids = [f"ORG:{item.id}" for item in architecture.principles]
    ids.extend(f"ORG:{item.id}" for item in architecture.api_guidelines)
    return tuple(ids)


def load_config(
    repo: Path,
    *,
    base_ref: str,
    org_config: str | None = None,
) -> LoadedConfig:
    """Load configuration from ``base_ref``. Working-tree edits are ignored."""
    root = repo.resolve()
    sha = _resolve_commit(root, base_ref)
    repo_raw = _load_yaml_text(_read_base_text(root, base_ref, _CONFIG_PATH), _CONFIG_PATH)
    arch_raw = _load_yaml_text(_read_base_text(root, base_ref, _ARCH_PATH), _ARCH_PATH)
    org_spec = org_config if org_config is not None else os.environ.get("TOLLGATE_ORG_CONFIG")
    merged = _merge_org(repo_raw, org_spec)
    return LoadedConfig(
        tollgate=_validate_model(TollgateConfig, merged, key=""),
        architecture=_validate_architecture(arch_raw),
        base_ref=base_ref,
        base_sha=sha,
    )


def parse_architecture_document(raw: Any) -> ArchitectureConfig:
    """Validate an architecture mapping that is already in memory."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("(root)", "configuration must be a mapping")
    return _validate_architecture(raw)


def parse_config_document(raw: Any) -> TollgateConfig:
    """Validate a mapping that is already in memory (tests and examples)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("(root)", "configuration must be a mapping")
    return _validate_model(TollgateConfig, raw, key="")


def _validate_architecture(raw: dict[str, Any]) -> ArchitectureConfig:
    architecture = _validate_model(ArchitectureConfig, raw, key="")
    seen: set[str] = set()
    for org_id in organisation_ids(architecture):
        if org_id in seen:
            raise ConfigError(org_id, "duplicate organisation standard id")
        seen.add(org_id)
    layer_names = [layer.name for layer in architecture.layers]
    if len(layer_names) != len(set(layer_names)):
        raise ConfigError("layers", "duplicate layer name")
    known = set(layer_names)
    for layer in architecture.layers:
        for dependency in layer.may_depend_on:
            if dependency not in known:
                raise ConfigError(
                    f"layers.{layer.name}.may_depend_on",
                    f"unknown layer {dependency!r}",
                )
    return architecture


def _merge_org(repo_raw: dict[str, Any], org_spec: str | None) -> dict[str, Any]:
    if not org_spec:
        return repo_raw
    org_raw = _load_yaml_text(_read_org_text(org_spec), "TOLLGATE_ORG_CONFIG")
    locked = org_raw.pop("locked", [])
    if not isinstance(locked, list) or not all(isinstance(item, str) for item in locked):
        raise ConfigError("locked", "must be a list of dotted paths")
    locked_keys = [item for item in locked if isinstance(item, str)]
    for dotted in locked_keys:
        present, repo_value = _lookup(repo_raw, dotted)
        if not present:
            continue
        org_present, org_value = _lookup(org_raw, dotted)
        if not org_present:
            raise ConfigError(dotted, "locked key is not set in the organisation file")
        if repo_value != org_value:
            raise ConfigError(dotted, "locked by the organisation configuration")
    merged = _deep_merge(org_raw, repo_raw)
    return merged


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _lookup(data: dict[str, Any], dotted: str) -> tuple[bool, Any]:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _validate_model(model: type[_ModelT], raw: dict[str, Any], *, key: str) -> _ModelT:
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise _from_validation(exc, prefix=key) from None


def _from_validation(exc: ValidationError, *, prefix: str) -> ConfigError:
    error = exc.errors()[0]
    parts = [str(part) for part in error["loc"]]
    loc = ".".join(part for part in parts if part != "__root__")
    named = f"{prefix}.{loc}" if prefix and loc else prefix or loc or "(root)"
    return ConfigError(named, error["msg"])


def _load_yaml_text(text: str | None, key: str) -> dict[str, Any]:
    if text is None or not text.strip():
        return {}
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(key, f"invalid YAML: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(key, "configuration must be a mapping")
    return loaded


def _read_org_text(spec: str) -> str:
    if spec.startswith(("http://", "https://")):
        try:
            response = httpx.get(spec, timeout=10.0, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConfigError("TOLLGATE_ORG_CONFIG", str(exc)) from exc
        return response.text
    path = Path(spec)
    if not path.is_file():
        raise ConfigError("TOLLGATE_ORG_CONFIG", f"not a file: {spec}")
    return path.read_text(encoding="utf-8")


def _resolve_commit(repo: Path, ref: str) -> str:
    if not _is_git_repo(repo):
        raise ConfigError("base", f"{repo} is not a git repository")
    result = _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if result.returncode != 0 or not result.stdout.strip():
        raise ConfigError("base", f"ref {ref!r} was not found")
    return result.stdout.strip()


def _read_base_text(repo: Path, ref: str, path: str) -> str | None:
    result = _git(repo, "show", f"{ref}:{path}")
    if result.returncode != 0:
        return None
    return result.stdout


def _is_git_repo(repo: Path) -> bool:
    result = _git(repo, "rev-parse", "--is-inside-work-tree")
    return result.returncode == 0 and result.stdout.strip() == "true"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
