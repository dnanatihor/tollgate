"""Language, role, and risk signals for changed files (SPEC.md §7.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from tollgate.config import TollgateConfig
from tollgate.globs import matches_any
from tollgate.models import DiffFile, FileRole

_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".kt": "kotlin",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".sh": "shell",
    ".tf": "terraform",
    ".proto": "protobuf",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".cob": "cobol",
    ".cbl": "cobol",
    ".dsl": "dsl",
}

_SHEBANGS: tuple[tuple[str, str], ...] = (
    ("python", "python"),
    ("node", "javascript"),
    ("bash", "shell"),
    ("sh", "shell"),
)

_MANIFESTS = {
    "package.json",
    "pipfile",
    "pyproject.toml",
    "go.mod",
    "cargo.toml",
    "gemfile",
    "composer.json",
    "pom.xml",
}
_RISK: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("authentication", re.compile(r"(?i)\b(password|authori[sz]e|authenticated|permission)\b")),
    ("crypto", re.compile(r"(?i)\b(hashlib|bcrypt|cipher|aes|sha256|hmac|md5)\b")),
    ("sql", re.compile(r"(?i)\b(select|insert|update|delete)\b|\.execute\(")),
    (
        "deserialisation",
        re.compile(r"(?i)\b(pickle\.loads|yaml\.load|unserialize|deserialize|readObject)\b"),
    ),
    (
        "command_execution",
        re.compile(r"(?i)\b(subprocess|os\.system|child_process|exec\(|Runtime\.getRuntime)\b"),
    ),
    ("file_path", re.compile(r"(?i)\b(os\.path\.join|pathlib|File\(|open\(|\.\./)\b")),
    ("outbound_http", re.compile(r"(?i)\b(requests\.|httpx\.|fetch\(|HttpClient|urllib)\b")),
    ("html", re.compile(r"(?i)(innerHTML|dangerouslySetInnerHTML|markupsafe|<script)")),
    ("redirect", re.compile(r"(?i)\b(redirect\(|location\s*=)")),
    (
        "cors_cookie",
        re.compile(r"(?i)\b(cors|access-control-allow-origin|set-cookie|document\.cookie)\b"),
    ),
    ("jwt", re.compile(r"(?i)\b(jwt|jsonwebtoken)\b")),
)
_LLM_SDKS = (
    "openai",
    "anthropic",
    "google.generativeai",
    "vertexai",
    "langchain",
    "llama_index",
    "semantic_kernel",
    "transformers",
    "ollama",
    "litellm",
    "spring.ai",
    "bedrock-runtime",
)
_PROMPT = re.compile(r"(?i)(you are|system prompt|<\s*system\s*>)")


@dataclass(frozen=True, slots=True)
class ClassifiedFile:
    diff: DiffFile
    language: str
    role: FileRole
    risk_signals: tuple[str, ...]
    llm_signals: tuple[str, ...]
    generated: bool
    skip_reason: str | None
    source_text: str


def classify_changes(
    files: tuple[DiffFile, ...],
    *,
    config: TollgateConfig,
    attributes: str,
    sources: dict[str, str],
) -> tuple[ClassifiedFile, ...]:
    classified: list[ClassifiedFile] = []
    for diff in files:
        source = sources.get(diff.path, "")
        reason = _skip_reason(diff, config, attributes)
        language = detect_language(diff.path, source or _hunk_text(diff))
        role = detect_role(diff.path, language)
        text = source or _hunk_text(diff)
        classified.append(
            ClassifiedFile(
                diff=diff,
                language=language,
                role=role,
                risk_signals=risk_signals(text),
                llm_signals=llm_signals(text, config.llm.extra_sdk_signals),
                generated=reason == "generated",
                skip_reason=reason,
                source_text=source,
            )
        )
    return tuple(classified)


def detect_language(path: str, text: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if name == "Dockerfile" or name.endswith(".dockerfile"):
        return "dockerfile"
    suffix = ""
    if "." in name:
        suffix = "." + name.rsplit(".", 1)[-1].lower()
    if suffix in _EXTENSIONS:
        return _EXTENSIONS[suffix]
    if name.startswith("requirements") and name.endswith(".txt"):
        return "text"
    first = text.splitlines()[0] if text.splitlines() else ""
    if first.startswith("#!"):
        for needle, language in _SHEBANGS:
            if needle in first:
                return language
    return "unknown"


def detect_role(path: str, language: str) -> FileRole:
    lowered = path.replace("\\", "/").lower()
    name = lowered.rsplit("/", 1)[-1]
    if _is_test(lowered, name):
        return "test"
    if lowered.endswith(".md") or lowered.startswith("docs/") or "/docs/" in lowered:
        return "documentation"
    if "/.github/workflows/" in f"/{lowered}" or name in {
        "jenkinsfile",
        "bitbucket-pipelines.yml",
        ".gitlab-ci.yml",
    }:
        return "ci_pipeline"
    if name == "dockerfile" or name.endswith(".dockerfile") or name.startswith("docker-compose"):
        return "container"
    if language == "terraform" or any(
        part in lowered for part in ("/k8s/", "/helm/", "/terraform/")
    ):
        return "infrastructure_as_code"
    if "migrat" in lowered:
        return "database_migration"
    if language == "protobuf" or "openapi" in name or "swagger" in name:
        return "api_contract"
    if name in _MANIFESTS or (name.startswith("requirements") and name.endswith(".txt")):
        return "dependency_manifest"
    if name.endswith(".csproj") or name in {"build.gradle", "build.gradle.kts"}:
        return "dependency_manifest"
    if language in {"yaml", "json", "toml", "xml"}:
        return "config"
    if language == "sql":
        return "source"
    return "source"


def risk_signals(text: str) -> tuple[str, ...]:
    return tuple(name for name, pattern in _RISK if pattern.search(text))


def llm_signals(text: str, extra: list[str]) -> tuple[str, ...]:
    lowered = text.lower()
    found = [sdk for sdk in (*_LLM_SDKS, *extra) if sdk.lower() in lowered]
    if _PROMPT.search(text):
        found.append("prompt_literal")
    return tuple(dict.fromkeys(found))


def is_generated(path: str, attributes: str) -> bool:
    """Last matching ``linguist-generated`` attribute wins."""
    generated: bool | None = None
    normalized = path.replace("\\", "/")
    for raw in attributes.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, _, rest = line.partition(" ")
        if "linguist-generated" not in rest and line.strip().endswith("linguist-generated"):
            rest = line[len(pattern) :]
        if "linguist-generated" not in rest:
            continue
        if not matches_any(normalized, [pattern]):
            continue
        generated = "linguist-generated=false" not in rest.split()
    return bool(generated)


def _skip_reason(diff: DiffFile, config: TollgateConfig, attributes: str) -> str | None:
    if diff.status == "binary" or diff.binary:
        return "binary"
    if diff.status == "deleted":
        return "deleted"
    if matches_any(diff.path, config.paths.exclude):
        return "excluded"
    if is_generated(diff.path, attributes):
        return "generated"
    return None


def _is_test(path: str, name: str) -> bool:
    if "/test/" in f"/{path}/" or "/tests/" in f"/{path}/" or "/__tests__/" in f"/{path}/":
        return True
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_test.go")
        or name.endswith("test.java")
        or ".test." in name
        or ".spec." in name
    )


def _hunk_text(diff: DiffFile) -> str:
    return "\n".join(line.text for hunk in diff.hunks for line in hunk.lines if line.kind != "-")
