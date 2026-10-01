"""Write the seeded and clean eval cases. Safe to re-run."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "eval" / "cases"

YML = """\
lenses:
  security: {security}
  llm_security: {llm}
  architecture: {architecture}
  performance: {performance}
critic:
  enabled: false
analyzers:
  semgrep: "off"
  gitleaks: "off"
  osv: "off"
"""


def main() -> None:
    for spec in SEEDED:
        _write_model_case(*spec)
    for spec in CLEAN:
        _write_clean(*spec)
    _mark_deterministic()


def _write_model_case(
    case_id: str,
    lens: str,
    standard: str,
    path: str,
    before: str,
    after: str,
    evidence: str,
) -> None:
    line = after.splitlines().index(evidence) + 1
    folder = ROOT / case_id
    _config(folder, lens)
    _file(folder / "base" / path, before)
    (folder / "change.patch").write_text(_diff(path, before, after), encoding="utf-8")
    (folder / "expected.yaml").write_text(
        "\n".join(
            [
                f"lens: {lens}",
                "expect:",
                "  - {standards_any: [" + json.dumps(standard) + "], "
                f"file: {path}, lines: [{line}, {line}], min_severity: high}}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (folder / "scripted.json").write_text(
        json.dumps(
            [
                {
                    "findings": [
                        {
                            "title": case_id.replace("-", " "),
                            "severity": "high",
                            "confidence": "high",
                            "start_line": line,
                            "end_line": line,
                            "evidence": evidence,
                            "explanation": "The changed line introduces this issue.",
                            "recommendation": "Replace the changed line with a safe alternative.",
                            "standards": [standard],
                        }
                    ]
                }
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_clean(case_id: str, path: str, before: str, after: str, model: bool) -> None:
    folder = ROOT / case_id
    _config(folder, "security" if model else "none")
    _file(folder / "base" / path, before)
    (folder / "change.patch").write_text(_diff(path, before, after), encoding="utf-8")
    (folder / "expected.yaml").write_text(
        "deterministic: true\nlens: security\nexpect: []\nmust_not:\n  - {min_severity: medium}\n",
        encoding="utf-8",
    )
    if model:
        (folder / "scripted.json").write_text(
            json.dumps([{"findings": []}]) + "\n", encoding="utf-8"
        )


def _config(folder: Path, lens: str) -> None:
    flags = {name: "false" for name in ("security", "llm", "architecture", "performance")}
    if lens == "llm_security":
        flags["llm"] = "true"
    elif lens in flags:
        flags[lens] = "true"
    text = YML.format(**flags)
    _file(folder / "base" / ".tollgate.yml", text)
    _file(folder / "base" / ".tollgate" / "architecture.yaml", "{}\n")


def _mark_deterministic() -> None:
    names = (
        "arch-layer",
        "tech-radar-hold",
        "significance-no-adr",
        "openapi-break",
        "migration-drop",
        "secret-added",
    )
    yml = YML.format(security="false", llm="false", architecture="false", performance="false")
    for name in names:
        folder = ROOT / name
        expected = folder / "expected.yaml"
        text = expected.read_text(encoding="utf-8")
        if "deterministic:" not in text:
            expected.write_text("deterministic: true\n" + text, encoding="utf-8")
        _file(folder / "base" / ".tollgate.yml", yml)


def _diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def _file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


SEEDED: tuple[tuple[str, str, str, str, str, str, str], ...] = (
    (
        "sec-sql",
        "security",
        "CWE-89",
        "app/orders.py",
        "def charge(order_id: str) -> str:\n    return order_id\n",
        'def charge(order_id: str) -> str:\n    return "SELECT * FROM orders WHERE id=" + order_id\n',
        '    return "SELECT * FROM orders WHERE id=" + order_id',
    ),
    (
        "sec-command",
        "security",
        "CWE-78",
        "app/shell.py",
        "def run(name: str) -> str:\n    return name\n",
        "def run(name: str) -> str:\n    os.system('ls ' + name)\n    return name\n",
        "    os.system('ls ' + name)",
    ),
    (
        "sec-path",
        "security",
        "CWE-22",
        "app/files.py",
        "def read(name: str) -> str:\n    return name\n",
        "def read(name: str) -> str:\n    return open('/data/' + name).read()\n",
        "    return open('/data/' + name).read()",
    ),
    (
        "sec-ssrf",
        "security",
        "CWE-918",
        "app/fetch.py",
        "def load(url: str) -> str:\n    return url\n",
        "def load(url: str) -> str:\n    return requests.get(url).text\n",
        "    return requests.get(url).text",
    ),
    (
        "sec-idor",
        "security",
        "OWASP-WEB-2025:A01",
        "app/account.py",
        "def show(user_id: str) -> str:\n    return user_id\n",
        "def show(user_id: str) -> str:\n    return db.get(user_id)\n",
        "    return db.get(user_id)",
    ),
    (
        "sec-pickle",
        "security",
        "CWE-502",
        "app/decode.py",
        "def load(blob: bytes) -> str:\n    return blob.decode()\n",
        "def load(blob: bytes) -> str:\n    return pickle.loads(blob)\n",
        "    return pickle.loads(blob)",
    ),
    (
        "sec-md5",
        "security",
        "CWE-327",
        "app/hash.py",
        "def digest(value: bytes) -> bytes:\n    return value\n",
        "def digest(value: bytes) -> bytes:\n    return hashlib.md5(value).digest()\n",
        "    return hashlib.md5(value).digest()",
    ),
    (
        "sec-xss",
        "security",
        "CWE-79",
        "web/profile.js",
        "function show(name) {\n  return name;\n}\n",
        "function show(name) {\n  document.write(name);\n  return name;\n}\n",
        "  document.write(name);",
    ),
    (
        "sec-redirect",
        "security",
        "OWASP-WEB-2025:A01",
        "app/redirect.py",
        "def go(url: str) -> str:\n    return url\n",
        "def go(url: str) -> str:\n    return redirect(request.args['next'])\n",
        "    return redirect(request.args['next'])",
    ),
    (
        "sec-trace",
        "security",
        "CWE-209",
        "app/errors.py",
        "def fail(exc: Exception) -> str:\n    return 'error'\n",
        "def fail(exc: Exception) -> str:\n    return traceback.format_exc()\n",
        "    return traceback.format_exc()",
    ),
    (
        "sec-jwt",
        "security",
        "OWASP-WEB-2025:A07",
        "app/jwt.py",
        "def check(token: str) -> str:\n    return token\n",
        "def check(token: str) -> str:\n    return jwt.decode(token, options={'verify_signature': False})\n",
        "    return jwt.decode(token, options={'verify_signature': False})",
    ),
    (
        "sec-cors",
        "security",
        "OWASP-WEB-2025:A02",
        "app/cors.py",
        "def headers() -> dict[str, str]:\n    return {}\n",
        "def headers() -> dict[str, str]:\n    return {'Access-Control-Allow-Origin': '*'}\n",
        "    return {'Access-Control-Allow-Origin': '*'}",
    ),
    (
        "sec-log",
        "security",
        "OWASP-WEB-2025:A09",
        "app/audit.py",
        "def record(user: str) -> str:\n    return user\n",
        "def record(user: str) -> str:\n    logging.info('user payload %s', user)\n    return user\n",
        "    logging.info('user payload %s', user)",
    ),
    (
        "llm-prompt",
        "llm_security",
        "OWASP-LLM-2025:LLM01",
        "app/prompt.py",
        "def ask(user: str) -> str:\n    return user\n",
        "def ask(user: str) -> str:\n    return client.complete(system + user)\n",
        "    return client.complete(system + user)",
    ),
    (
        "llm-eval",
        "llm_security",
        "OWASP-LLM-2025:LLM05",
        "app/sink.py",
        "def apply(text: str) -> str:\n    return text\n",
        "def apply(text: str) -> str:\n    return eval(model_output)\n",
        "    return eval(model_output)",
    ),
    (
        "llm-tool",
        "llm_security",
        "OWASP-LLM-2025:LLM06",
        "app/tool.py",
        "def act() -> str:\n    return 'ok'\n",
        "def act() -> str:\n    return delete_records(confirmed=False)\n",
        "    return delete_records(confirmed=False)",
    ),
    (
        "llm-key",
        "llm_security",
        "OWASP-LLM-2025:LLM07",
        "app/system.py",
        "def prompt() -> str:\n    return 'help'\n",
        "def prompt() -> str:\n    return 'system credential sk-live-demo'\n",
        "    return 'system credential sk-live-demo'",
    ),
    (
        "llm-limit",
        "llm_security",
        "OWASP-LLM-2025:LLM10",
        "app/chat.py",
        "def call() -> str:\n    return 'ok'\n",
        "def call() -> str:\n    return client.generate(timeout=None)\n",
        "    return client.generate(timeout=None)",
    ),
    (
        "llm-rag",
        "llm_security",
        "OWASP-LLM-2025:LLM08",
        "app/rag.py",
        "def search(q: str) -> str:\n    return q\n",
        "def search(q: str) -> str:\n    return index.search(q, filter=None)\n",
        "    return index.search(q, filter=None)",
    ),
    (
        "llm-remote",
        "llm_security",
        "OWASP-LLM-2025:LLM03",
        "app/model.py",
        "def load() -> str:\n    return 'ok'\n",
        "def load() -> str:\n    return AutoModel.from_pretrained('org/model', trust_remote_code=True)\n",
        "    return AutoModel.from_pretrained('org/model', trust_remote_code=True)",
    ),
    (
        "perf-nplus1",
        "performance",
        "TG-PERF-001",
        "app/list.py",
        "def names(users: list[str]) -> list[str]:\n    return users\n",
        "def names(users: list[str]) -> list[str]:\n    return [db.query(user) for user in users]\n",
        "    return [db.query(user) for user in users]",
    ),
    (
        "perf-unbounded",
        "performance",
        "TG-PERF-002",
        "app/all.py",
        "def all_rows() -> list[str]:\n    return []\n",
        "def all_rows() -> list[str]:\n    return db.execute('SELECT * FROM orders')\n",
        "    return db.execute('SELECT * FROM orders')",
    ),
    (
        "perf-sleep",
        "performance",
        "TG-PERF-003",
        "app/async_handler.py",
        "async def handle() -> str:\n    return 'ok'\n",
        "async def handle() -> str:\n    time.sleep(2)\n    return 'ok'\n",
        "    time.sleep(2)",
    ),
    (
        "perf-quadratic",
        "performance",
        "TG-PERF-004",
        "app/scan.py",
        "def has(items: list[str], other: list[str]) -> bool:\n    return False\n",
        "def has(items: list[str], other: list[str]) -> bool:\n    return any(item in other for item in items)\n",
        "    return any(item in other for item in items)",
    ),
    (
        "perf-regex",
        "performance",
        "TG-PERF-005",
        "app/match.py",
        "def match(value: str) -> bool:\n    return False\n",
        "def match(value: str) -> bool:\n    return bool(re.match(r'(a+)+$', value))\n",
        "    return bool(re.match(r'(a+)+$', value))",
    ),
    (
        "perf-read",
        "performance",
        "TG-PERF-006",
        "app/stream.py",
        "def body(path: str) -> str:\n    return path\n",
        "def body(path: str) -> str:\n    return Path(path).read_text()\n",
        "    return Path(path).read_text()",
    ),
    (
        "arch-timeout",
        "architecture",
        "TG-ARCH-007",
        "app/client.py",
        "def call(url: str) -> str:\n    return url\n",
        "def call(url: str) -> str:\n    return httpx.get(url).text\n",
        "    return httpx.get(url).text",
    ),
    (
        "arch-observability",
        "architecture",
        "TG-ARCH-008",
        "app/endpoint.py",
        "def serve() -> str:\n    return 'ok'\n",
        "def serve() -> str:\n    return store.save()\n",
        "    return store.save()",
    ),
    (
        "arch-hardcoded",
        "architecture",
        "TG-ARCH-009",
        "app/env.py",
        "def host() -> str:\n    return 'localhost'\n",
        "def host() -> str:\n    return 'https://billing.internal.example'\n",
        "    return 'https://billing.internal.example'",
    ),
    (
        "arch-boundary",
        "architecture",
        "TG-ARCH-010",
        "app/export.py",
        "def send(row: dict[str, str]) -> str:\n    return 'ok'\n",
        "def send(row: dict[str, str]) -> str:\n    return partner.post(row['restricted'])\n",
        "    return partner.post(row['restricted'])",
    ),
    (
        "arch-conflict",
        "architecture",
        "TG-ARCH-004",
        "app/sync.py",
        "def notify() -> str:\n    return 'ok'\n",
        "def notify() -> str:\n    return other_service.get('/charges')\n",
        "    return other_service.get('/charges')",
    ),
)

CLEAN: tuple[tuple[str, str, str, str, bool], ...] = (
    (
        "clean-params",
        "app/orders.py",
        "def charge(order_id: str) -> str:\n    return order_id\n",
        "def charge(order_id: str) -> str:\n    return db.execute('SELECT * FROM orders WHERE id = ?', order_id)\n",
        True,
    ),
    (
        "clean-argv",
        "app/shell.py",
        "def run() -> int:\n    return 0\n",
        "def run() -> int:\n    return subprocess.run(['ls', '-l'], check=False).returncode\n",
        True,
    ),
    (
        "clean-page",
        "app/page.py",
        "def page() -> list[str]:\n    return []\n",
        "def page() -> list[str]:\n    return db.limit(50).offset(0).all()\n",
        True,
    ),
    (
        "clean-test",
        "tests/test_orders.py",
        "def test_ok() -> None:\n    assert True\n",
        "def test_ok() -> None:\n    assert 1 + 1 == 2\n",
        False,
    ),
    (
        "clean-docs",
        "docs/guide.md",
        "# Guide\n\nHello.\n",
        "# Guide\n\nHello, reviewer.\n",
        False,
    ),
    (
        "clean-rename",
        "app/names.py",
        "def total(values: list[int]) -> int:\n    return sum(values)\n",
        "def total_amount(values: list[int]) -> int:\n    return sum(values)\n",
        True,
    ),
    (
        "clean-const",
        "app/const.py",
        "LIMIT = 10\n",
        "LIMIT = 20\n",
        True,
    ),
    (
        "clean-typed",
        "app/typed.py",
        "def length(value):\n    return len(value)\n",
        "def length(value: str) -> int:\n    return len(value)\n",
        True,
    ),
    (
        "clean-comment",
        "app/note.py",
        "def ready() -> bool:\n    return True\n",
        "def ready() -> bool:\n    # saved after the review comment\n    return True\n",
        True,
    ),
    (
        "clean-list",
        "app/copy.py",
        "def copy(items: list[str]) -> list[str]:\n    return items\n",
        "def copy(items: list[str]) -> list[str]:\n    return list(items)\n",
        True,
    ),
)


if __name__ == "__main__":
    main()
