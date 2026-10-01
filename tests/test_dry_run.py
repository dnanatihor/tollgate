"""``review --local --dry-run`` prints units and estimates."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.git_repo import commit, init_repo, write

ROOT = Path(__file__).resolve().parents[1]


def test_dry_run_prints_units_and_estimates(tmp_path: Path) -> None:
    init_repo(tmp_path)
    write(tmp_path, ".tollgate.yml", (ROOT / ".tollgate.yml").read_text(encoding="utf-8"))
    write(tmp_path, "app/orders.py", "def charge(order_id):\n    return order_id\n")
    commit(tmp_path, "base")
    source = (
        "def charge(order_id):\n"
        '    query = "SELECT * FROM orders WHERE id=" + order_id\n'
        "    return query\n"
    )
    write(tmp_path, "app/orders.py", source)
    commit(tmp_path, "head")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tollgate",
            "review",
            "--local",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--dry-run",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout
    assert "app/orders.py" in output
    assert "lenses=" in output
    assert "security" in output
    assert "estimated_input_tokens:" in output
    assert "estimated_usd:" in output
    assert "L2 +" in output
