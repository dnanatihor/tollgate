"""Filtering, unit splits, and the pull-request token budget."""

from __future__ import annotations

from tollgate.classify import classify_changes
from tollgate.config import LLMBudget, LLMSettings, TollgateConfig
from tollgate.models import DiffFile, DiffLine, Hunk
from tollgate.planner import build_plan


def _line(number: int, text: str) -> DiffLine:
    return DiffLine(kind="+", text=text, new_line=number, old_line=None)


def _file(path: str, lines: tuple[DiffLine, ...], *, source: str | None = None) -> DiffFile:
    return DiffFile(
        path=path,
        status="added",
        hunks=(
            Hunk(
                old_start=0,
                old_lines=0,
                new_start=1,
                new_lines=len(lines),
                lines=lines,
            ),
        ),
    )


def test_excludes_generated_and_vendor_and_records_deletions() -> None:
    deleted = DiffFile(path="old.py", status="deleted")
    generated = _file("lib/a.gen.py", (_line(1, "x = 1"),))
    vendor = _file("vendor/pkg.js", (_line(1, "x = 1"),))
    kept = _file("app/orders.py", (_line(1, 'query = "SELECT" + order_id'),))
    attributes = "*.gen.py linguist-generated\n"
    classified = classify_changes(
        (deleted, generated, vendor, kept),
        config=TollgateConfig(),
        attributes=attributes,
        sources={"app/orders.py": 'query = "SELECT" + order_id\n'},
    )
    plan = build_plan(classified, TollgateConfig())
    reasons = dict(plan.not_reviewed)
    assert reasons["old.py"] == "deleted"
    assert reasons["lib/a.gen.py"] == "generated"
    assert reasons["vendor/pkg.js"] == "excluded"
    assert [unit.path for unit in plan.units] == ["app/orders.py"]
    assert "security" in plan.units[0].lenses
    assert "sql" in plan.units[0].risk_signals


def test_units_split_and_respect_the_token_budget() -> None:
    big_lines = tuple(_line(index + 1, "x" * 80) for index in range(500))
    big = _file("app/big.py", big_lines)
    risky = _file("app/pay.py", (_line(1, 'query = "SELECT id FROM t"'),))
    quiet = _file("app/quiet.py", (_line(1, "print('ok')"),))
    classified = classify_changes(
        (big, risky, quiet),
        config=TollgateConfig(),
        attributes="",
        sources={},
    )
    wide = build_plan(classified, TollgateConfig())
    big_units = [unit for unit in wide.units if unit.path == "app/big.py"]
    assert len(big_units) >= 2

    first_cost = wide.units[0].estimated_tokens * max(len(wide.units[0].lenses), 1)
    limited = TollgateConfig(llm=LLMSettings(budget=LLMBudget(max_input_tokens_per_pr=first_cost)))
    plan = build_plan(classified, limited)
    assert plan.units
    assert plan.units[0].path == wide.units[0].path
    assert any(reason == "token_budget" for _, reason in plan.not_reviewed)
    assert plan.estimated_input_tokens <= first_cost


def test_secrets_and_excluded_paths_are_masked() -> None:
    secret = _file(
        "app/settings.py",
        (_line(1, 'password = "hunter2"'),),
    )
    hidden = _file("config/prod/app.yml", (_line(1, "token: abcd"),))
    classified = classify_changes(
        (secret, hidden),
        config=TollgateConfig(),
        attributes="",
        sources={},
    )
    plan = build_plan(classified, TollgateConfig())
    by_path = {unit.path: unit for unit in plan.units}
    assert "hunter2" not in by_path["app/settings.py"].annotated_hunks
    assert "«secret»" in by_path["app/settings.py"].annotated_hunks
    assert by_path["config/prod/app.yml"].annotated_hunks == "«secret»"
    assert "abcd" not in by_path["config/prod/app.yml"].structural_context
