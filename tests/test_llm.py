"""Scripted-model reviews: fallback, repair, cache, and budget."""

from __future__ import annotations

import json

import pytest

from tollgate.classify import classify_changes
from tollgate.config import LensToggles, LLMBudget, LLMSettings, TollgateConfig
from tollgate.llm.schemas import LensOutput
from tollgate.llm.scripted import ScriptedChat
from tollgate.llm.structured import looks_like_json_prompt, structured_output
from tollgate.models import DiffFile, DiffLine, Hunk
from tollgate.pipeline import review_plan
from tollgate.planner import build_plan
from tollgate.render.sarif import render_sarif, validate_sarif
from tollgate.verdict import decide

EVIDENCE = '    query = "SELECT * FROM orders WHERE id=" + order_id'
FILE = f"def charge(order_id):\n{EVIDENCE}\n    return query\n"


def _reply() -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "title": "SQL injection",
                    "severity": "high",
                    "confidence": "high",
                    "start_line": 2,
                    "end_line": 2,
                    "evidence": EVIDENCE,
                    "explanation": "The query concatenates a request value.",
                    "recommendation": "Use a parameterised query.",
                    "standards": ["OWASP-WEB-2025:A05", "CWE-89"],
                }
            ]
        }
    )


def _config(**overrides: object) -> TollgateConfig:
    lenses = LensToggles(
        security=True,
        llm_security=False,
        architecture=False,
        performance=False,
    )
    data: dict[str, object] = {"lenses": lenses}
    data.update(overrides)
    return TollgateConfig.model_validate(data)


def _unit_file(path: str, source: str) -> DiffFile:
    lines = tuple(
        DiffLine(kind="+", text=line, new_line=index, old_line=None)
        for index, line in enumerate(source.splitlines(), start=1)
    )
    return DiffFile(
        path=path,
        status="added",
        hunks=(Hunk(old_start=0, old_lines=0, new_start=1, new_lines=len(lines), lines=lines),),
    )


@pytest.mark.asyncio
async def test_scripted_pipeline_and_sarif(tmp_path) -> None:
    model = ScriptedChat([_reply()])
    diff = _unit_file("app/orders.py", FILE)
    classified = classify_changes(
        (diff,),
        config=_config(),
        attributes="",
        sources={"app/orders.py": FILE},
    )
    plan = build_plan(classified, _config())
    outcome = await review_plan(
        plan,
        config=_config(),
        model=model,
        file_texts={"app/orders.py": FILE},
        cache_dir=tmp_path / "cache",
    )
    assert outcome.verdict.outcome == "concerns"
    assert outcome.ranked.findings[0].standards[0] == "OWASP-WEB-2025:A05"
    assert model.structured_calls
    document = render_sarif(list(outcome.ranked.findings), outcome.verdict)
    validate_sarif(document)
    again = ScriptedChat([])
    cached = await review_plan(
        plan,
        config=_config(),
        model=again,
        file_texts={"app/orders.py": FILE},
        cache_dir=tmp_path / "cache",
    )
    assert cached.ranked.findings
    assert again.structured_calls == []


@pytest.mark.asyncio
async def test_repair_and_json_fallback() -> None:
    model = ScriptedChat(["this is not json", _reply()], supports_native=False)
    result = await structured_output(
        model,
        system="system",
        user="unit",
        schema=LensOutput,
        mode="auto",
    )
    assert isinstance(result, LensOutput)
    assert len(result.findings) == 1
    assert len(model.completions) == 2
    assert looks_like_json_prompt(model.completions[0][1])
    assert "failed validation" in model.completions[1][1]


@pytest.mark.asyncio
async def test_budget_exhaustion_skips_later_units(tmp_path) -> None:
    risky = _unit_file("app/orders.py", FILE)
    quiet = _unit_file("app/other.py", "print('ok')\n")
    base = _config()
    classified = classify_changes(
        (risky, quiet),
        config=base,
        attributes="",
        sources={"app/orders.py": FILE, "app/other.py": "print('ok')\n"},
    )
    full = build_plan(classified, base)
    first = full.units[0].estimated_tokens * max(len(full.units[0].lenses), 1)
    limited = _config(llm=LLMSettings(budget=LLMBudget(max_input_tokens_per_pr=first)))
    plan = build_plan(classified, limited)
    model = ScriptedChat([_reply()])
    outcome = await review_plan(
        plan,
        config=limited,
        model=model,
        file_texts={"app/orders.py": FILE, "app/other.py": "print('ok')\n"},
        cache_dir=tmp_path,
    )
    assert len(model.structured_calls) == 1
    assert outcome.ranked.findings
    assert decide(list(outcome.ranked.findings), limited).outcome in {"concerns", "block", "pass"}
