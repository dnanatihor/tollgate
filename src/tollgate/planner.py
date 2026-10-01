"""Turn classified files into review units (SPEC.md §7.4)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import yaml

from tollgate.classify import ClassifiedFile
from tollgate.config import TollgateConfig
from tollgate.context.treesitter import structural_context
from tollgate.globs import matches_any
from tollgate.llm.redact import mask_secrets
from tollgate.models import DiffLine, ReviewUnit

# See ADR 0003.
UNIT_TOKEN_BUDGET = 8000

_SECURITY_ROLES = {"source", "config", "infrastructure_as_code", "container", "ci_pipeline"}
_PERFORMANCE_ROLES = {"source", "database_migration"}


@dataclass(frozen=True, slots=True)
class ReviewPlan:
    units: tuple[ReviewUnit, ...]
    not_reviewed: tuple[tuple[str, str], ...]
    estimated_input_tokens: int
    estimated_usd: float | None


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text) / 3.5 * 1.15))


def build_plan(files: tuple[ClassifiedFile, ...], config: TollgateConfig) -> ReviewPlan:
    skipped: list[tuple[str, str]] = []
    candidates: list[ClassifiedFile] = []
    for item in files:
        if item.skip_reason is not None:
            skipped.append((item.diff.path, item.skip_reason))
            continue
        candidates.append(item)
    candidates.sort(key=_risk_key, reverse=True)

    selected: list[ClassifiedFile] = []
    changed_lines = 0
    for item in candidates:
        if len(selected) >= config.limits.max_files:
            skipped.append((item.diff.path, "max_files"))
            continue
        lines = _changed_lines(item)
        if changed_lines + lines > config.limits.max_changed_lines and selected:
            skipped.append((item.diff.path, "max_changed_lines"))
            continue
        selected.append(item)
        changed_lines += lines

    units: list[ReviewUnit] = []
    for item in selected:
        units.extend(_units_for(item, config))

    kept: list[ReviewUnit] = []
    spent = 0
    budget = config.llm.budget.max_input_tokens_per_pr
    for unit in units:
        cost = unit.estimated_tokens * max(len(unit.lenses), 1)
        if kept and spent + cost > budget:
            skipped.append((unit.path, "token_budget"))
            continue
        if not kept and cost > budget:
            skipped.append((unit.path, "token_budget"))
            continue
        kept.append(unit)
        spent += cost
    return ReviewPlan(
        units=tuple(kept),
        not_reviewed=tuple(skipped),
        estimated_input_tokens=spent,
        estimated_usd=_usd(spent, config.llm.roles.review.model),
    )


def render_plan(plan: ReviewPlan) -> str:
    lines = [f"units: {len(plan.units)}"]
    for unit in plan.units:
        lenses = ",".join(unit.lenses) if unit.lenses else "-"
        risks = ",".join(unit.risk_signals) if unit.risk_signals else "-"
        lines.append(
            f"- {unit.path} language={unit.language} role={unit.role} "
            f"lenses={lenses} risk={risks} tokens={unit.estimated_tokens}"
        )
        if unit.annotated_hunks:
            lines.append(unit.annotated_hunks)
    if plan.not_reviewed:
        lines.append("not_reviewed:")
        for path, reason in plan.not_reviewed:
            lines.append(f"- {path} {reason}")
    cost = "unpriced" if plan.estimated_usd is None else f"{plan.estimated_usd:.4f}"
    lines.append(f"estimated_input_tokens: {plan.estimated_input_tokens}")
    lines.append(f"estimated_usd: {cost}")
    return "\n".join(lines) + "\n"


def _units_for(item: ClassifiedFile, config: TollgateConfig) -> list[ReviewUnit]:
    hidden = matches_any(item.diff.path, config.paths.exclude_from_llm)
    context = structural_context(item.language, item.source_text, item.diff.hunks)
    context = "«secret»" if hidden else mask_secrets(context)
    annotated = _annotate(item)
    if hidden:
        annotated = "«secret»"
    lenses = _lenses(item, config)
    chunks = _split_annotated(annotated)
    units: list[ReviewUnit] = []
    for chunk in chunks:
        body = f"{chunk}\n{context}"
        units.append(
            ReviewUnit(
                path=item.diff.path,
                language=item.language,
                role=item.role,
                risk_signals=item.risk_signals,
                llm_signals=item.llm_signals,
                annotated_hunks=chunk,
                structural_context=context,
                lenses=lenses,
                estimated_tokens=estimate_tokens(body),
            )
        )
    return units


def _annotate(item: ClassifiedFile) -> str:
    lines: list[str] = []
    for hunk in item.diff.hunks:
        for line in hunk.lines:
            rendered = _render_line(line)
            if rendered is not None:
                lines.append(mask_secrets(rendered))
    return "\n".join(lines)


def _render_line(line: DiffLine) -> str | None:
    if line.kind == "-" or line.new_line is None:
        return f"     - {line.text}"
    marker = "+" if line.kind == "+" else " "
    return f"L{line.new_line} {marker} {line.text}"


def _split_annotated(annotated: str) -> list[str]:
    if estimate_tokens(annotated) <= UNIT_TOKEN_BUDGET:
        return [annotated]
    chunks: list[str] = []
    current: list[str] = []
    for line in annotated.splitlines():
        tentative = "\n".join([*current, line])
        if current and estimate_tokens(tentative) > UNIT_TOKEN_BUDGET:
            chunks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append("\n".join(current))
    return chunks or [annotated]


def _lenses(item: ClassifiedFile, config: TollgateConfig) -> tuple[str, ...]:
    if item.role in {"test", "documentation"} and not (
        item.role == "test" and config.paths.review_tests
    ):
        return ()
    chosen: list[str] = []
    if config.lenses.security and item.role in _SECURITY_ROLES:
        chosen.append("security")
    llm = config.lenses.llm_security
    if llm is True or (llm == "auto" and item.llm_signals):
        chosen.append("llm_security")
    if config.lenses.architecture and item.role not in {"documentation"}:
        chosen.append("architecture")
    if config.lenses.performance and (item.role in _PERFORMANCE_ROLES or item.language == "sql"):
        chosen.append("performance")
    return tuple(chosen)


def _risk_key(item: ClassifiedFile) -> tuple[int, int, str]:
    return (len(item.risk_signals) + len(item.llm_signals), _changed_lines(item), item.diff.path)


def _changed_lines(item: ClassifiedFile) -> int:
    return sum(1 for hunk in item.diff.hunks for line in hunk.lines if line.kind in {"+", "-"})


def _usd(tokens: int, model: str) -> float | None:
    prices = _load_prices()
    rate = prices.get(model)
    if rate is None:
        return None
    return tokens / 1_000_000 * rate


def _load_prices() -> dict[str, float]:
    roots = [
        Path.cwd() / "prices.yaml",
        Path(__file__).resolve().parents[2] / "prices.yaml",
    ]
    for path in roots:
        if not path.is_file():
            continue
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return {}
        models = loaded.get("models", {})
        if not isinstance(models, dict):
            return {}
        prices: dict[str, float] = {}
        for key, value in models.items():
            if isinstance(key, str) and isinstance(value, int | float):
                prices[key] = float(value)
        return prices
    return {}
