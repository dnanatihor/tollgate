"""Run lens reviews for a plan and publish only verified findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tollgate.config import TollgateConfig
from tollgate.graph import compile_review_graph
from tollgate.llm.cache import ResponseCache, cache_key
from tollgate.llm.schemas import LensOutput
from tollgate.llm.structured import ChatBackend, ReviewFailed, structured_output
from tollgate.models import Finding, ReviewUnit, Verdict
from tollgate.planner import ReviewPlan
from tollgate.prompting import render_lens_prompt
from tollgate.rank import Ranked, rank_findings
from tollgate.standards import CatalogEntry, load_catalogs
from tollgate.verdict import decide
from tollgate.verify import known_ids_from_catalogs, verify_finding

PROMPT_VERSION = "v1"


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    ranked: Ranked
    verdict: Verdict
    failed_units: tuple[str, ...]
    dropped: int


async def review_plan(
    plan: ReviewPlan,
    *,
    config: TollgateConfig,
    model: ChatBackend,
    file_texts: dict[str, str],
    cache_dir: Path,
    organisation: tuple[str, ...] = (),
) -> ReviewOutcome:
    catalogs = load_catalogs()
    known = known_ids_from_catalogs(catalogs, organisation)
    web = f"OWASP-WEB-{config.standards.owasp_web}:"
    cache = ResponseCache(cache_dir)
    jobs: list[dict[str, Any]] = []
    for unit in plan.units:
        for lens in unit.lenses:
            jobs.append(
                {
                    "unit": unit,
                    "lens": lens,
                    "model": model,
                    "config": config,
                    "known": known,
                    "web": web,
                    "catalogs": catalogs,
                    "file_text": file_texts.get(unit.path, ""),
                    "organisation": organisation,
                    "cache": cache,
                }
            )
    for job in jobs:
        job["runner"] = _review_job
    graph = compile_review_graph()
    state = await graph.ainvoke({"jobs": jobs, "results": []})
    findings: list[Finding] = []
    failed: list[str] = []
    dropped = 0
    for item in state.get("results", []):
        if item is None:
            continue
        kind, payload = item
        if kind == "failed":
            failed.append(payload)
        elif kind == "dropped":
            dropped += 1
        else:
            findings.append(payload)
    ranked = rank_findings(findings, config)
    return ReviewOutcome(
        ranked=ranked,
        verdict=decide(list(ranked.findings), config),
        failed_units=tuple(failed),
        dropped=dropped,
    )


async def _review_job(job: dict[str, Any]) -> list[tuple[str, Any]]:
    unit: ReviewUnit = job["unit"]
    lens: str = job["lens"]
    model: ChatBackend = job["model"]
    config: TollgateConfig = job["config"]
    entries = _entries(job["catalogs"], lens, config.standards.owasp_web)
    extra = job["organisation"] if lens == "architecture" else ()
    system, user = render_lens_prompt(lens, unit, entries=entries, extra_ids=extra)
    content = f"{system}\n{user}"
    key = cache_key(model.model_id, PROMPT_VERSION, lens, content)
    cache: ResponseCache = job["cache"]
    cached = cache.get(key)
    try:
        if cached is not None:
            output = LensOutput.model_validate_json(cached)
        else:
            parsed = await structured_output(
                model,
                system=system,
                user=user,
                schema=LensOutput,
                mode=config.llm.structured_output,
            )
            output = parsed if isinstance(parsed, LensOutput) else LensOutput.model_validate(parsed)
            cache.put(key, output.model_dump_json())
    except ReviewFailed:
        return [("failed", unit.path)]
    produced: list[tuple[str, Any]] = []
    findings = output.findings[:5]
    for proposed in findings:
        verified = verify_finding(
            proposed,
            lens=lens,  # type: ignore[arg-type]
            path=unit.path,
            annotated=unit.annotated_hunks,
            file_text=job["file_text"],
            known_ids=job["known"],
            web_prefix=job["web"],
        )
        if verified is None:
            produced.append(("dropped", unit.path))
        else:
            produced.append(("finding", verified))
    return produced


def _entries(
    catalogs: dict[str, tuple[CatalogEntry, ...]],
    lens: str,
    web_year: str,
) -> tuple[CatalogEntry, ...]:
    names: tuple[str, ...]
    if lens == "security":
        names = (f"owasp-web-{web_year}", "owasp-api-2023", "cwe")
    elif lens == "llm_security":
        names = ("owasp-llm-2025",)
    elif lens == "architecture":
        names = ("tollgate-arch",)
    else:
        names = ("tollgate-perf",)
    entries: list[CatalogEntry] = []
    for name in names:
        entries.extend(catalogs.get(name, ()))
    return tuple(entries)
