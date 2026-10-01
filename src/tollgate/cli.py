"""Command-line entry point. Phase 0 exposes standards listing and config loading."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import yaml

from tollgate.classify import classify_changes
from tollgate.config import load_config, organisation_ids, parse_architecture_document
from tollgate.diff import parse_unified_diff
from tollgate.errors import ConfigError
from tollgate.llm.client import ModelUnreachable, RoleName, chat_for, probe_role
from tollgate.models import Finding, Verdict
from tollgate.pipeline import review_plan
from tollgate.planner import build_plan, render_plan
from tollgate.rank import Ranked
from tollgate.render.sarif import render_sarif
from tollgate.render.summary import render_json, render_markdown
from tollgate.sources.local_git import load_local_git
from tollgate.standards import load_catalogs, render_standards_list

app = typer.Typer(no_args_is_help=True, add_completion=False)
standards_app = typer.Typer(no_args_is_help=True, add_completion=False)
models_app = typer.Typer(no_args_is_help=True, add_completion=False)
app.add_typer(standards_app, name="standards")
app.add_typer(models_app, name="models")


def _organisation_from_cwd() -> tuple[str, ...]:
    path = Path.cwd() / ".tollgate" / "architecture.yaml"
    if not path.is_file():
        return ()
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ConfigError(".tollgate/architecture.yaml", "configuration must be a mapping")
    return organisation_ids(parse_architecture_document(loaded))


@standards_app.command("list")
def standards_list(
    catalog: str | None = typer.Option(None, "--catalog", help="Catalog file stem to print."),
) -> None:
    """Print every standards catalog, or one catalog."""
    text = render_standards_list(
        load_catalogs(),
        organisation=_organisation_from_cwd(),
        only=catalog,
    )
    typer.echo(text, nl=False)


@app.command()
def review(
    local: bool = typer.Option(False, "--local", help="Review a local git repository."),
    base: str = typer.Option("main", "--base", help="Base ref whose configuration is loaded."),
    head: str = typer.Option("HEAD", "--head", help="Head ref to diff against the merge base."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print review units and estimates without calling a model.",
    ),
    report_format: str = typer.Option("md", "--format", help="md, json, or sarif."),
) -> None:
    """Review a local checkout. Use --dry-run to skip the model."""
    if not local:
        raise ConfigError("mode", "review requires --local until a platform mode is implemented")
    if report_format not in {"md", "json", "sarif"}:
        raise ConfigError("format", "format must be md, json, or sarif")
    loaded = load_config(Path.cwd(), base_ref=base)
    typer.echo(f"configuration ok ({loaded.base_sha[:12]})")
    snapshot = load_local_git(Path.cwd(), base_ref=base, head_ref=head)
    diff_files = parse_unified_diff(snapshot.diff_text)
    sources = {
        item.path: snapshot.read_text(item.path, snapshot.head_sha)
        for item in diff_files
        if item.status != "deleted"
    }
    classified = classify_changes(
        diff_files,
        config=loaded.tollgate,
        attributes=snapshot.gitattributes(),
        sources=sources,
    )
    plan = build_plan(classified, loaded.tollgate)
    if dry_run:
        typer.echo(render_plan(plan), nl=False)
        return
    if not plan.units:
        empty = Ranked(findings=(), inline=(), summary_only=())
        _emit(report_format, empty, Verdict(outcome="pass"))
        return
    try:
        outcome = asyncio.run(
            review_plan(
                plan,
                config=loaded.tollgate,
                model=chat_for(loaded.tollgate, "review"),
                file_texts=sources,
                cache_dir=Path.cwd() / ".tollgate_cache",
                organisation=organisation_ids(loaded.architecture),
            )
        )
    except ModelUnreachable as exc:
        typer.echo(str(exc), err=True)
        raise SystemExit(3) from None
    _emit(report_format, outcome.ranked, outcome.verdict)
    if loaded.tollgate.mode != "comment" and outcome.verdict.outcome == "block":
        raise SystemExit(1)


def _emit(report_format: str, ranked: Ranked, verdict: Verdict) -> None:
    findings: list[Finding] = list(ranked.findings)
    if report_format == "json":
        typer.echo(render_json(findings, verdict), nl=False)
    elif report_format == "sarif":
        typer.echo(render_sarif(findings, verdict), nl=False)
    else:
        typer.echo(render_markdown(ranked, verdict), nl=False)


@models_app.command("check")
def models_check(
    base: str = typer.Option("main", "--base", help="Base ref whose configuration is loaded."),
) -> None:
    """Probe each configured role and print which output mode works."""
    loaded = load_config(Path.cwd(), base_ref=base)
    roles: tuple[RoleName, ...] = ("triage", "review", "critic")
    for role in roles:
        try:
            model_id, mode, elapsed = asyncio.run(probe_role(loaded.tollgate, role))
        except ModelUnreachable as exc:
            typer.echo(str(exc), err=True)
            raise SystemExit(3) from None
        typer.echo(f"{role} model={model_id} mode={mode} latency_s={elapsed:.3f}")


def main() -> None:
    try:
        app()
    except ConfigError as exc:
        typer.echo(exc.format_cli(), err=True)
        raise SystemExit(2) from None
