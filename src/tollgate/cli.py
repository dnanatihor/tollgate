"""Command-line entry point. Phase 0 exposes standards listing and config loading."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Literal

import httpx
import typer
import yaml

from tollgate.analyzers.run import analyze
from tollgate.classify import classify_changes
from tollgate.config import (
    TollgateConfig,
    load_config,
    organisation_ids,
    parse_architecture_document,
)
from tollgate.critic import apply_critic
from tollgate.diff import parse_unified_diff
from tollgate.errors import ConfigError
from tollgate.llm.client import ModelUnreachable, RoleName, chat_for, probe_role
from tollgate.llm.scripted import ScriptedChat
from tollgate.llm.structured import ChatBackend
from tollgate.models import Finding, Verdict
from tollgate.pipeline import review_plan
from tollgate.planner import build_plan, render_plan
from tollgate.rank import Ranked, rank_findings
from tollgate.render.sarif import render_sarif
from tollgate.render.summary import render_json, render_markdown
from tollgate.scm.bitbucket_cloud import BitbucketCloudProvider
from tollgate.scm.bitbucket_dc import BitbucketDataCenterProvider
from tollgate.scm.github import GitHubProvider, checkout_mode, is_fork_event
from tollgate.sources.local_git import load_local_git
from tollgate.standards import load_catalogs, render_standards_list
from tollgate.verdict import decide

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
    github: bool = typer.Option(False, "--github", help="Review the GitHub pull request in CI."),
    bitbucket_dc: bool = typer.Option(
        False,
        "--bitbucket-dc",
        help="Review a Bitbucket Data Center pull request.",
    ),
    project: str = typer.Option("", "--project", help="Data Center project key."),
    repo: str = typer.Option("", "--repo", help="Data Center repository slug."),
    pr_id: str = typer.Option("", "--pr", help="Data Center pull request id."),
    bitbucket_cloud: bool = typer.Option(
        False,
        "--bitbucket-cloud",
        help="Review the Bitbucket Cloud pull request in Pipelines.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print review units and estimates without calling a model.",
    ),
    report_format: str = typer.Option("md", "--format", help="md, json, or sarif."),
) -> None:
    """Review a local checkout. Use --dry-run to skip the model."""
    if github:
        _github_preflight()
    if bitbucket_cloud:
        _bitbucket_preflight()
    if bitbucket_dc:
        _dc_preflight(project, repo, pr_id)
    if not any((local, github, bitbucket_cloud, bitbucket_dc)):
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
    base_texts = {
        item.path: snapshot.read_text(item.path, snapshot.merge_base)
        for item in diff_files
        if item.status != "deleted"
    }
    analysis = analyze(
        diff_files,
        head_texts=sources,
        base_texts=base_texts,
        architecture=loaded.architecture,
        config=loaded.tollgate,
    )
    if not plan.units:
        ranked = rank_findings(list(analysis.findings), loaded.tollgate)
        verdict = decide(list(ranked.findings), loaded.tollgate)
        _emit(report_format, ranked, verdict, analysis.coverage)
        if github:
            _publish_github(ranked, verdict, loaded.tollgate.fingerprint(), loaded.tollgate.mode)
        if bitbucket_cloud:
            _publish_bitbucket(ranked, verdict, loaded.tollgate.fingerprint())
        if bitbucket_dc:
            _publish_dc(ranked, verdict, loaded.tollgate.fingerprint(), project, repo, pr_id)
        return
    try:
        if any(unit.lenses for unit in plan.units):
            model = _review_model(loaded.tollgate)
            outcome = asyncio.run(
                review_plan(
                    plan,
                    config=loaded.tollgate,
                    model=model,
                    file_texts=sources,
                    cache_dir=Path.cwd() / ".tollgate_cache",
                    organisation=organisation_ids(loaded.architecture),
                )
            )
            criticised = asyncio.run(
                apply_critic(
                    [*outcome.ranked.findings, *analysis.findings],
                    model=model,
                    config=loaded.tollgate,
                )
            )
        else:
            criticised = list(analysis.findings)
    except ModelUnreachable as exc:
        typer.echo(str(exc), err=True)
        raise SystemExit(3) from None
    merged = rank_findings(criticised, loaded.tollgate)
    verdict = decide(list(merged.findings), loaded.tollgate)
    _emit(report_format, merged, verdict, analysis.coverage)
    if github:
        _publish_github(merged, verdict, loaded.tollgate.fingerprint(), loaded.tollgate.mode)
    if bitbucket_cloud:
        _publish_bitbucket(merged, verdict, loaded.tollgate.fingerprint())
    if bitbucket_dc:
        _publish_dc(merged, verdict, loaded.tollgate.fingerprint(), project, repo, pr_id)
    if loaded.tollgate.mode != "comment" and verdict.outcome == "block":
        raise SystemExit(1)


def _review_model(config: TollgateConfig) -> ChatBackend:
    path = os.environ.get("TOLLGATE_SCRIPTED")
    if not path:
        return chat_for(config, "review")
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise ConfigError("TOLLGATE_SCRIPTED", "replies must be a JSON list")
    replies = [item if isinstance(item, str) else json.dumps(item) for item in loaded]
    return ScriptedChat(replies)


def _publish_github(ranked: Ranked, verdict: Verdict, config_hash: str, mode: str) -> None:
    event = _load_event()
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        raise ConfigError("github", "event has no pull_request object")
    base_repo = _mapping(pull.get("base"), "base").get("repo")
    repo_map = _mapping(base_repo, "base.repo")
    owner = str(_mapping(repo_map.get("owner"), "base.repo.owner").get("login", ""))
    repo = str(repo_map.get("name", ""))
    number = str(pull.get("number", ""))
    head = _mapping(pull.get("head"), "head")
    head_sha = str(head.get("sha", ""))
    markdown = render_markdown(ranked, verdict)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        Path(summary_path).write_text(markdown, encoding="utf-8")
    sarif_path = Path("tollgate.sarif")
    if is_fork_event(event):
        sarif_path.write_text(render_sarif(list(ranked.findings), verdict), encoding="utf-8")
        return

    async def publish() -> None:
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"},
        ) as client:
            provider = GitHubProvider(client, owner=owner, repo=repo, read_only=False)
            provider.write_sarif(sarif_path, list(ranked.findings), verdict)
            await provider.publish(
                number=number,
                head_sha=head_sha,
                findings=ranked.findings,
                verdict=verdict,
                markdown=markdown,
                config_hash=config_hash,
                mode=mode,
            )

    asyncio.run(publish())


def _load_event() -> dict[str, Any]:
    raw = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError("github", "event payload must be a JSON object")
    return raw


def _mapping(value: Any, key: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError("github", f"event is missing {key}")
    return value


def _bitbucket_preflight() -> None:
    missing = [
        name
        for name in (
            "BITBUCKET_WORKSPACE",
            "BITBUCKET_REPO_SLUG",
            "BITBUCKET_PR_ID",
            "BITBUCKET_COMMIT",
            "BITBUCKET_ACCESS_TOKEN",
        )
        if not os.environ.get(name)
    ]
    if missing:
        raise ConfigError("bitbucket", f"missing {missing[0]}")


def _publish_bitbucket(ranked: Ranked, verdict: Verdict, config_hash: str) -> None:
    workspace = os.environ["BITBUCKET_WORKSPACE"]
    repo = os.environ["BITBUCKET_REPO_SLUG"]
    number = os.environ["BITBUCKET_PR_ID"]
    commit = os.environ["BITBUCKET_COMMIT"]
    token = os.environ["BITBUCKET_ACCESS_TOKEN"]
    insights = os.environ.get("TOLLGATE_INSIGHTS_URL", "https://api.bitbucket.org/2.0")
    if os.environ.get("BITBUCKET_BUILD_NUMBER") and "TOLLGATE_INSIGHTS_URL" not in os.environ:
        insights = "http://localhost:29418"
    markdown = render_markdown(ranked, verdict)

    async def publish() -> None:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(headers=headers) as client:
            provider = BitbucketCloudProvider(
                client,
                workspace=workspace,
                repo=repo,
                insights_base=insights,
            )
            await provider.publish(
                number=number,
                commit=commit,
                findings=ranked.findings,
                verdict=verdict,
                markdown=markdown,
                config_hash=config_hash,
            )

    asyncio.run(publish())


def _dc_preflight(project: str, repo: str, pr_id: str) -> None:
    if not project or not repo or not pr_id:
        raise ConfigError("bitbucket_dc", "project, repo, and pr are required")
    if not os.environ.get("BITBUCKET_URL") or not os.environ.get("BITBUCKET_TOKEN"):
        raise ConfigError("bitbucket_dc", "BITBUCKET_URL and BITBUCKET_TOKEN are required")


def _publish_dc(
    ranked: Ranked,
    verdict: Verdict,
    config_hash: str,
    project: str,
    repo: str,
    pr_id: str,
) -> None:
    base_url = os.environ["BITBUCKET_URL"]
    token = os.environ["BITBUCKET_TOKEN"]
    markdown = render_markdown(ranked, verdict)
    line_types: dict[str, Literal["ADDED", "CONTEXT"]] = {
        item.fingerprint: "ADDED"
        for item in ranked.findings
        if item.file is not None and item.start_line is not None
    }

    async def publish() -> None:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(headers=headers) as client:
            provider = BitbucketDataCenterProvider(
                client,
                base_url=base_url,
                project=project,
                repo=repo,
            )
            await provider.publish(
                number=pr_id,
                commit=os.environ.get("BITBUCKET_COMMIT", "HEAD"),
                findings=ranked.findings,
                verdict=verdict,
                markdown=markdown,
                config_hash=config_hash,
                line_types=line_types,
            )

    asyncio.run(publish())


def _github_preflight() -> None:
    """Reject a GitHub run that would check out a head under pull_request_target."""
    event_name = os.environ.get("GITHUB_EVENT_NAME", "pull_request")
    if checkout_mode(event_name) == "api":
        raise ConfigError(
            "github",
            "pull_request_target cannot check out the pull request head; read the diff via the API",
        )
    if not os.environ.get("GITHUB_EVENT_PATH"):
        raise ConfigError("github", "GITHUB_EVENT_PATH is not set")
    if not os.environ.get("GITHUB_TOKEN"):
        raise ConfigError("github", "GITHUB_TOKEN is not set")


def _emit(
    report_format: str,
    ranked: Ranked,
    verdict: Verdict,
    coverage: tuple[object, ...] = (),
) -> None:
    findings: list[Finding] = list(ranked.findings)
    if report_format == "json":
        typer.echo(render_json(findings, verdict), nl=False)
    elif report_format == "sarif":
        typer.echo(render_sarif(findings, verdict), nl=False)
    else:
        typer.echo(render_markdown(ranked, verdict, coverage), nl=False)


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


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8080, "--port"),
) -> None:
    """Run the webhook service."""
    import uvicorn

    from tollgate.server.app import create_app

    uvicorn.run(create_app(), host=host, port=port)


def main() -> None:
    try:
        app()
    except ConfigError as exc:
        typer.echo(exc.format_cli(), err=True)
        raise SystemExit(2) from None
