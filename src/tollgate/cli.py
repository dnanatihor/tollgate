"""Command-line entry point. Phase 0 exposes standards listing and config loading."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml

from tollgate.config import load_config, organisation_ids, parse_architecture_document
from tollgate.errors import ConfigError
from tollgate.standards import load_catalogs, render_standards_list

app = typer.Typer(no_args_is_help=True, add_completion=False)
standards_app = typer.Typer(no_args_is_help=True, add_completion=False)
app.add_typer(standards_app, name="standards")


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
) -> None:
    """Load configuration from the base ref. The review pipeline starts in Phase 1."""
    if not local:
        raise ConfigError("mode", "review requires --local until a platform mode is implemented")
    loaded = load_config(Path.cwd(), base_ref=base)
    typer.echo(f"configuration ok ({loaded.base_sha[:12]})")


def main() -> None:
    try:
        app()
    except ConfigError as exc:
        typer.echo(exc.format_cli(), err=True)
        raise SystemExit(2) from None
