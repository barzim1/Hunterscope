from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from hunterscope.config.loader import load_redactor_config, load_rules_config
from hunterscope.ingest import load_events
from hunterscope.models import host_key, user_key
from hunterscope.redactor import Redactor
from hunterscope.report import render_json, render_markdown
from hunterscope.triage import build_dossier, parse_timerange

app = typer.Typer(add_completion=False, no_args_is_help=True, help="HunterScope: SOC triage dossiers.")
err = Console(stderr=True)


@app.callback()
def _main() -> None:
    """HunterScope: identity-centric investigation & dossier engine."""


@app.command()
def triage(
    inputs: Annotated[
        list[Path], typer.Option("--input", "-i", exists=True, help="JSON/NDJSON export, .eml or a directory of them (repeatable)")
    ],
    user: Annotated[str | None, typer.Option("--user", "-u", help="UPN, sAMAccountName or DOMAIN\\user")] = None,
    host: Annotated[str | None, typer.Option("--host", "-H", help="Hostname (FQDN suffix ignored)")] = None,
    timerange: Annotated[str, typer.Option("--timerange", "-t", help="e.g. 90m, 24h, 7d")] = "24h",
    anchor: Annotated[str, typer.Option(help="Window end: 'latest' (offline data), 'now' or ISO timestamp")] = "latest",
    redact: Annotated[bool, typer.Option("--redact", help="Pseudonymize PII before output")] = False,
    key_env: Annotated[str | None, typer.Option(help="Env var holding an HMAC key for stable pseudonyms across runs")] = None,
    mapping_out: Annotated[Path | None, typer.Option(help="Write label->original mapping (SENSITIVE)")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="md | json")] = "md",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option(help="Rules config overriding defaults")] = None,
    redactor_config: Annotated[Path | None, typer.Option(help="Redactor config overriding defaults")] = None,
) -> None:
    """Build an investigation dossier for a user or a host."""
    if (user is None) == (host is None):
        raise typer.BadParameter("provide exactly one of --user / --host")
    if fmt not in {"md", "json"}:
        raise typer.BadParameter("--format must be md or json")
    try:
        window = parse_timerange(timerange)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    from datetime import datetime, timezone

    anchor_dt = None
    if anchor == "now":
        anchor_dt = datetime.now(timezone.utc)
    elif anchor != "latest":
        anchor_dt = datetime.fromisoformat(anchor)
        if anchor_dt.tzinfo is None:
            anchor_dt = anchor_dt.replace(tzinfo=timezone.utc)

    cfg = load_rules_config(config)
    loaded = load_events(inputs)
    kind, target = ("user", user) if user else ("host", host or "")
    try:
        dossier = build_dossier(
            loaded.events, kind, target, window, cfg,
            anchor=anchor_dt, skipped=loaded.skipped,
        )
    except LookupError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    text = render_markdown(dossier, cfg) if fmt == "md" else render_json(dossier)

    if redact:
        key = None
        if key_env:
            raw = os.environ.get(key_env)
            if not raw:
                raise typer.BadParameter(f"environment variable {key_env} is empty or unset")
            key = raw.encode()
        known_users = [user_key(user)] if user else []
        known_hosts = [host_key(host)] if host else []
        redactor = Redactor(load_redactor_config(redactor_config), key, known_users, known_hosts)
        text = redactor.redact(text)
        if mapping_out:
            mapping_out.write_text(json.dumps(redactor.mapping(), indent=2), encoding="utf-8")
            err.print(f"[yellow]Mapping written to {mapping_out}: contains real values, do not share.[/yellow]")
    elif mapping_out:
        raise typer.BadParameter("--mapping-out requires --redact")

    if output:
        output.write_text(text, encoding="utf-8")
        err.print(f"[green]Report written to {output}[/green] (score {dossier.score.total}/100, {dossier.score.level})")
    elif fmt == "md" and sys.stdout.isatty():
        Console().print(Markdown(text))
    else:
        typer.echo(text)


@app.command()
def rules(config: Annotated[Path | None, typer.Option()] = None) -> None:
    """List loaded detection rules with their MITRE ATT&CK mapping."""
    cfg = load_rules_config(config)
    table = Table(title="Detection rules")
    for col in ("Rule", "On", "Severity", "Weight", "Tactic", "MITRE"):
        table.add_column(col)
    for rid, r in cfg["rules"].items():
        table.add_row(rid, "yes" if r.get("enabled", True) else "no", r["severity"],
                      str(r["weight"]), r["tactic"], ", ".join(r["mitre"]))
    Console().print(table)
