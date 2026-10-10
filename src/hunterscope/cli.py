from __future__ import annotations

import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from hunterscope import coverage as cov
from hunterscope.casestore import STATUSES, CaseStore, default_db_path, iso
from hunterscope.config.loader import load_redactor_config, load_rules_config
from hunterscope.handover import Handover, build_handover
from hunterscope.handover import render_html as render_handover_html
from hunterscope.handover import render_markdown as render_handover_md
from hunterscope.ingest import load_events
from hunterscope.models import host_key, user_key
from hunterscope.redactor import Redactor
from hunterscope.report import render_html, render_json, render_markdown
from hunterscope.triage import build_dossier, parse_timerange

app = typer.Typer(add_completion=False, no_args_is_help=True, help="HunterScope: SOC triage dossiers.")
case_app = typer.Typer(no_args_is_help=True, help="Work with saved cases (SQLite).")
app.add_typer(case_app, name="case")
err = Console(stderr=True)

DbOpt = Annotated[Path | None, typer.Option("--db", help="Case DB (default: $HUNTERSCOPE_DB or ~/.hunterscope/cases.db)")]
AuthorOpt = Annotated[str | None, typer.Option("--author", help="Analyst name (default: $HUNTERSCOPE_ANALYST or OS user)")]


def _author(value: str | None) -> str:
    return value or os.environ.get("HUNTERSCOPE_ANALYST") or getpass.getuser()


def _open_store(db: Path | None) -> CaseStore:
    return CaseStore(db or default_db_path())


def _parse_timestamp(value: str, option: str) -> datetime:
    """ISO 8601, naive means UTC. Accepts a trailing 'Z', which datetime.fromisoformat only does from 3.11."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise typer.BadParameter(f"invalid timestamp '{value}' for {option}", param_hint=option) from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_until(value: str) -> datetime:
    return datetime.now(timezone.utc) if value == "now" else _parse_timestamp(value, "--until")


def _redactor(redactor_config: Path | None, key_env: str | None, users: list[str], hosts: list[str]) -> Redactor:
    key = None
    if key_env:
        raw = os.environ.get(key_env)
        if not raw:
            raise typer.BadParameter(f"environment variable {key_env} is empty or unset")
        key = raw.encode()
    return Redactor(load_redactor_config(redactor_config), key, users, hosts)


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
    fmt: Annotated[str, typer.Option("--format", "-f", help="md | json | html")] = "md",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option(help="Rules config overriding defaults")] = None,
    redactor_config: Annotated[Path | None, typer.Option(help="Redactor config overriding defaults")] = None,
    save: Annotated[bool, typer.Option("--save", help="Record/update a case in the case DB")] = False,
    db: DbOpt = None,
    author: AuthorOpt = None,
) -> None:
    """Build an investigation dossier for a user or a host."""
    if (user is None) == (host is None):
        raise typer.BadParameter("provide exactly one of --user / --host")
    if fmt not in {"md", "json", "html"}:
        raise typer.BadParameter("--format must be md, json or html")
    try:
        window = parse_timerange(timerange)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    from datetime import datetime, timezone

    anchor_dt = None
    if anchor == "now":
        anchor_dt = datetime.now(timezone.utc)
    elif anchor != "latest":
        anchor_dt = _parse_timestamp(anchor, "--anchor")

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

    renderers = {"md": lambda: render_markdown(dossier, cfg), "json": lambda: render_json(dossier),
                 "html": lambda: render_html(dossier, cfg)}
    text = renderers[fmt]()

    if save:
        with _open_store(db) as store:
            res = store.upsert_from_dossier(dossier, _author(author))
        verb = "opened" if res.created else "updated"
        err.print(f"[cyan]Case #{res.case_id} {verb}[/cyan] ({res.new_findings} new finding(s)). "
                  f"Set outcome: hunterscope case status {res.case_id} <status> --note ...")

    if redact:
        redactor = _redactor(redactor_config, key_env, [user_key(user)] if user else [], [host_key(host)] if host else [])
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
    elif fmt == "html" and sys.stdout.isatty():
        raise typer.BadParameter("HTML belongs in a file: use -o report.html")
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


@case_app.command("list")
def case_list(db: DbOpt = None, all_: Annotated[bool, typer.Option("--all", help="Include closed cases")] = False) -> None:
    """List cases (open ones by default)."""
    with _open_store(db) as store:
        cases = store.list_cases(open_only=not all_)
    table = Table(title="Cases")
    for col in ("ID", "Target", "Risk", "Status", "Updated (UTC)"):
        table.add_column(col)
    for c in cases:
        table.add_row(str(c.id), f"{c.kind} {c.target}", f"{c.score} ({c.level})", c.status_label,
                      iso(c.updated_at).replace("+00:00", "").replace("T", " "))
    Console().print(table)


@case_app.command("show")
def case_show(case_id: int, db: DbOpt = None) -> None:
    """Show a case: findings and the full audit log."""
    with _open_store(db) as store:
        try:
            case = store.get_case(case_id)
        except KeyError as exc:
            err.print(f"[red]{exc.args[0]}[/red]")
            raise typer.Exit(2) from exc
        findings, log = store.findings(case_id), store.log(case_id)
    out = Console()
    out.print(f"[bold]Case #{case.id}[/bold] {case.kind} [bold]{case.target}[/bold] · {case.status_label} · "
              f"risk {case.score}/100 ({case.level})")
    for f in findings:
        out.print(f"  [{f['severity']}] {f['title']} ({f['mitre']}) - {f['description']}", highlight=False)
    out.print("[dim]Log[/dim]")
    for e in log:
        change = f" {e.from_status} -> {e.to_status}" if e.kind == "status" else ""
        out.print(f"  {iso(e.ts)} {e.author} {e.kind}{change}: {e.text}", highlight=False)


@case_app.command("status")
def case_status(
    case_id: int,
    status: Annotated[str, typer.Argument(help=" | ".join(STATUSES))],
    note: Annotated[str, typer.Option("--note", "-n", help="Required for escalations and closures")] = "",
    db: DbOpt = None,
    author: AuthorOpt = None,
) -> None:
    """Change a case status (closures and escalations need --note)."""
    with _open_store(db) as store:
        try:
            store.set_status(case_id, status, _author(author), note)
        except KeyError as exc:
            err.print(f"[red]{exc.args[0]}[/red]")
            raise typer.Exit(2) from exc
        except ValueError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
    err.print(f"[green]Case #{case_id} -> {STATUSES[status]}[/green]")


@case_app.command("note")
def case_note(case_id: int, text: str, db: DbOpt = None, author: AuthorOpt = None) -> None:
    """Add a note to a case."""
    with _open_store(db) as store:
        try:
            store.add_note(case_id, _author(author), text)
        except KeyError as exc:
            err.print(f"[red]{exc.args[0]}[/red]")
            raise typer.Exit(2) from exc
        except ValueError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc


def _handover_tables(ho: Handover) -> None:
    out = Console()
    out.print(f"[bold]Shift handover[/bold] {iso(ho.since)} -> {iso(ho.until)} · {ho.analyst}")
    out.print(f"opened [bold]{ho.opened}[/bold] · closed FP [green]{len(ho.closed_fp)}[/green] · closed TP "
              f"[red]{len(ho.closed_tp)}[/red] · escalated [yellow]{len(ho.escalated)}[/yellow] · unresolved "
              f"[bold]{len(ho.unresolved)}[/bold]")
    sections = (
        ("Unresolved: needs follow-up", ho.unresolved, "yellow"),
        ("Escalated", ho.escalated, "magenta"),
        ("Closed: False Positive", ho.closed_fp, "green"),
        ("Closed: True Positive", ho.closed_tp, "red"),
    )
    for title, views, color in sections:
        table = Table(title=title, title_style=f"bold {color}", title_justify="left", show_lines=False)
        for col in ("Case", "Target", "Risk", "Status", "Detail"):
            table.add_column(col)
        for v in views:
            flags = (" STALE" if v.stale else "") + (" new" if v.new_this_shift else "")
            detail = v.decision_note if v.case.status in {"closed_fp", "closed_tp", "escalated_l2", "escalated_l3"} \
                else "; ".join(v.top_findings)
            table.add_row(f"#{v.case.id}{flags}", f"{v.case.kind} {v.case.target}", f"{v.case.score} ({v.case.level})",
                          v.case.status_label, detail)
        out.print(table if views else f"[dim]{title}: none[/dim]")


@app.command("shift-summary")
def shift_summary(
    hours: Annotated[float, typer.Option("--hours", help="Shift length")] = 12,
    until: Annotated[str, typer.Option(help="Window end: 'now' or ISO timestamp")] = "now",
    fmt: Annotated[str, typer.Option("--format", "-f", help="auto | terminal | md | html")] = "auto",
    redact: Annotated[bool, typer.Option("--redact", help="Pseudonymize before output (md text)")] = False,
    key_env: Annotated[str | None, typer.Option(help="Env var with an HMAC key for stable pseudonyms")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option(help="Rules config overriding defaults")] = None,
    redactor_config: Annotated[Path | None, typer.Option(help="Redactor config overriding defaults")] = None,
    db: DbOpt = None,
    author: AuthorOpt = None,
) -> None:
    """Handover for the next shift: unresolved anomalies, escalations and closures."""
    if fmt not in {"auto", "terminal", "md", "html"}:
        raise typer.BadParameter("--format must be auto, terminal, md or html")
    if hours <= 0:
        raise typer.BadParameter("--hours must be positive")
    cfg = load_rules_config(config)
    with _open_store(db) as store:
        ho = build_handover(store, _parse_until(until), hours, cfg, _author(author))

    if fmt == "auto":
        fmt = "md" if output or not sys.stdout.isatty() or redact else "terminal"
    if fmt == "terminal" and not redact and not output:
        _handover_tables(ho)
        return
    text = render_handover_html(ho) if fmt == "html" else render_handover_md(ho)
    if redact:
        users = [t for k, t in ho.targets if k == "user"]
        hosts = [t for k, t in ho.targets if k == "host"]
        text = _redactor(redactor_config, key_env, [user_key(u) for u in users], [host_key(h) for h in hosts]).redact(text)
    if output:
        output.write_text(text, encoding="utf-8")
        err.print(f"[green]Handover written to {output}[/green]")
    elif sys.stdout.isatty() and fmt == "md":
        Console().print(Markdown(text))
    elif sys.stdout.isatty():
        raise typer.BadParameter("HTML belongs in a file: use -o handover.html")
    else:
        typer.echo(text)


@app.command("coverage")
def coverage_cmd(
    otrf: Annotated[Path | None, typer.Option(exists=True, file_okay=False, help="Checkout of OTRF/Security-Datasets")] = None,
    evtx: Annotated[Path | None, typer.Option(exists=True, file_okay=False, help="Checkout of EVTX-ATTACK-SAMPLES")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option(help="Rules config overriding defaults")] = None,
    ablate: Annotated[str, typer.Option(help="Comma-separated rule ids: also run without them and report the delta")] = "",
) -> None:
    """Measure rule coverage against public labelled datasets (see scripts/fetch_datasets.py)."""
    if otrf is None and evtx is None:
        raise typer.BadParameter("give at least one of --otrf / --evtx")
    cfg = load_rules_config(config)
    otrf_results = None
    evtx_rows = None
    baseline = None
    ablated: tuple[str, ...] = ()
    if otrf:
        datasets = cov.load_otrf(otrf)
        if not datasets:
            err.print("[red]No labelled Windows datasets found. Run scripts/fetch_datasets.py first.[/red]")
            raise typer.Exit(2)
        err.print(f"Running {len(datasets)} OTRF datasets...")
        otrf_results = cov.run_otrf(datasets, cfg)
        ablated = tuple(r.strip() for r in ablate.split(",") if r.strip())
        unknown = [r for r in ablated if r not in cfg["rules"]]
        if unknown:
            raise typer.BadParameter(f"unknown rule(s): {', '.join(unknown)}")
        baseline = cov.run_otrf(datasets, cfg, also_disable=ablated) if ablated else None
    if evtx:
        err.print("Running EVTX samples...")
        try:
            evtx_rows = cov.run_evtx(evtx, cfg)
        except RuntimeError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
    text = cov.render(otrf_results, evtx_rows, cfg, cov.git_head(otrf) if otrf else "",
                      cov.git_head(evtx) if evtx else "", baseline, ablated)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        err.print(f"[green]Coverage report written to {output}[/green]")
    else:
        typer.echo(text)


@app.command("train")
def train_cmd(
    port: Annotated[int, typer.Option(help="Local port for the trainer UI")] = 8765,
    db: Annotated[Path | None, typer.Option("--db", help="Progress DB (default: $HUNTERSCOPE_TRAINER_DB or ~/.hunterscope/trainer.db)")] = None,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Do not open a browser tab")] = False,
) -> None:
    """SOC L1 trainer: generated alerts and logs, hidden verdict, scored debrief (local web UI, synthetic data)."""
    import webbrowser

    from hunterscope.trainer.server import make_server
    from hunterscope.trainer.store import TrainerStore, default_db_path

    store = TrainerStore(db or default_db_path())
    try:
        server = make_server("127.0.0.1", port, store)
    except OSError as exc:
        err.print(f"[red]Cannot listen on 127.0.0.1:{port}: {exc}[/red]")
        raise typer.Exit(2) from exc
    url = f"http://localhost:{server.server_address[1]}/"
    err.print(f"Trainer running at [bold]{url}[/bold] (progress: {store.path}). Ctrl+C to stop.")
    if not no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        err.print("Stopped.")
    finally:
        server.server_close()


@app.command("train-export")
def train_export_cmd(
    token: Annotated[str, typer.Argument(help="Scenario token, e.g. 482133-ps_encoded-2-p")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="NDJSON file (default: stdout)")] = None,
    with_truth: Annotated[bool, typer.Option("--with-truth", help="Include the verdict and key/herring marks (spoils the exercise)")] = False,
) -> None:
    """Export a scenario's events as NDJSON, to practice queries in your own SIEM."""
    from hunterscope.trainer.scenarios import generate

    try:
        scn = generate(token)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    lines = []
    for e in scn.events:
        row = e.public()
        if with_truth:
            row |= {"role": e.role, "note": e.note}
        lines.append(json.dumps(row, ensure_ascii=False))
    if with_truth:
        lines.append(json.dumps({"truth": scn.truth.verdict, "summary": scn.truth.summary}, ensure_ascii=False))
    text = "\n".join(lines) + "\n"
    if output:
        output.write_text(text, encoding="utf-8")
        err.print(f"[green]{len(scn.events)} events written to {output}[/green]")
    else:
        typer.echo(text, nl=False)
