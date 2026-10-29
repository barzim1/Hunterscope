from __future__ import annotations

import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from hunterscope import coverage as cov
from hunterscope import explain as exp
from hunterscope import llm as llm_mod
from hunterscope.casestore import STATUSES, CaseStore, default_db_path, iso
from hunterscope.config.loader import load_knowledge, load_redactor_config, load_rules_config
from hunterscope.handover import Handover, build_handover
from hunterscope.handover import render_html as render_handover_html
from hunterscope.handover import render_markdown as render_handover_md
from hunterscope.ingest import load_events
from hunterscope.llm import DEFAULT_MODEL
from hunterscope.models import host_key, user_key
from hunterscope.redactor import Redactor
from hunterscope.report import render_html, render_json, render_markdown
from hunterscope.triage import build_dossier, parse_timerange

app = typer.Typer(add_completion=False, no_args_is_help=True, help="HunterScope: SOC triage dossiers.")
case_app = typer.Typer(no_args_is_help=True, help="Work with saved cases (SQLite).")
app.add_typer(case_app, name="case")
err = Console(stderr=True)

MAX_LLM_GAPS = 5  # `explain --llm` on a dossier asks about at most this many uncovered kinds of event

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


def _resolve_anchor(anchor: str) -> datetime | None:
    """'latest' -> None (end the window at the target's newest event), 'now', or an ISO timestamp."""
    if anchor == "latest":
        return None
    if anchor == "now":
        return datetime.now(timezone.utc)
    return _parse_timestamp(anchor, "--anchor")


def _redactor(redactor_config: Path | None, key_env: str | None, users: list[str], hosts: list[str],
              overrides: dict[str, object] | None = None) -> Redactor:
    key = None
    if key_env:
        raw = os.environ.get(key_env)
        if not raw:
            raise typer.BadParameter(f"environment variable {key_env} is empty or unset")
        key = raw.encode()
    return Redactor({**load_redactor_config(redactor_config), **(overrides or {})}, key, users, hosts)


def _llm_redactor(redactor_config: Path | None, key_env: str | None, users: list[str], hosts: list[str]) -> Redactor:
    """Stricter than the offline default: the model gains nothing from public IPs or external addresses, and
    the company's own egress IP is public too."""
    return _redactor(redactor_config, key_env, users, hosts,
                     overrides={"keep_public_ips": False, "keep_external_emails": False})


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

    cfg = load_rules_config(config)
    loaded = load_events(inputs)
    kind, target = ("user", user) if user else ("host", host or "")
    try:
        dossier = build_dossier(
            loaded.events, kind, target, window, cfg,
            anchor=_resolve_anchor(anchor), skipped=loaded.skipped,
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


@app.command("explain")
def explain_cmd(
    terms: Annotated[
        list[str] | None,
        typer.Argument(help="What to explain: Windows/Sysmon event id (4688), Entra code (50126), process "
                            "(certutil.exe), M365 operation, ATT&CK id (T1003.001) or rule id. Prefixes event: "
                            "sysmon: entra: proc: ual: tech: rule: narrow the search."),
    ] = None,
    inputs: Annotated[
        list[Path] | None,
        typer.Option("--input", "-i", exists=True, help="Instead of terms: explain what a dossier for --user/--host contains"),
    ] = None,
    log: Annotated[
        str | None,
        typer.Option("--log", help="Instead of terms: a raw log line or text to explain ('-' = stdin)"),
    ] = None,
    user: Annotated[str | None, typer.Option("--user", "-u", help="UPN, sAMAccountName or DOMAIN\\user")] = None,
    host: Annotated[str | None, typer.Option("--host", "-H", help="Hostname (FQDN suffix ignored)")] = None,
    timerange: Annotated[str, typer.Option("--timerange", "-t", help="e.g. 90m, 24h, 7d")] = "24h",
    anchor: Annotated[str, typer.Option(help="Window end: 'latest' (offline data), 'now' or ISO timestamp")] = "latest",
    redact: Annotated[bool, typer.Option("--redact", help="Pseudonymize the target before output (dossier mode)")] = False,
    key_env: Annotated[str | None, typer.Option(help="Env var holding an HMAC key for stable pseudonyms across runs")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="md | json")] = "md",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    kb: Annotated[Path | None, typer.Option(help="Knowledge base overriding/extending the defaults")] = None,
    config: Annotated[Path | None, typer.Option(help="Rules config overriding defaults")] = None,
    redactor_config: Annotated[Path | None, typer.Option(help="Redactor config overriding defaults")] = None,
    llm: Annotated[bool, typer.Option("--llm", help="Ask an LLM about what the knowledge base cannot cover. "
                                                   "Text is pseudonymized first; see --dry-run")] = False,
    model: Annotated[str, typer.Option(envvar="HUNTERSCOPE_LLM_MODEL", help="Model for --llm")] = DEFAULT_MODEL,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="With --llm: print exactly what would be sent, send nothing")] = False,
    mask_user: Annotated[list[str] | None, typer.Option("--mask-user", help="Name to pseudonymize before sending (repeatable)")] = None,
    mask_host: Annotated[list[str] | None, typer.Option("--mask-host", help="Short hostname to pseudonymize before sending (repeatable)")] = None,
    allow_default_redaction: Annotated[bool, typer.Option("--allow-default-redaction", help="Send even though --redactor-config is "
                                                          "not set (the default config only knows the fictional contoso.com)")] = False,
) -> None:
    """Explain in plain language what an event, code, process, log line or dossier means."""
    if fmt not in {"md", "json"}:
        raise typer.BadParameter("--format must be md or json")
    modes = [bool(terms), bool(inputs), log is not None]
    if sum(modes) != 1:
        raise typer.BadParameter("give exactly one of: terms to look up, --input with --user/--host, or --log")
    dossier_mode, log_mode = bool(inputs), log is not None
    if dossier_mode and (user is None) == (host is None):
        raise typer.BadParameter("provide exactly one of --user / --host")
    if not dossier_mode and (user or host or redact):
        raise typer.BadParameter("--user/--host/--redact only apply together with --input")
    if (dry_run or mask_user or mask_host or allow_default_redaction) and not llm:
        raise typer.BadParameter("--dry-run/--mask-user/--mask-host/--allow-default-redaction only apply with --llm")
    if llm and redactor_config is None and not allow_default_redaction:
        raise typer.BadParameter(
            "refusing to send text without a redactor config: the default only knows the fictional contoso.com, "
            "so your real domain and usernames would pass through. Pass --redactor-config FILE (see "
            "src/hunterscope/config/redactor.yaml), or --allow-default-redaction if you accept that, and check "
            "what would be sent with --dry-run first.")
    try:
        base = exp.KnowledgeBase(load_knowledge(kb))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise typer.BadParameter(f"cannot load knowledge base: {exc}") from exc

    def ask_llm(texts: list[tuple[str, str]]) -> list[tuple[str, llm_mod.Prepared, llm_mod.LLMExplanation | None]]:
        """Pseudonymize, build and (unless --dry-run) send each (label, text). Raises LLMError."""
        redactor = _llm_redactor(redactor_config, key_env, mask_user or [], mask_host or [])
        prepared = [(label, llm_mod.prepare(text, base, redactor)) for label, text in texts]
        if dry_run:
            return [(label, p, None) for label, p in prepared]
        client = llm_mod.make_client(model)
        out = []
        for label, p in prepared:
            err.print(f"[cyan]Sending {p.sent_chars} characters (pseudonymized) to {model}...[/cyan]")
            out.append((label, p, llm_mod.explain_with_llm(p, client)))
        return out

    def dry_run_text(batch: list[tuple[str, llm_mod.Prepared, llm_mod.LLMExplanation | None]]) -> str:
        return "\n".join(llm_mod.render_dry_run(model, p) for _, p, _ in batch)

    missing = False
    try:
        if dossier_mode:
            try:
                window = parse_timerange(timerange)
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            cfg = load_rules_config(config)
            loaded = load_events(inputs or [])
            kind, target = ("user", user) if user else ("host", host or "")
            try:
                dossier = build_dossier(loaded.events, kind, target, window, cfg,
                                        anchor=_resolve_anchor(anchor), skipped=loaded.skipped)
            except LookupError as exc:
                err.print(f"[red]{exc}[/red]")
                raise typer.Exit(2) from exc
            explained = exp.explain_dossier(dossier, base)
            batch = []
            if llm and explained.gaps:  # only the kinds of event the base lacks, and only as ids, never raw events
                batch = ask_llm([(f"{exp.TABLES[t]} {k}", f"{exp.TABLES[t]} {k}") for t, k, _ in explained.gaps[:MAX_LLM_GAPS]])
            if dry_run:
                text = dry_run_text(batch) if batch else "Brak rodzajów zdarzeń bez wpisu: nic do wysłania.\n"
            elif fmt == "json":
                data = exp.dossier_to_dict(explained)
                data["llm"] = [{"term": label, **llm_mod.llm_to_dict(x)} for label, _, x in batch if x]
                text = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                text = exp.render_dossier_markdown(explained)
                if batch:
                    text += "\n## Wyjaśnienia modelu dla zdarzeń bez wpisu w bazie\n\n"
                    for label, _, x in batch:
                        text += f"### {label}\n\n" + llm_mod.render_llm_markdown(x, "####") + "\n"  # type: ignore[arg-type]
            if redact:
                redactor = _redactor(redactor_config, key_env, [user_key(user)] if user else [],
                                     [host_key(host)] if host else [])
                text = redactor.redact(text)
        elif log_mode:
            raw = sys.stdin.read() if log == "-" else Path(log or "").read_text(encoding="utf-8", errors="replace")
            entries = exp.ground(raw, base)
            batch = ask_llm([("log", raw)]) if llm else []
            if dry_run:
                text = dry_run_text(batch)
            elif fmt == "json":
                data = {"known": [x.to_dict() for x in entries]}
                data["llm"] = llm_mod.llm_to_dict(batch[0][2]) if batch and batch[0][2] else None  # type: ignore[assignment]
                text = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                text = exp.render_log_markdown(entries)
                if batch and batch[0][2]:
                    text += "\n" + llm_mod.render_llm_markdown(batch[0][2])
        else:
            results = [(t, exp.lookup(t, base)) for t in terms or []]
            unknown = [t for t, found in results if not found]
            missing = bool(unknown) and not llm
            batch = ask_llm([(t, t) for t in unknown]) if llm and unknown else []
            by_term = {label: x for label, _, x in batch if x}
            if dry_run:
                text = dry_run_text(batch) if batch else "Wszystkie terminy są w bazie: nic do wysłania.\n"
            elif fmt == "json":
                data = exp.lookup_to_dict(results)
                for item in data:
                    if item["term"] in by_term:
                        item["llm"] = llm_mod.llm_to_dict(by_term[item["term"]])
                text = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                text = exp.render_lookup_markdown(results)
                for term, x in by_term.items():
                    text += f"\n## `{term}`: odpowiedź modelu\n\n" + llm_mod.render_llm_markdown(x, "###")
    except llm_mod.LLMError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(3) from exc
    except ValueError as exc:  # a knowledge base entry missing a required field
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    if output:
        output.write_text(text, encoding="utf-8")
        err.print(f"[green]Explanation written to {output}[/green]")
    elif fmt == "md" and sys.stdout.isatty():
        Console().print(Markdown(text))
    else:
        typer.echo(text)
    if missing:
        raise typer.Exit(1)


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
