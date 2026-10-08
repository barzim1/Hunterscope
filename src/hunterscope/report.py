from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from hunterscope.models import Event
from hunterscope.triage import Dossier


def _summary(e: Event) -> str:
    if e.source == "entra":
        where = ", ".join(x for x in (e.city, e.country) if x)
        reason = e.detail.get("reason") or ""
        return " · ".join(x for x in (e.app, where, f"err {e.error_code}", reason) if x)
    if e.source == "email":
        d = e.detail
        auth = "/".join(f"{k}={d.get(k) or '-'}" for k in ("spf", "dkim", "dmarc"))
        return f"{d.get('subject', '')} · from {d.get('from_addr', '?')} · {auth}"
    if e.source == "ual":
        params: dict[str, str] = e.detail.get("params", {})
        return "; ".join(f"{k}={v}" for k, v in list(params.items())[:4])
    return (e.command_line or e.app or "")[:140]


def _cell(value: object) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _mitre_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def make_env() -> Environment:
    env = Environment(
        loader=PackageLoader("hunterscope", "templates"),
        # HTML templates render untrusted log content (command lines, subjects): escape by default.
        autoescape=select_autoescape(enabled_extensions=("html.j2",), default=False),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["cell"] = _cell
    env.filters["summary"] = _summary
    env.filters["mitre_url"] = _mitre_url
    env.filters["id"] = id
    env.filters["ts"] = lambda d: d.strftime("%Y-%m-%d %H:%M:%S")
    return env


def render_markdown(d: Dossier, cfg: dict[str, Any]) -> str:
    limit = cfg["report"]["timeline_limit"]
    return make_env().get_template("dossier.md.j2").render(
        d=d,
        iocs=d.iocs(),
        flagged=d.flagged_ids,
        timeline=d.events[:limit],
        truncated=max(0, len(d.events) - limit),
    )


def render_json(d: Dossier) -> str:
    return json.dumps(d.to_dict(), indent=2, ensure_ascii=False)


# ATT&CK enterprise order; tactics HunterScope has no rule for still show up if a custom rule uses them.
TACTIC_ORDER = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
                "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
                "exfiltration", "impact"]


def tactic_chain(d: Dossier) -> list[dict[str, Any]]:
    seen: dict[str, int] = {}
    for f in d.findings:
        seen[f.tactic] = seen.get(f.tactic, 0) + 1
    names = TACTIC_ORDER + sorted(t for t in seen if t not in TACTIC_ORDER)
    return [{"name": n, "on": n in seen, "count": seen.get(n, 0)} for n in names]


def _stamp(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S")


def render_html(d: Dossier, cfg: dict[str, Any]) -> str:
    from hunterscope import __version__

    limit = cfg["report"]["timeline_limit"]
    points = [c.points for c in d.score.contributions] + [d.score.bonus]
    return make_env().get_template("dossier.html.j2").render(
        d=d,
        iocs=d.iocs(),
        flagged=d.flagged_ids,
        timeline=d.events[:limit],
        truncated=max(0, len(d.events) - limit),
        tactics=tactic_chain(d),
        max_points=max(points) or 1,
        version=__version__,
        generated=_stamp(d.generated),
    )
