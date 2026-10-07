from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from hunterscope.models import Event
from hunterscope.triage import Dossier


def _summary(e: Event) -> str:
    if e.source == "entra":
        where = ", ".join(x for x in (e.city, e.country) if x)
        reason = e.detail.get("reason") or ""
        return " · ".join(x for x in (e.app, where, f"err {e.error_code}", reason) if x)
    if e.source == "ual":
        params: dict[str, str] = e.detail.get("params", {})
        return "; ".join(f"{k}={v}" for k, v in list(params.items())[:4])
    return (e.command_line or e.app or "")[:140]


def _cell(value: object) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _mitre_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("hunterscope", "templates"),
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
    return _env().get_template("dossier.md.j2").render(
        d=d,
        iocs=d.iocs(),
        flagged=d.flagged_ids,
        timeline=d.events[:limit],
        truncated=max(0, len(d.events) - limit),
    )


def render_json(d: Dossier) -> str:
    return json.dumps(d.to_dict(), indent=2, ensure_ascii=False)
