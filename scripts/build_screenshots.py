"""Rebuild docs/examples/*.html and docs/img/*.png from the synthetic samples.

Deterministic: fixed case timestamps, fixed analyst name, no real data. Needs Playwright and a Chromium:

    pip install -e ".[shots]"
    python scripts/build_screenshots.py [/path/to/chrome]

Without a path Playwright's own browser is used (`playwright install chromium`).
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from hunterscope.casestore import CaseStore
from hunterscope.config.loader import load_redactor_config, load_rules_config
from hunterscope.handover import build_handover
from hunterscope.handover import render_html as handover_html
from hunterscope.ingest import load_events
from hunterscope.redactor import Redactor
from hunterscope.report import render_html as dossier_html
from hunterscope.triage import build_dossier, parse_timerange

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "samples"
EXAMPLES = ROOT / "docs" / "examples"
IMG = ROOT / "docs" / "img"


def at(day: int, hh: int, mm: int) -> datetime:
    return datetime(2026, 3, day, hh, mm, tzinfo=timezone.utc)


def build_html() -> dict[str, str]:
    cfg = load_rules_config()
    loaded = load_events([SAMPLES])
    day = parse_timerange("24h")

    def dossier(kind: str, target: str):
        return build_dossier(loaded.events, kind, target, day, cfg, skipped=loaded.skipped)

    jk = dossier("user", "jkowalski")
    out = {"dossier-jkowalski": dossier_html(jk, cfg)}

    # A plausible shift: one escalation, one closure, one live case, one forgotten (stale) case.
    with tempfile.TemporaryDirectory() as tmp, CaseStore(Path(tmp) / "demo.db") as store:
        old = store.upsert_from_dossier(dossier("user", "bkowalczyk"), "marek", at(9, 15, 0))
        c_jk = store.upsert_from_dossier(jk, "anna", at(11, 10, 45)).case_id
        c_ak = store.upsert_from_dossier(dossier("user", "akowalska"), "anna", at(11, 9, 15)).case_id
        c_ws = store.upsert_from_dossier(dossier("host", "ws-jkowalski"), "anna", at(11, 10, 50)).case_id
        assert old.created
        store.set_status(c_ak, "closed_fp", "anna",
                         "Business trip WAW->LHR, 3 typos then success; no spray pattern.", at(11, 9, 40))
        store.set_status(c_jk, "in_progress", "anna", now=at(11, 10, 55))
        store.add_note(c_jk, "anna", "Password reset forced; waiting for the user to call back.", at(11, 14, 10))
        store.set_status(c_ws, "escalated_l2", "anna",
                         "Encoded PowerShell + certutil download; needs EDR isolation and memory capture.",
                         at(11, 11, 20))
        ho = build_handover(store, at(11, 20, 0), 12, cfg, "anna")
        out["handover"] = handover_html(ho)
        known_users = [t for k, t in ho.targets if k == "user"]
        known_hosts = [t for k, t in ho.targets if k == "host"]
    redactor = Redactor(load_redactor_config(), None, known_users, known_hosts)
    out["dossier-jkowalski-redacted"] = redactor.redact(out["dossier-jkowalski"])
    return out


def shoot(pages: dict[str, str], chrome: str | None) -> None:
    from playwright.sync_api import sync_playwright

    IMG.mkdir(parents=True, exist_ok=True)

    def open_page(browser, name: str, scheme: str):
        pg = browser.new_page(viewport={"width": 1200, "height": 900}, color_scheme=scheme)
        pg.goto((EXAMPLES / f"{name}.html").as_uri())
        return pg

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chrome) if chrome else p.chromium.launch()
        pg = open_page(browser, "dossier-jkowalski", "light")
        pg.screenshot(path=IMG / "dossier-light.png", clip={"x": 0, "y": 0, "width": 1200, "height": 900})

        pg = open_page(browser, "dossier-jkowalski", "dark")
        top = pg.locator("h2", has_text="Findings").bounding_box()["y"] - 16
        pg.screenshot(path=IMG / "dossier-dark-findings.png", full_page=True,
                      clip={"x": 0, "y": top, "width": 1200, "height": 760})

        pg = open_page(browser, "handover", "light")
        height = min(pg.evaluate("document.documentElement.scrollHeight"), 1100)
        pg.screenshot(path=IMG / "handover-light.png", full_page=True,
                      clip={"x": 0, "y": 0, "width": 1200, "height": height})

        pg = open_page(browser, "dossier-jkowalski-redacted", "light")
        pg.screenshot(path=IMG / "dossier-redacted.png", clip={"x": 0, "y": 0, "width": 1200, "height": 560})
        browser.close()


def main() -> None:
    pages = build_html()
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    for name, html in pages.items():
        (EXAMPLES / f"{name}.html").write_text(html, encoding="utf-8")
    shoot(pages, sys.argv[1] if len(sys.argv) > 1 else None)
    print("wrote", ", ".join(sorted(p.name for p in [*EXAMPLES.glob("*.html"), *IMG.glob("*.png")])))


if __name__ == "__main__":
    main()
