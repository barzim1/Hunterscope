"""Rebuild docs/examples/*.html and docs/img/*.png from the synthetic samples.

Deterministic: fixed case timestamps, fixed analyst name, no real data. Needs Playwright and a Chromium:

    pip install -e ".[shots]"
    python scripts/build_screenshots.py [/path/to/chrome]

Without a path Playwright's own browser is used (`playwright install chromium`).

Also shoots the trainer (docs/img/trainer-*.png): a local server with a throwaway database, a fixed scenario token
and a fixed "time spent", so the screenshots show the same case every run.
"""

from __future__ import annotations

import sys
import tempfile
import threading
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

# A true positive: a macro in a fake invoice starts cmd, which starts hidden PowerShell. Tokens are
# `<seed>-<template>-<difficulty>-<mix>`; the verdict is derived from the seed, so this one is always the same case.
TRAINER_TOKEN = "20-ps_encoded-2-s"
TRAINER_JUSTIFICATION = (
    "WINWORD.EXE uruchomil cmd.exe, a ten ukryty PowerShell z -enc. Po dekodowaniu payload pobiera skrypt z S3 "
    "i laczy sie na zewnetrzny adres, w Autostarcie powstal nowy skrot. To realny incydent, nie skan ani test: "
    "eskaluje do L2, prosze o izolacje hosta i blokade domeny nadawcy."
)


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
        shoot_trainer(browser)
        browser.close()


def shoot_trainer(browser) -> None:
    """Alert with its logs and the decision panel, then the debrief after a correct verdict."""
    from hunterscope.trainer.scenarios import generate
    from hunterscope.trainer.server import make_server
    from hunterscope.trainer.store import TrainerStore

    scn = generate(TRAINER_TOKEN)
    key_ids = [e.id for e in scn.events if e.role == "key"]
    with tempfile.TemporaryDirectory() as tmp:
        server = make_server("127.0.0.1", 0, TrainerStore(Path(tmp) / "trainer.db"))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            pg = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme="light")
            pg.goto(f"http://127.0.0.1:{server.server_address[1]}/")
            pg.wait_for_selector("#nav button")
            pg.evaluate(
                "async (t) => { const r = await fetch('/api/scenario?token=' + t);"
                " S.cases.alert = newCase(await r.json()); render(); }", TRAINER_TOKEN)
            pg.wait_for_selector(".alert")
            pg.screenshot(path=IMG / "trainer-alert.png", clip={"x": 0, "y": 0, "width": 1280, "height": 900})

            # the analyst's decision: key events starred, the right verdict and actions, a written reason
            pg.evaluate("(ids) => ids.forEach(toggleEvidence)", key_ids)
            pg.evaluate(
                "(a) => { a.forEach((x) => C.form.actions.add(x)); C.startedAt = Date.now() - 95000; render(); }",
                scn.truth.required_actions)
            pg.check("input[name=verdict][value=tp]")
            pg.fill("textarea[aria-label=Uzasadnienie]", TRAINER_JUSTIFICATION)
            pg.click("text=Zatwierdź werdykt")
            pg.wait_for_selector("text=Wzorcowa notatka do ticketu", timeout=15000)
            pg.screenshot(path=IMG / "trainer-debrief.png", full_page=True,
                          clip={"x": 0, "y": 0, "width": 1280, "height": 1000})
        finally:
            server.shutdown()
            server.server_close()


def main() -> None:
    pages = build_html()
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    for name, html in pages.items():
        (EXAMPLES / f"{name}.html").write_text(html, encoding="utf-8")
    shoot(pages, sys.argv[1] if len(sys.argv) > 1 else None)
    print("wrote", ", ".join(sorted(p.name for p in [*EXAMPLES.glob("*.html"), *IMG.glob("*.png")])))


if __name__ == "__main__":
    main()
