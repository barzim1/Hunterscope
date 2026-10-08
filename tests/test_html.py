import re
from collections import Counter
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers import cmd, signin, ts
from hunterscope.casestore import CaseStore
from hunterscope.cli import app
from hunterscope.detect import run_detections
from hunterscope.handover import build_handover
from hunterscope.handover import render_html as handover_html
from hunterscope.report import render_html
from hunterscope.score import compute_score
from hunterscope.triage import Dossier, build_dossier, parse_timerange

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
runner = CliRunner()


def dossier_for(events, cfg, target="u"):
    findings = run_detections(events, cfg)
    return Dossier("user", target, ts(2, 0, 0), ts(2, 23, 0), events, findings, compute_score(findings, cfg), Counter())


def test_sample_dossier_html_is_static_and_self_contained(loaded, cfg):
    d = build_dossier(loaded.events, "user", "jkowalski", parse_timerange("24h"), cfg)
    html = render_html(d, cfg)
    assert "<script" not in html.lower() and "javascript:" not in html.lower()
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert 'role="meter"' in html and 'aria-valuenow="100"' in html and "CRITICAL" in html
    # no external resource is loaded; the only links are MITRE technique pages
    assert not re.findall(r"(?:src|srcset)=", html) and "@import" not in html
    hrefs = re.findall(r'href="([^"]+)"', html)
    assert hrefs and all(h.startswith("https://attack.mitre.org/techniques/") for h in hrefs)
    assert "impossible_travel" in html and "⚑ flagged" in html and "hxxp://198[.]51[.]100[.]200/login" in html


def test_untrusted_log_content_is_escaped(cfg):
    evil = '<img src=x onerror=alert(1)> whoami /priv <script>alert(2)</script>'
    d = dossier_for([cmd(ts(2, 9, 0), evil, host="<b>h</b>"), signin(ts(2, 9, 5), user='"><svg onload=alert(3)>')],
                    cfg, target="</code><script>alert(4)</script>")
    html = render_html(d, cfg)
    for payload in ("<img src=x", "<script>alert", "<svg onload", "<b>h</b>", "</code><script>"):
        assert payload not in html, payload
    assert "&lt;img src=x onerror=alert(1)&gt;" in html and "&lt;script&gt;alert(2)" in html


def test_empty_dossier_renders_info_level_and_empty_states(cfg):
    html = render_html(dossier_for([signin(ts(2, 9, 0))], cfg), cfg)
    assert "sev-info" in html and "No detections fired" in html and "None extracted." in html
    assert "width: 0%" in html


def test_score_meter_width_matches_score(loaded, cfg):
    d = build_dossier(loaded.events, "user", "jkowalski", parse_timerange("24h"), cfg)
    d.score.total = 37
    d.score.level = "medium"
    html = render_html(d, cfg)
    assert "width: 37%" in html and 'class="card sev-medium"' in html


def test_timeline_truncation_notice(cfg):
    import copy

    small = copy.deepcopy(cfg)
    small["report"]["timeline_limit"] = 2
    evs = [signin(ts(2, 9, i)) for i in range(5)]
    assert "Timeline truncated: 3 further event(s)" in render_html(dossier_for(evs, small), small)


def test_cli_html_dossier_and_redaction(tmp_path):
    out = tmp_path / "r.html"
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "jkowalski", "-f", "html", "--redact", "-o", str(out)])
    assert r.exit_code == 0
    html = out.read_text()
    for secret in ("jkowalski", "contoso", "mail-drop.test"):
        assert secret not in html.lower()
    assert "USER_A" in html and "@media (prefers-color-scheme: dark)" in html    # redaction left the CSS intact
    assert html.count("<style>") == 1 and "</html>" in html


def test_cli_html_without_output_on_non_tty_prints(tmp_path):
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "akowalska", "-f", "html"])
    assert r.exit_code == 0 and r.stdout.lstrip().lower().startswith("<!doctype html>")


@pytest.fixture
def store():
    with CaseStore(":memory:") as s:
        yield s


def test_handover_html_sections_chips_and_escaping(store, loaded, cfg):
    now = ts(2, 20, 0)
    d = build_dossier(loaded.events, "user", "jkowalski", parse_timerange("24h"), cfg)
    stale = store.upsert_from_dossier(d, "marek", now - timedelta(hours=60)).case_id
    other = build_dossier(loaded.events, "user", "akowalska", parse_timerange("24h"), cfg)
    cid = store.upsert_from_dossier(other, "anna", now - timedelta(hours=3)).case_id
    store.set_status(cid, "closed_fp", "anna", '<script>alert(1)</script> benign & checked', now - timedelta(hours=1))
    html = handover_html(build_handover(store, now, 12, cfg, "<i>anna</i>"))
    assert "<script" not in html.lower() and "&lt;script&gt;alert(1)&lt;/script&gt; benign &amp; checked" in html
    assert "&lt;i&gt;anna&lt;/i&gt;" in html
    assert "STALE" in html and f"#{stale}" in html and "CRITICAL" in html
    assert "Closed: false positive" in html and "Closed: true positive" in html and "None." in html


def test_cli_handover_html(tmp_path):
    db = ["--db", str(tmp_path / "c.db"), "--author", "anna"]
    runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "jkowalski", "--save", *db])
    out = tmp_path / "h.html"
    r = runner.invoke(app, ["shift-summary", "-f", "html", "-o", str(out), *db])
    assert r.exit_code == 0 and "Shift handover" in out.read_text()
    red = tmp_path / "hr.html"
    runner.invoke(app, ["shift-summary", "-f", "html", "--redact", "-o", str(red), *db])
    text = red.read_text()
    assert "jkowalski" not in text.lower() and "USER_A" in text and "@media" in text


def test_format_validation():
    assert runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "jkowalski", "-f", "pdf"]).exit_code != 0
    assert runner.invoke(app, ["shift-summary", "-f", "pdf", "--db", ":memory:"]).exit_code != 0
