import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers import ts
from hunterscope.cli import app
from hunterscope.detect import run_detections
from hunterscope.models import Event
from hunterscope.triage import build_dossier, parse_timerange

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
runner = CliRunner()
USER = "u@contoso.com"
RULE = "new_sign_in_properties"


def signin(day, country="PL", client="Browser", app="Exchange", hour=8, user=USER, ok=True, source="entra"):
    return Event(ts=ts(day, hour, 0), source=source, action="signin", outcome="success" if ok else "failure",
                 user=user, ip="192.0.2.1", country=country, app=app, error_code=0 if ok else 50126,
                 detail={"client_app": client})


def baseline(days=10, **kw):
    return [signin(d, **kw) for d in range(1, days + 1)]


def fired(cfg, window, history):
    return [f for f in run_detections(window, cfg, history=history) if f.rule_id == RULE]


def test_new_country_is_flagged_with_the_usual_values_in_the_description(cfg):
    [f] = fired(cfg, [signin(20, country="BR")], baseline())
    assert f.severity == "low" and f.weight == 10 and f.mitre == ["T1078.004"]
    assert f.title == "Unfamiliar sign-in properties: country BR"
    assert "10 earlier sign-ins over 10 days" in f.description and "country PL (10)" in f.description
    assert "client Browser (10)" in f.description and len(f.evidence) == 1


def test_two_new_properties_in_one_sign_in_raise_severity_and_weight(cfg):
    [f] = fired(cfg, [signin(20, country="BR", client="IMAP4")], baseline())
    assert (f.severity, f.weight) == ("medium", 20) and "country BR, client IMAP4" in f.title


def test_familiar_values_stay_quiet(cfg):
    assert fired(cfg, [signin(20)], baseline()) == []


def test_comparison_ignores_case(cfg):
    assert fired(cfg, [signin(20, country="pl", client="BROWSER", app="exchange")], baseline()) == []


def test_a_value_seen_once_is_not_familiar_but_twice_is(cfg):
    hist = [*baseline(), signin(11, country="DE")]
    assert len(fired(cfg, [signin(20, country="DE")], hist)) == 1          # one sighting: still new
    assert fired(cfg, [signin(20, country="DE")], [*hist, signin(12, country="DE")]) == []


@pytest.mark.parametrize("history", [[], baseline(4), [signin(1, hour=h) for h in range(8, 20)]])
def test_without_enough_history_the_rule_is_silent(cfg, history):
    # no history; fewer than 5 sign-ins; 12 sign-ins but all on one day (fewer than 3 days)
    assert fired(cfg, [signin(20, country="BR")], history) == []


def test_only_the_first_sighting_in_the_window_is_flagged(cfg):
    window = [signin(20, country="BR"), signin(21, country="BR")]
    assert len(fired(cfg, window, baseline())) == 1


def test_two_different_new_values_are_two_findings(cfg):
    window = [signin(20, country="BR"), signin(21, country="DE")]
    assert [f.title for f in fired(cfg, window, baseline())] == [
        "Unfamiliar sign-in properties: country BR", "Unfamiliar sign-in properties: country DE"]


def test_failed_sign_ins_neither_make_values_familiar_nor_trigger_the_rule(cfg):
    poisoned = [*baseline(), *[signin(11 + i, country="BR", ok=False) for i in range(5)]]
    assert len(fired(cfg, [signin(20, country="BR")], poisoned)) == 1
    assert fired(cfg, [signin(20, country="BR", ok=False)], baseline()) == []


def test_other_accounts_history_does_not_leak(cfg):
    other = baseline(user="other@contoso.com", country="BR")
    assert len(fired(cfg, [signin(20, country="BR")], [*baseline(), *other])) == 1


def test_history_older_than_the_lookback_does_not_count(cfg):
    old = [signin(1, country="PL").model_copy(update={"ts": ts(1, 8, 0) - timedelta(days=90 + i)}) for i in range(10)]
    assert fired(cfg, [signin(20, country="BR")], old) == []


def test_history_from_after_the_window_start_is_not_a_baseline(cfg):
    future = [signin(21 + d, country="BR") for d in range(10)]  # after the window event: must not whitelist it
    assert len(fired(cfg, [signin(20, country="BR")], [*baseline(), *future])) == 1


def test_only_entra_sign_ins_are_considered(cfg):
    win = Event(ts=ts(20, 8, 0), source="windows", action="logon", outcome="success", user=USER, ip="1.2.3.4")
    assert fired(cfg, [win], baseline()) == []
    assert fired(cfg, [signin(20, country="BR")], baseline(source="windows")) == []


def test_configured_properties_are_respected(cfg):
    c = copy.deepcopy(cfg)
    c["rules"][RULE]["properties"] = ["client_app"]
    assert fired(c, [signin(20, country="BR")], baseline()) == []
    assert len(fired(c, [signin(20, client="IMAP4")], baseline())) == 1
    c["rules"][RULE]["enabled"] = False
    assert fired(c, [signin(20, client="IMAP4")], baseline()) == []


def test_events_without_a_value_for_a_property_are_not_new(cfg):
    assert fired(cfg, [signin(20, country=None)], baseline()) == []


def test_each_account_is_judged_against_its_own_baseline(cfg):
    hist = [*baseline(), *baseline(user="b@contoso.com", country="DE")]
    window = [signin(20, country="DE"), signin(20, country="DE", user="b@contoso.com")]
    found = fired(cfg, window, hist)
    assert len(found) == 1 and found[0].evidence[0].user == USER


# ------------------------------------------------------------------------ dossiers and CLI


def test_history_feeds_the_rule_but_stays_out_of_the_window(loaded, cfg):
    d = build_dossier(loaded.events, "user", "mkrawczyk", parse_timerange("24h"), cfg)
    assert [f.title for f in d.findings] == ["Unfamiliar sign-in properties: country DE"]
    assert len(d.events) == 1 and d.score.total == 10


def test_sample_users_behave_as_documented(loaded, cfg):
    day = parse_timerange("24h")
    jk = build_dossier(loaded.events, "user", "jkowalski", day, cfg)
    assert "Unfamiliar sign-in properties: country BR" in [f.title for f in jk.findings]
    assert jk.score.total == 100
    assert build_dossier(loaded.events, "user", "akowalska", day, cfg).findings == []  # too little history


def test_ip_pivot_uses_each_accounts_own_baseline(loaded, cfg):
    d = build_dossier(loaded.events, "ip", "198.51.100.88", parse_timerange("24h"), cfg)
    assert [f.rule_id for f in d.findings] == [RULE]


def test_host_dossiers_have_no_baseline(loaded, cfg):
    d = build_dossier(loaded.events, "host", "ws-jkowalski", parse_timerange("24h"), cfg)
    assert RULE not in {f.rule_id for f in d.findings}


def test_cli_json_shows_the_finding(tmp_path):
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "mkrawczyk", "-f", "json"])
    data = json.loads(r.stdout)
    assert r.exit_code == 0 and data["findings"][0]["rule_id"] == RULE and data["score"]["level"] == "low"


def test_disabling_the_rule_removes_the_finding(loaded, cfg):
    c = copy.deepcopy(cfg)
    c["rules"][RULE]["enabled"] = False
    assert build_dossier(loaded.events, "user", "mkrawczyk", parse_timerange("24h"), c).findings == []
