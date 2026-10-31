import copy
from collections import Counter
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers import signin, ts
from hunterscope.cli import app
from hunterscope.detect import run_detections
from hunterscope.models import Event
from hunterscope.triage import build_dossier, parse_timerange

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
runner = CliRunner()
SPRAY = "203.0.113.77"


def spray_events(n=6, ip=SPRAY, start=(2, 3, 0), step=2):
    h, m = start[1], start[2]
    return [signin(ts(start[0], h, m + i * step), ok=False, ip=ip, user=f"user{i}@contoso.com") for i in range(n)]


def fired(cfg, events, context=None):
    return [f for f in run_detections(events, cfg, context=context) if f.rule_id == "password_spray_ip"]


def test_spray_across_accounts_fires_and_per_user_rule_stays_silent(cfg):
    evs = spray_events(6)
    found = run_detections(evs, cfg)
    assert [f.rule_id for f in found] == ["password_spray_ip"]  # nobody has >1 failure: only this rule can see it
    [f] = found
    assert f.severity == "medium" and f.weight == 30 and "6 accounts targeted" in f.title
    assert f.mitre == ["T1110.003"] and ("ip", SPRAY) in f.iocs and len(f.evidence) == 6


def test_attacked_account_signing_in_raises_severity_weight_and_adds_account_ioc(cfg):
    evs = [*spray_events(6), signin(ts(2, 3, 20), ip=SPRAY, user="user3@contoso.com")]
    [f] = fired(cfg, evs)
    assert (f.severity, f.weight) == ("high", 45) and "1 signed in afterwards" in f.title
    assert ("account", "user3@contoso.com") in f.iocs and "user3@contoso.com" in f.description
    assert len(f.evidence) == 7


def test_success_of_an_account_that_was_not_attacked_does_not_count(cfg):
    evs = [*spray_events(6), signin(ts(2, 3, 20), ip=SPRAY, user="someoneelse@contoso.com")]
    [f] = fired(cfg, evs)
    assert (f.severity, f.weight) == ("medium", 30)


def test_success_from_a_different_ip_does_not_count(cfg):
    evs = [*spray_events(6), signin(ts(2, 3, 20), ip="198.51.100.9", user="user3@contoso.com")]
    assert fired(cfg, evs)[0].severity == "medium"


@pytest.mark.parametrize("n", [1, 3, 4])
def test_below_min_accounts_is_quiet(cfg, n):
    assert fired(cfg, spray_events(n)) == []


def test_exactly_min_accounts_fires(cfg):
    assert len(fired(cfg, spray_events(5))) == 1


def test_many_attempts_per_account_is_brute_force_not_spray(cfg):
    evs = [signin(ts(2, 3, i), ok=False, ip=SPRAY, user=f"user{i % 5}@contoso.com") for i in range(25)]  # 5 each
    assert fired(cfg, evs) == []


def test_a_burst_that_hammers_every_account_later_is_judged_as_a_whole(cfg):
    first_round = spray_events(6, step=1)
    retries = [signin(ts(2, 3, 10 + i), ok=False, ip=SPRAY, user=f"user{i % 6}@contoso.com") for i in range(24)]
    assert fired(cfg, [*first_round, *retries]) == []  # 5 attempts per account on average


def test_two_attempts_per_account_still_counts_as_spray(cfg):
    evs = [signin(ts(2, 3, i), ok=False, ip=SPRAY, user=f"user{i % 5}@contoso.com") for i in range(10)]
    assert len(fired(cfg, evs)) == 1


def test_failures_spread_beyond_the_window_do_not_add_up(cfg):
    evs = [signin(ts(2, 3 + i, 0), ok=False, ip=SPRAY, user=f"user{i}@contoso.com") for i in range(8)]  # hourly+
    assert fired(cfg, evs) == []


def test_sliding_window_finds_a_burst_inside_a_long_trickle(cfg):
    trickle = [signin(ts(2, 1, 0), ok=False, ip=SPRAY, user="old@contoso.com")]
    evs = [*trickle, *spray_events(6, start=(2, 6, 0))]
    [f] = fired(cfg, evs)
    assert "6 accounts targeted" in f.title and all(e.ts.hour >= 6 for e in f.evidence)


def test_accounts_are_counted_per_ip_not_globally(cfg):
    evs = [*spray_events(3, ip="203.0.113.1"), *spray_events(3, ip="203.0.113.2")]
    assert fired(cfg, evs) == []


def test_ignore_ips_silences_a_known_shared_egress(cfg):
    c = copy.deepcopy(cfg)
    c["rules"]["password_spray_ip"]["ignore_ips"] = [SPRAY]
    assert fired(c, spray_events(8)) == [] and len(fired(cfg, spray_events(8))) == 1


def test_disabled_rule_is_skipped(cfg):
    c = copy.deepcopy(cfg)
    c["rules"]["password_spray_ip"]["enabled"] = False
    assert fired(c, spray_events(8)) == []


def test_windows_4625_failures_count_too(cfg):
    evs = [Event(ts=ts(2, 3, i), source="windows", action="logon", outcome="failure", user=f"CONTOSO\\u{i}",
                 host="dc1", ip=SPRAY) for i in range(6)]
    assert len(fired(cfg, evs)) == 1


def test_mfa_failures_are_not_credential_failures(cfg):
    evs = [signin(ts(2, 3, i), ok=False, code=500121, ip=SPRAY, user=f"user{i}@contoso.com") for i in range(8)]
    assert fired(cfg, evs) == []


def test_events_without_ip_or_user_are_ignored(cfg):
    evs = [signin(ts(2, 3, i), ok=False, ip=None, user=f"user{i}@contoso.com") for i in range(8)]
    evs += [signin(ts(2, 3, i), ok=False, ip=SPRAY, user=None) for i in range(8)]
    assert fired(cfg, evs) == []


def test_context_lets_one_victim_see_the_spray_and_is_not_double_counted(cfg):
    evs = spray_events(6)
    mine, others = evs[:1], evs[1:]
    assert fired(cfg, mine) == []                       # alone, one failure means nothing
    assert len(fired(cfg, mine, context=others)) == 1   # with the other accounts' events, it is a spray
    assert len(fired(cfg, evs, context=evs)) == 1       # the same events passed twice are counted once
    [f] = fired(cfg, evs, context=evs)
    assert len(f.evidence) == 6


def test_context_is_invisible_to_per_user_rules(cfg):
    target = [signin(ts(2, 10, 0), ip=SPRAY, user="me@contoso.com")]
    # If the context leaked into per-user rules, these would be a 6-failures-then-success brute force of `other`.
    ctx = [signin(ts(2, 10, i), ok=False, ip=SPRAY, user="other@contoso.com") for i in range(1, 7)]
    ctx.append(signin(ts(2, 10, 8), ip=SPRAY, user="other@contoso.com"))
    assert run_detections(target, cfg, context=ctx) == []


# ------------------------------------------------------------------------------ dossiers and CLI


def test_victim_dossier_shows_the_spray_and_lists_the_other_accounts(loaded, cfg):
    d = build_dossier(loaded.events, "user", "tkrol", parse_timerange("24h"), cfg)
    assert "password_spray_ip" in [f.rule_id for f in d.findings] and d.score.level == "high"
    others = {r.user for r in d.related}
    assert "tkrol@contoso.com" not in others and {"mnowak@contoso.com", "sdabrowski@contoso.com"} <= others
    assert all(r.ip == SPRAY for r in d.related)


def test_ip_dossier_lists_every_account_and_only_that_ips_events(loaded, cfg):
    d = build_dossier(loaded.events, "ip", SPRAY, parse_timerange("24h"), cfg)
    assert {e.ip for e in d.events} == {SPRAY} and len(d.events) == 8
    assert len(d.related) == 7 and sum(r.failures for r in d.related) == 7 and sum(r.successes for r in d.related) == 1
    assert d.score.total == 63


def test_unknown_ip_raises_lookup_error(loaded, cfg):
    with pytest.raises(LookupError):
        build_dossier(loaded.events, "ip", "198.51.100.254", parse_timerange("24h"), cfg)


def test_existing_sample_scenarios_are_unchanged(loaded, cfg):
    day = parse_timerange("24h")
    assert build_dossier(loaded.events, "user", "jkowalski", day, cfg).score.total == 100
    assert build_dossier(loaded.events, "user", "akowalska", day, cfg).score.total == 0


def test_benign_nat_mistypes_stay_quiet(loaded, cfg):
    day = parse_timerange("24h")
    assert build_dossier(loaded.events, "ip", "192.0.2.10", day, cfg).findings == []  # 3 users mistyped once
    assert build_dossier(loaded.events, "user", "jmazur", day, cfg).findings == []


def test_cli_ip_pivot_json_and_html(tmp_path):
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "--ip", SPRAY, "-f", "json"])
    assert r.exit_code == 0
    import json

    data = json.loads(r.stdout)
    assert data["kind"] == "ip" and len(data["related_accounts"]) == 7
    assert any(f["rule_id"] == "password_spray_ip" for f in data["findings"])
    out = tmp_path / "ip.html"
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "--ip", SPRAY, "-f", "html", "-o", str(out)])
    html = out.read_text()
    assert r.exit_code == 0 and "Accounts seen from this IP" in html and "sdabrowski@contoso.com" in html
    assert "<script" not in html.lower()


def test_cli_validates_target_options():
    base = ["triage", "-i", str(SAMPLES)]
    assert runner.invoke(app, [*base, "--ip", "not-an-ip"]).exit_code != 0
    assert runner.invoke(app, [*base, "--ip", SPRAY, "-u", "tkrol"]).exit_code != 0
    assert runner.invoke(app, base).exit_code != 0
    assert runner.invoke(app, [*base, "--ip", "198.51.100.254"]).exit_code == 2


def test_cli_ip_accepts_ipv6_and_normalizes():
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "--ip", "::1"])
    assert r.exit_code == 2  # valid address, nothing seen from it


def test_redacting_an_ip_dossier_masks_the_other_accounts():
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "--ip", SPRAY, "--redact"])
    low = r.stdout.lower()
    assert r.exit_code == 0 and "tkrol" not in low and "contoso" not in low and "USER_" in r.stdout


def test_ip_case_is_saved_updated_and_closed_independently_of_users(tmp_path):
    db = ["--db", str(tmp_path / "c.db"), "--author", "anna"]
    base = ["triage", "-i", str(SAMPLES), "--ip", SPRAY, "--save", *db]
    a, b = runner.invoke(app, base), runner.invoke(app, base)
    assert "opened" in a.stderr + a.output and "updated" in b.stderr + b.output
    u = runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "tkrol", "--save", *db])
    assert "opened" in u.stderr + u.output  # a user case is a different case from the IP case
    listed = runner.invoke(app, ["case", "list", "--db", db[1]])
    assert "ip" in listed.stdout and SPRAY in listed.stdout and "tkrol" in listed.stdout


def test_related_accounts_are_escaped_in_html(cfg):
    from hunterscope.report import render_html
    from hunterscope.score import compute_score
    from hunterscope.triage import Dossier, RelatedAccount

    d = Dossier("ip", SPRAY, ts(2, 0, 0), ts(2, 23, 0), [], [], compute_score([], cfg), Counter(),
                related=[RelatedAccount('"><script>alert(1)</script>', SPRAY, 1, 0, ts(2, 3, 0), ts(2, 3, 5))])
    html = render_html(d, cfg)
    assert "<script>alert" not in html and "&lt;script&gt;alert(1)" in html


def test_window_arithmetic_uses_the_configured_minutes(cfg):
    c = copy.deepcopy(cfg)
    c["rules"]["password_spray_ip"]["window_minutes"] = 5
    wide = [signin(ts(2, 3, 0) + timedelta(minutes=3 * i), ok=False, ip=SPRAY, user=f"u{i}@contoso.com")
            for i in range(6)]
    assert fired(c, wide) == [] and len(fired(cfg, wide)) == 1
