from pathlib import Path

import pytest

from helpers import signin, ts
from hunterscope.detect import run_detections
from hunterscope.detect.rules import defang, email_signals
from hunterscope.ingest import load_events
from hunterscope.ingest.eml import parse_eml
from hunterscope.models import Event

EMAILS = Path(__file__).resolve().parent.parent / "data" / "samples" / "emails"


def mail(when=None, **detail) -> Event:
    base = {"from_addr": "a@partner.example.net", "from_name": "A", "subject": "hello",
            "reply_to": "", "return_path": "", "urls": [], "attachments": [],
            "spf": "pass", "dkim": "pass", "dmarc": "pass"}
    return Event(ts=when or ts(2, 9, 0), source="email", action="email_received", outcome="success",
                 user="u@contoso.com", detail={**base, **detail})


def sig(e: Event, cfg, strong=True):
    s, w, _ = email_signals(e, cfg["rules"]["suspicious_email"])
    return s if strong else w


def test_parse_phishing_eml():
    [e] = parse_eml(EMAILS / "phish_password_expiry.eml")
    d = e.detail
    assert e.user == "jkowalski@contoso.com" and e.ip == "198.51.100.200"
    assert (d["spf"], d["dkim"], d["dmarc"]) == ("fail", "none", "fail")
    assert d["from_addr"] == "helpdesk@c0ntoso-support.test"
    assert d["attachments"][0]["filename"] == "invoice_0311.html"
    assert len(d["attachments"][0]["sha256"]) == 64
    assert {"href": "http://198.51.100.200/login", "text": "https://contoso.com/sso"} in d["urls"]


def test_parse_rejects_garbage(tmp_path):
    bad = tmp_path / "x.eml"
    bad.write_text("not an email at all")
    assert load_events([bad]).skipped == 1


def test_multiple_recipients_yield_one_event_each(tmp_path):
    p = tmp_path / "m.eml"
    p.write_text("From: a@x.test\nTo: b@contoso.com, c@contoso.com\nCc: d@contoso.com\n"
                 "Date: Wed, 11 Mar 2026 08:50:12 +0000\nSubject: hi\n\nbody")
    assert sorted(e.user for e in parse_eml(p)) == ["b@contoso.com", "c@contoso.com", "d@contoso.com"]


def test_benign_newsletter_does_not_fire(cfg):
    [e] = parse_eml(EMAILS / "benign_newsletter.eml")
    assert run_detections([e], cfg) == []


def test_weak_signals_alone_do_not_fire(cfg):
    e = mail(reply_to="editor@other.example.org", return_path="b@bounce.example.org",
             subject="your invoice")
    assert len(sig(e, cfg, strong=False)) == 3  # at threshold (3) -> fires
    assert run_detections([e], cfg)[0].rule_id == "suspicious_email"
    two = mail(reply_to="editor@other.example.org", subject="your invoice")
    assert run_detections([two], cfg) == []


@pytest.mark.parametrize(
    ("detail", "needle"),
    [
        ({"spf": "softfail"}, "SPF softfail"),
        ({"dmarc": "fail"}, "DMARC fail"),
        ({"from_addr": "x@c0ntoso.com"}, "imitates contoso.com"),
        ({"from_addr": "x@contoso-login.test"}, "imitates contoso.com"),
        ({"from_addr": "x@xn--cntoso-9ua.test"}, "punycode"),
        ({"from_name": "billing@contoso.com"}, "display name shows contoso.com"),
        ({"attachments": [{"filename": "a.iso", "sha256": "0" * 64}]}, "risky attachment"),
        ({"attachments": [{"filename": "scan.pdf.exe", "sha256": "0" * 64}]}, "risky attachment"),
        ({"urls": [{"href": "http://203.0.113.9/x", "text": ""}]}, "raw IP"),
        ({"urls": [{"href": "http://evil.test/x", "text": "https://contoso.com/sso"}]}, "points to evil.test"),
    ],
)
def test_strong_signals(cfg, detail, needle):
    assert any(needle in s for s in sig(mail(**detail), cfg))


def test_internal_sender_is_not_lookalike(cfg):
    assert sig(mail(from_addr="hr@mail.contoso.com"), cfg) == []


def test_legit_link_text_matching_host_is_fine(cfg):
    e = mail(urls=[{"href": "https://www.news.example.net/a", "text": "news.example.net/a"}])
    assert sig(e, cfg) == []


def test_defang():
    assert defang("http://198.51.100.200/login") == "hxxp://198[.]51[.]100[.]200/login"
    assert defang("https://evil.test") == "hxxps://evil[.]test"


def _phish(cfg_when=None):
    return mail(cfg_when or ts(2, 9, 0), spf="fail", dmarc="fail")


def test_takeover_correlation_fires_for_new_ip_within_window(cfg):
    evs = [signin(ts(2, 7, 0), ip="192.0.2.10"), _phish(), signin(ts(2, 10, 0), ip="203.0.113.50")]
    ids = [f.rule_id for f in run_detections(evs, cfg)]
    assert "phish_then_new_signin" in ids


def test_takeover_not_fired_for_known_ip_or_late_or_no_history(cfg):
    known = [signin(ts(2, 7, 0), ip="192.0.2.10"), _phish(), signin(ts(2, 10, 0), ip="192.0.2.10")]
    late = [signin(ts(2, 7, 0), ip="192.0.2.10"), _phish(), signin(ts(4, 10, 0), ip="203.0.113.50")]
    no_history = [_phish(), signin(ts(2, 10, 0), ip="203.0.113.50")]
    for evs in (known, late, no_history):
        assert "phish_then_new_signin" not in [f.rule_id for f in run_detections(evs, cfg)]
