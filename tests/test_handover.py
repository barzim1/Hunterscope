from datetime import datetime, timedelta, timezone

import pytest

from hunterscope.casestore import CaseStore
from hunterscope.config.loader import load_redactor_config, load_rules_config
from hunterscope.handover import build_handover, render_markdown
from hunterscope.redactor import Redactor
from test_casestore import dossier, finding

NOW = datetime(2026, 3, 11, 20, 0, tzinfo=timezone.utc)
CFG = load_rules_config()


def hrs(n: float) -> timedelta:
    return timedelta(hours=n)


@pytest.fixture
def store():
    with CaseStore(":memory:") as s:
        yield s


def open_case(store, target, at, score=50, kind="user", findings=()):
    return store.upsert_from_dossier(dossier(findings, target, kind, score), "anna", at).case_id


def test_buckets(store):
    fp = open_case(store, "alice", NOW - hrs(8))
    tp = open_case(store, "bob", NOW - hrs(7), score=90)
    esc = open_case(store, "carol", NOW - hrs(6), score=80)
    nw = open_case(store, "dave", NOW - hrs(2), score=60)
    low = open_case(store, "erin", NOW - hrs(5), score=20)
    store.set_status(fp, "closed_fp", "anna", "travel", NOW - hrs(4))
    store.set_status(tp, "closed_tp", "anna", "confirmed, creds reset", NOW - hrs(3))
    store.set_status(esc, "escalated_l3", "anna", "malware on host", NOW - hrs(1))
    ho = build_handover(store, NOW, 12, CFG, "anna")
    assert [v.case.id for v in ho.closed_fp] == [fp]
    assert [v.case.id for v in ho.closed_tp] == [tp]
    assert [v.case.id for v in ho.escalated] == [esc] and ho.escalated[0].new_this_shift
    assert [v.case.id for v in ho.unresolved] == [nw, low]  # sorted by risk, high first
    assert ho.opened == 5
    assert ho.closed_fp[0].decision_note == "travel"


def test_cases_closed_before_window_are_not_listed(store):
    cid = open_case(store, "alice", NOW - hrs(30))
    store.set_status(cid, "closed_fp", "anna", "old", NOW - hrs(29))
    ho = build_handover(store, NOW, 12, CFG, "anna")
    assert not (ho.closed_fp or ho.closed_tp or ho.unresolved or ho.escalated) and ho.opened == 0


def test_old_escalation_still_listed_but_not_flagged_new(store):
    cid = open_case(store, "carol", NOW - hrs(40))
    store.set_status(cid, "escalated_l2", "anna", "waiting on L2", NOW - hrs(39))
    [v] = build_handover(store, NOW, 12, CFG, "anna").escalated
    assert not v.new_this_shift and v.decision_note == "waiting on L2"


def test_stale_flag_uses_idle_time_not_age(store):
    cid = open_case(store, "alice", NOW - hrs(48))
    assert build_handover(store, NOW, 12, CFG, "anna").unresolved[0].stale
    store.add_note(cid, "bob", "still waiting for user", NOW - hrs(1))
    assert not build_handover(store, NOW, 12, CFG, "anna").unresolved[0].stale


def test_window_end_in_the_past_ignores_later_activity(store):
    cid = open_case(store, "alice", NOW - hrs(8))
    store.set_status(cid, "closed_fp", "anna", "later", NOW + hrs(1))
    ho = build_handover(store, NOW, 12, CFG, "anna")
    assert not ho.closed_fp  # closure happens after the window being summarized


def test_findings_summary_is_ranked_and_truncated(store):
    fs = [finding(rule=f"r{i}", title=f"F{i}", at=NOW - hrs(10 - i)) for i in range(5)]
    open_case(store, "alice", NOW - hrs(5), findings=fs)
    v = build_handover(store, NOW, 12, CFG, "anna").unresolved[0]
    assert len(v.top_findings) == 3 and v.more_findings == 2


def test_markdown_render_and_pipe_escaping(store):
    cid = open_case(store, "alice", NOW - hrs(5))
    store.set_status(cid, "closed_fp", "anna", "a | b\nsecond line", NOW - hrs(1))
    md = render_markdown(build_handover(store, NOW, 12, CFG, "anna"))
    assert "a \\| b second line" in md and "## Closed: False Positive" in md
    assert "_Nothing unresolved._" in md


def test_redacted_handover_leaks_no_targets(store):
    open_case(store, "jkowalski", NOW - hrs(5), score=90)
    open_case(store, "srv-db01", NOW - hrs(4), kind="host")
    cid = open_case(store, "akowalska", NOW - hrs(3))
    store.set_status(cid, "closed_fp", "anna", "mail from akowalska@contoso.com checked", NOW - hrs(1))
    ho = build_handover(store, NOW, 12, CFG, "anna")
    users = [t for k, t in ho.targets if k == "user"]
    hosts = [t for k, t in ho.targets if k == "host"]
    out = Redactor(load_redactor_config(), None, users, hosts).redact(render_markdown(ho))
    for secret in ("jkowalski", "akowalska", "srv-db01", "contoso"):
        assert secret not in out.lower()
    assert "USER_A" in out and "HOST_1" in out
