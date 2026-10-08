from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from hunterscope.casestore import CaseStore
from hunterscope.models import Event, Finding
from hunterscope.score import Score
from hunterscope.triage import Dossier

T0 = datetime(2026, 3, 11, 12, 0, tzinfo=timezone.utc)


def finding(rule="mfa_fatigue", at=T0, ip="203.0.113.5", title="MFA fatigue") -> Finding:
    ev = Event(ts=at, source="entra", action="signin", outcome="success", user="u@contoso.com", ip=ip)
    return Finding(rule, title, "high", "credential-access", ["T1621"], 30.0, "desc", [ev])


def dossier(findings=(), target="jkowalski", kind="user", score=40) -> Dossier:
    return Dossier(kind=kind, target=target, since=T0 - timedelta(hours=24), until=T0, events=[],
                   findings=list(findings), score=Score(score, "medium"), sources=Counter())


@pytest.fixture
def store():
    with CaseStore(":memory:") as s:
        yield s


def test_first_triage_opens_case(store):
    res = store.upsert_from_dossier(dossier([finding()]), "anna", T0)
    assert (res.created, res.new_findings) == (True, 1)
    c = store.get_case(res.case_id)
    assert (c.status, c.score, c.target) == ("new", 40, "jkowalski")
    assert [e.kind for e in store.log(c.id)] == ["triage"]


def test_retriage_same_data_is_idempotent(store):
    a = store.upsert_from_dossier(dossier([finding()]), "anna", T0)
    b = store.upsert_from_dossier(dossier([finding()]), "anna", T0 + timedelta(hours=1))
    assert (b.created, b.case_id, b.new_findings) == (False, a.case_id, 0)
    assert len(store.findings(a.case_id)) == 1
    assert len(store.list_cases()) == 1


def test_retriage_adds_only_new_findings_and_updates_score(store):
    a = store.upsert_from_dossier(dossier([finding()], score=40), "anna", T0)
    later = finding(rule="impossible_travel", title="Travel", at=T0 + timedelta(hours=2))
    b = store.upsert_from_dossier(dossier([finding(), later], score=70), "anna", T0 + timedelta(hours=3))
    assert b.new_findings == 1
    assert store.get_case(a.case_id).score == 70
    assert "40 -> 70" in store.log(a.case_id)[-1].text


def test_identity_variants_share_a_case(store):
    a = store.upsert_from_dossier(dossier(target="jkowalski"), "anna", T0)
    b = store.upsert_from_dossier(dossier(target="JKowalski@contoso.com"), "anna", T0)
    assert a.case_id == b.case_id


def test_user_and_host_with_same_name_are_separate(store):
    a = store.upsert_from_dossier(dossier(target="x", kind="user"), "anna", T0)
    b = store.upsert_from_dossier(dossier(target="x", kind="host"), "anna", T0)
    assert a.case_id != b.case_id


def test_closed_case_is_immutable_and_new_triage_opens_new_case(store):
    a = store.upsert_from_dossier(dossier([finding()]), "anna", T0)
    store.set_status(a.case_id, "closed_fp", "anna", "benign travel", T0)
    with pytest.raises(ValueError, match="immutable"):
        store.set_status(a.case_id, "in_progress", "anna", "", T0)
    with pytest.raises(ValueError, match="immutable"):
        store.set_status(a.case_id, "closed_tp", "anna", "reopen?", T0)
    b = store.upsert_from_dossier(dossier([finding()]), "anna", T0 + timedelta(days=1))
    assert b.created and b.case_id != a.case_id


@pytest.mark.parametrize("status", ["closed_fp", "closed_tp", "escalated_l2", "escalated_l3"])
def test_decisions_require_a_reason(store, status):
    cid = store.upsert_from_dossier(dossier(), "anna", T0).case_id
    for blank in ("", "   "):
        with pytest.raises(ValueError, match="note is required"):
            store.set_status(cid, status, "anna", blank, T0)
    assert store.get_case(cid).status == "new"


def test_in_progress_needs_no_note_and_noop_is_rejected(store):
    cid = store.upsert_from_dossier(dossier(), "anna", T0).case_id
    store.set_status(cid, "in_progress", "anna", "", T0)
    with pytest.raises(ValueError, match="already"):
        store.set_status(cid, "in_progress", "anna", "", T0)


def test_unknown_status_and_missing_case(store):
    cid = store.upsert_from_dossier(dossier(), "anna", T0).case_id
    with pytest.raises(ValueError, match="unknown status"):
        store.set_status(cid, "done", "anna", "x", T0)
    with pytest.raises(KeyError):
        store.get_case(999)
    with pytest.raises(KeyError):
        store.add_note(999, "anna", "x")
    with pytest.raises(ValueError, match="empty"):
        store.add_note(cid, "anna", "  ")


def test_log_is_an_audit_trail(store):
    cid = store.upsert_from_dossier(dossier(), "anna", T0).case_id
    store.add_note(cid, "bob", "called the user", T0 + timedelta(minutes=5))
    store.set_status(cid, "escalated_l2", "bob", "needs purge", T0 + timedelta(minutes=9))
    log = store.log(cid)
    assert [(e.kind, e.author) for e in log] == [("triage", "anna"), ("note", "bob"), ("status", "bob")]
    assert (log[-1].from_status, log[-1].to_status) == ("new", "escalated_l2")


def test_db_persists_and_refuses_newer_schema(tmp_path):
    path = tmp_path / "sub" / "c.db"
    with CaseStore(path) as s:
        s.upsert_from_dossier(dossier([finding()]), "anna", T0)
    with CaseStore(path) as s:
        assert len(s.list_cases()) == 1
    import sqlite3

    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 99")
    con.commit()
    con.close()
    with pytest.raises(RuntimeError, match="newer"):
        CaseStore(path)
