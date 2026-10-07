import json

from hunterscope.ingest import load_events
from hunterscope.models import host_key, user_key


def test_samples_load_without_skips(loaded):
    assert loaded.skipped == 0
    assert set(loaded.sources) == {"entra", "ual", "windows", "email"}
    assert [e.ts for e in loaded.events] == sorted(e.ts for e in loaded.events)


def test_ndjson_json_array_and_graph_envelope(tmp_path):
    rec = {"createdDateTime": "2026-03-01T10:00:00Z", "userPrincipalName": "a@contoso.com",
           "ipAddress": "203.0.113.1", "status": {"errorCode": 0}}
    (tmp_path / "a.ndjson").write_text(json.dumps(rec) + "\n\n")
    (tmp_path / "b.json").write_text(json.dumps([rec, rec]))
    (tmp_path / "c.json").write_text(json.dumps({"value": [rec]}))
    res = load_events([tmp_path / n for n in ("a.ndjson", "b.json", "c.json")])
    assert len(res.events) == 4 and res.skipped == 0


def test_bad_records_are_counted_not_fatal(tmp_path):
    good = {"EventID": 4625, "TimeCreated": "2026-03-01T10:00:00Z", "Computer": "h"}
    p = tmp_path / "x.ndjson"
    p.write_text("\n".join([json.dumps(good), "{not json", json.dumps({"foo": 1}),
                            json.dumps({"EventID": "x", "TimeCreated": "bad"})]))
    res = load_events([p])
    assert len(res.events) == 1 and res.skipped == 3


def test_ual_client_ip_port_stripped_and_naive_time_is_utc(tmp_path):
    p = tmp_path / "u.ndjson"
    p.write_text(json.dumps({"CreationTime": "2026-03-01T10:00:00", "Operation": "UserLoggedIn",
                             "UserId": "a@contoso.com", "ClientIP": "203.0.113.5:51234"}))
    e = load_events([p]).events[0]
    assert e.ip == "203.0.113.5" and e.ts.utcoffset().total_seconds() == 0


def test_identity_keys():
    assert user_key("CONTOSO\\JKowalski") == user_key("jkowalski@contoso.com") == "jkowalski"
    assert host_key("SRV-DB01.contoso.com") == "srv-db01"
