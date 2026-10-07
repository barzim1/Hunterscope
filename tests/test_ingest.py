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


def test_windows_logon_uses_target_account_not_machine_subject():
    from hunterscope.ingest.parsers import parse_windows

    rec = {"EventID": 4625, "TimeCreated": "2026-03-01T10:00:00Z", "Hostname": "WS1.contoso.com",
           "SubjectUserName": "WS1$", "SubjectDomainName": "CONTOSO", "TargetUserName": "jkowalski",
           "TargetDomainName": "CONTOSO", "IpAddress": "203.0.113.7"}
    e = parse_windows(rec)
    assert (e.user, e.host, e.ip, e.outcome) == ("CONTOSO\\jkowalski", "WS1.contoso.com", "203.0.113.7", "failure")
    assert parse_windows({**rec, "IpAddress": "-"}).ip is None


def test_windows_process_event_security_4688_shape():
    from hunterscope.ingest.parsers import parse_windows

    rec = {"EventID": 4688, "TimeCreated": "2026-03-01T10:00:00Z", "Hostname": "ws1", "SubjectUserName": "pgustavo",
           "SubjectDomainName": "THESHIRE", "NewProcessName": "C:\\x\\a.exe", "CommandLine": "a.exe /c"}
    e = parse_windows(rec)
    assert (e.user, e.app, e.command_line) == ("THESHIRE\\pgustavo", "C:\\x\\a.exe", "a.exe /c")


def test_windows_timestamp_variants_across_exporters():
    from hunterscope.ingest.parsers import detect_source, parse_windows

    for key, value in [("TimeCreated", "2026-03-01T10:00:00Z"), ("@timestamp", "2026-03-01T10:00:00.123Z"),
                       ("EventTime", "2026-03-01 10:00:00"), ("UtcTime", "2026-03-01 10:00:00.123")]:
        rec = {"EventID": 1, key: value, "Hostname": "h", "CommandLine": "x"}
        assert detect_source(rec) == "windows"
        assert parse_windows(rec).ts.year == 2026
