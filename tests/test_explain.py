import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helpers import cmd, signin, ts
from hunterscope.cli import app
from hunterscope.config.loader import load_knowledge, load_rules_config
from hunterscope.explain import (
    TABLES,
    KnowledgeBase,
    event_keys,
    explain_dossier,
    lookup,
    render_dossier_markdown,
)
from hunterscope.ingest.parsers import _ENTRA_REASONS, _WIN_GROUP_IDS, _WIN_PROCESS_IDS
from hunterscope.triage import build_dossier, parse_timerange

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
runner = CliRunner()


@pytest.fixture(scope="module")
def kb():
    return KnowledgeBase(load_knowledge())


# ------------------------------------------------- the base must cover what the tool produces


def test_every_entry_is_complete_and_sourced(kb):
    count = 0
    for table in TABLES:
        for key in kb.keys(table):
            x = kb.get(table, key)  # raises if a required field is missing
            assert x is not None and x.check, f"{table}/{key} has no checks"
            assert x.source.startswith("https://"), f"{table}/{key} has no source URL"
            count += 1
    assert count > 100


def test_yaml_keys_are_strings():
    raw = load_knowledge()
    for table in TABLES:
        assert all(isinstance(k, str) for k in raw[table]), f"{table}: unquoted numeric key"


def test_every_rule_is_explained(kb):
    """Adding a rule without an explanation must fail here, not surface later as a blank section."""
    cfg = load_rules_config()
    missing = [rid for rid in cfg["rules"] if kb.get("rules", rid) is None]
    assert not missing, f"rules without a knowledge-base entry: {missing}"


def test_every_technique_used_by_a_rule_is_explained(kb):
    cfg = load_rules_config()
    used: set[str] = set()
    for rule_cfg in cfg["rules"].values():
        used.update(rule_cfg["mitre"])
        for pattern in rule_cfg.get("patterns", []):
            used.update(pattern.get("mitre", []))
    missing = sorted(t for t in used if kb.get("techniques", t) is None)
    assert not missing, f"techniques without a knowledge-base entry: {missing}"


def test_every_entra_code_the_parser_names_is_explained(kb):
    assert [c for c in _ENTRA_REASONS if kb.get("entra_errors", str(c)) is None] == []


def test_every_windows_event_the_parser_handles_is_explained(kb):
    handled = {4624, 4625, 10, *_WIN_PROCESS_IDS, *_WIN_GROUP_IDS}
    missing = []
    for event_id in sorted(handled):
        table = "sysmon_events" if event_id <= 30 else "windows_events"
        if kb.get(table, str(event_id)) is None:
            missing.append((table, event_id))
    assert not missing


# ------------------------------------------------------------------------------- lookup


def test_numeric_term_returns_every_table_it_matches(kb):
    assert [x.table for x in lookup("4688", kb)] == ["windows_events"]
    assert [x.table for x in lookup("10", kb)] == ["sysmon_events"]  # not an Entra code
    assert [x.table for x in lookup("50126", kb)] == ["entra_errors"]


@pytest.mark.parametrize("term,table,key", [
    ("AADSTS50126", "entra_errors", "50126"),
    ("entra:500121", "entra_errors", "500121"),
    ("sysmon:1", "sysmon_events", "1"),
    ("t1003.001", "techniques", "T1003.001"),
    ("CertUtil", "processes", "certutil.exe"),
    ("C:\\Windows\\System32\\CertUtil.exe", "processes", "certutil.exe"),
    ("/usr/local/bin/mimikatz", "processes", "mimikatz.exe"),
    ("Consent to application.", "ual_operations", "consent to application"),
    ("lsass_access", "rules", "lsass_access"),
])
def test_lookup_resolves(kb, term, table, key):
    hits = lookup(term, kb)
    assert [(x.table, x.key) for x in hits] == [(table, key)]


def test_unknown_term_is_empty_not_guessed(kb):
    assert lookup("definitely-not-a-thing", kb) == []
    assert lookup("4999", kb) == []


def test_user_knowledge_base_overrides_and_extends(tmp_path):
    custom = tmp_path / "kb.yaml"
    custom.write_text(
        "processes:\n"
        "  corp-agent.exe:\n"
        "    title: corp-agent.exe\n    what: nasz agent\n    risk: brak\n    normal: zawsze\n"
        "    check: [nic]\n    source: https://intranet.example/agent\n"
        "windows_events:\n"
        "  '4688':\n"
        "    title: nadpisane\n    what: w\n    risk: r\n    normal: n\n    check: [c]\n    source: https://x.example\n"
    )
    merged = KnowledgeBase(load_knowledge(custom))
    assert lookup("corp-agent", merged)[0].what == "nasz agent"
    assert lookup("4688", merged)[0].title == "nadpisane"
    assert lookup("4624", merged)[0].title.startswith("4624")  # reszta bazy nietknięta


def test_entry_with_missing_field_fails_loudly(tmp_path):
    bad = tmp_path / "kb.yaml"
    bad.write_text("processes:\n  x.exe:\n    title: x\n    what: w\n")
    with pytest.raises(ValueError, match="lacks"):
        lookup("x.exe", KnowledgeBase(load_knowledge(bad)))


# ------------------------------------------------------------------------------- dossier


def _dossier(loaded, cfg, user="jkowalski"):
    return build_dossier(loaded.events, "user", user, parse_timerange("7d"), cfg)


def test_dossier_explains_every_rule_that_fired(kb, loaded, cfg):
    d = _dossier(loaded, cfg)
    ex = explain_dossier(d, kb)
    assert {g.rule_id for g in ex.groups} == {f.rule_id for f in d.findings}
    assert all(g.explanation is not None and not g.unknown_techniques for g in ex.groups)


def test_dossier_lists_flagged_events_first_and_hides_quiet_ones(kb, loaded, cfg):
    ex = explain_dossier(_dossier(loaded, cfg), kb)
    flagged_flags = [s.flagged > 0 for s in ex.seen]
    assert flagged_flags == sorted(flagged_flags, reverse=True)
    assert all(not s.explanation.quiet for s in ex.seen)
    assert ("entra_errors", "0") not in {(s.explanation.table, s.explanation.key) for s in ex.seen}


def test_benign_user_has_nothing_to_explain_but_no_crash(kb, loaded, cfg):
    text = render_dossier_markdown(explain_dossier(_dossier(loaded, cfg, "akowalska"), kb))
    assert "Brak wykryć w oknie" in text


def test_gaps_name_what_the_base_does_not_cover(kb):
    from hunterscope.models import Event

    unknown = Event(ts=ts(11, 9, 0), source="windows", action="event_9999", host="h1", user="u",
                    detail={"event_id": 9999})
    d = build_dossier([unknown, signin(ts(11, 9, 1), user="u")], "user", "u", parse_timerange("1d"),
                      load_rules_config())
    ex = explain_dossier(d, kb)
    assert ("windows_events", "9999", 1) in ex.gaps
    assert "Bez wyjaśnienia" in render_dossier_markdown(ex)


def test_unlisted_process_is_not_reported_as_a_gap(kb):
    d = build_dossier([cmd(ts(11, 9, 0), "notepad.exe x")], "host", "ws1", parse_timerange("1d"),
                      load_rules_config())
    assert explain_dossier(d, kb).gaps == []


def test_event_keys_per_source():
    from hunterscope.models import Event

    proc = Event(ts=ts(11, 9, 0), source="windows", action="process_create", app="C:\\Windows\\System32\\CertUtil.exe",
                 detail={"event_id": 4688})
    assert event_keys(proc) == [("windows_events", "4688"), ("processes", "certutil.exe")]
    access = Event(ts=ts(11, 9, 0), source="windows", action="process_access", app="C:\\x\\dump.exe",
                   detail={"event_id": 10, "target_image": "C:\\Windows\\System32\\lsass.exe"})
    assert event_keys(access) == [("sysmon_events", "10"), ("processes", "dump.exe"), ("processes", "lsass.exe")]
    assert event_keys(signin(ts(11, 9, 0), ok=False, code=50126)) == [("entra_errors", "50126")]


# --------------------------------------------------------------------------------- CLI


def test_cli_lookup_and_exit_codes():
    ok = runner.invoke(app, ["explain", "4688", "T1003.001"])
    assert ok.exit_code == 0 and "Utworzenie procesu" in ok.stdout and "LSASS Memory" in ok.stdout
    unknown = runner.invoke(app, ["explain", "4688", "nonsense"])
    assert unknown.exit_code == 1 and "Brak wpisu" in unknown.stdout and "Utworzenie procesu" in unknown.stdout


def test_cli_lookup_json():
    r = runner.invoke(app, ["explain", "50126", "nonsense", "-f", "json"])
    data = json.loads(r.stdout)
    assert data[0]["found"] and data[0]["entries"][0]["key"] == "50126"
    assert data[1]["found"] is False and data[1]["entries"] == []


def test_cli_dossier_mode_explains_findings():
    r = runner.invoke(app, ["explain", "-i", str(SAMPLES), "-u", "jkowalski", "-t", "7d"])
    assert r.exit_code == 0
    for needle in ("Reguła impossible_travel", "Reguła mfa_fatigue", "500121", "New-InboxRule", "Co sprawdzić"):
        assert needle in r.stdout


def test_cli_dossier_redaction_hides_the_target():
    plain = runner.invoke(app, ["explain", "-i", str(SAMPLES), "-u", "jkowalski"])
    assert "jkowalski" in plain.stdout
    red = runner.invoke(app, ["explain", "-i", str(SAMPLES), "-u", "jkowalski", "--redact"])
    assert "jkowalski" not in red.stdout.lower() and "USER_A" in red.stdout


def test_cli_dossier_unknown_target_is_exit_2():
    assert runner.invoke(app, ["explain", "-i", str(SAMPLES), "-u", "nobody"]).exit_code == 2


@pytest.mark.parametrize("args", [
    [],                                                     # nothing to do
    ["4688", "-i", str(SAMPLES), "-u", "jkowalski"],        # both modes
    ["-i", str(SAMPLES)],                                   # dossier mode without a target
    ["-i", str(SAMPLES), "-u", "a", "-H", "b"],             # two targets
    ["4688", "-u", "jkowalski"],                            # target without --input
    ["4688", "--redact"],                                   # --redact is meaningless for a lookup
    ["4688", "-f", "html"],
])
def test_cli_rejects_bad_combinations(args):
    assert runner.invoke(app, ["explain", *args]).exit_code != 0


def test_cli_bad_kb_file_is_a_clean_error(tmp_path):
    bad = tmp_path / "kb.yaml"
    bad.write_text("processes: [unclosed")
    r = runner.invoke(app, ["explain", "4688", "--kb", str(bad)])
    assert r.exit_code != 0 and "Traceback" not in r.stdout
