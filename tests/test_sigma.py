import base64

import pytest
import yaml

from hunterscope.sigma import Rec, Unsupported, compile_condition, compile_field, load_ruleset, parse_rule
from hunterscope.sigma.rule import _b64_variants


def rec(**fields):
    return Rec(fields)


def hit(spec, values, **fields):
    return compile_field(spec, values)(rec(**fields))


# ------------------------------------------------------------------------------- string modifiers


def test_equality_is_case_insensitive_and_exact():
    assert hit("Image", "C:\\Windows\\CMD.exe", Image="c:\\windows\\cmd.EXE")
    assert not hit("Image", "cmd.exe", Image="C:\\cmd.exe")


@pytest.mark.parametrize(
    ("spec", "value", "text", "expected"),
    [
        ("Image|endswith", "\\cmd.exe", "C:\\Windows\\System32\\CMD.EXE", True),
        ("Image|endswith", "\\cmd.exe", "C:\\cmd.exe.bak", False),
        ("Image|startswith", "c:\\users\\", "C:\\Users\\bob\\x.exe", True),
        ("Image|startswith", "c:\\users\\", "D:\\C:\\Users\\", False),
        ("CommandLine|contains", "-ENC", "powershell -enc AAAA", True),
        ("CommandLine|contains", "mimikatz", "notepad", False),
    ],
)
def test_contains_startswith_endswith(spec, value, text, expected):
    field = spec.split("|")[0]
    assert hit(spec, value, **{field: text}) is expected


def test_value_list_is_or_and_all_modifier_is_and():
    assert hit("CommandLine|contains", ["foo", "bar"], CommandLine="xx bar xx")
    assert not hit("CommandLine|contains|all", ["foo", "bar"], CommandLine="xx bar xx")
    assert hit("CommandLine|contains|all", ["foo", "bar"], CommandLine="bar and foo")


def test_missing_field_never_matches():
    assert not hit("Image|endswith", "x", CommandLine="x")
    assert not hit("Image", "x")


def test_field_names_are_case_insensitive():
    assert hit("image", "x", IMAGE="x") and hit("IMAGE|contains", "x", Image="axb")


def test_numbers_and_booleans_compare_as_text():
    assert hit("EventID", 4688, EventID=4688) and hit("EventID", 4688, EventID="4688")
    assert hit("Elevated", True, Elevated="true")


# ------------------------------------------------------------------------------------- wildcards


def test_wildcards():
    assert hit("Image", "*\\cmd.exe", Image="C:\\Windows\\cmd.exe")
    assert hit("Image", "c:\\\\*\\cmd.exe", Image="C:\\Windows\\System32\\cmd.exe")  # `\\*`: backslash + wildcard
    assert hit("Image", "cm?.exe", Image="cmd.exe") and not hit("Image", "cm?.exe", Image="cmdd.exe")
    assert hit("CommandLine|contains", "a*b", CommandLine="xxaFOOb")


def test_escaped_wildcards_are_literal():
    assert hit("CommandLine|contains", "a\\*b", CommandLine="a*b")
    assert not hit("CommandLine|contains", "a\\*b", CommandLine="aXb")
    assert hit("CommandLine|contains", "what\\?", CommandLine="what?")
    assert not hit("CommandLine|contains", "what\\?", CommandLine="whatx")


def test_backslash_before_a_wildcard_pair_is_a_literal_backslash_then_wildcard():
    assert hit("Image", "c:\\\\*", Image="c:\\windows")
    assert not hit("Image", "c:\\\\*", Image="c:/windows")


def test_plain_backslashes_in_paths_stay_literal():
    assert hit("Image|contains", "\\windows\\temp\\", Image="C:\\Windows\\Temp\\x.exe")


# ---------------------------------------------------------------------------------------- re


def test_regex_is_case_sensitive_unless_i():
    assert hit("CommandLine|re", "^foo\\d+$", CommandLine="foo123")
    assert not hit("CommandLine|re", "^FOO", CommandLine="foo")
    assert hit("CommandLine|re|i", "^FOO", CommandLine="foo")


def test_regex_flags_m_and_s():
    assert hit("CommandLine|re|m", "^b$", CommandLine="a\nb\nc")
    assert hit("CommandLine|re|s", "a.b", CommandLine="a\nb") and not hit("CommandLine|re", "a.b", CommandLine="a\nb")


def test_bad_regex_is_unsupported_not_a_crash():
    with pytest.raises(Unsupported):
        compile_field("CommandLine|re", "([")


# -------------------------------------------------------------------------------------- windash


@pytest.mark.parametrize("dash", ["-", "/", "\u2013", "\u2014", "\u2015"])
def test_windash_matches_every_dash_style(dash):
    assert hit("CommandLine|contains|windash", " -enc ", CommandLine=f"powershell {dash}enc AAAA")


def test_windash_does_not_touch_dashes_inside_words():
    assert not hit("CommandLine|contains|windash", "a-b", CommandLine="a/b")
    assert hit("CommandLine|contains|windash", "a-b", CommandLine="a-b")


# --------------------------------------------------------------------------------------- cidr


def test_cidr():
    f = compile_field("DestinationIp|cidr", ["10.0.0.0/8", "192.168.0.0/16"])
    assert f(rec(DestinationIp="10.20.30.40")) and f(rec(DestinationIp="192.168.5.5"))
    assert not f(rec(DestinationIp="8.8.8.8")) and not f(rec(DestinationIp="not an ip"))
    assert not f(rec(DestinationIp="::1")) and not f(rec())


# ------------------------------------------------------------------- exists, null, numeric


def test_exists():
    assert compile_field("ParentImage|exists", True)(rec(ParentImage="x"))
    assert not compile_field("ParentImage|exists", True)(rec())
    assert compile_field("ParentImage|exists", False)(rec())


def test_null_matches_missing_or_empty_and_mixes_with_values():
    only_null = compile_field("ParentImage", None)
    assert only_null(rec()) and only_null(rec(ParentImage="")) and not only_null(rec(ParentImage="x"))
    mixed = compile_field("ParentImage", [None, "cmd.exe"])
    assert mixed(rec()) and mixed(rec(ParentImage="cmd.exe")) and not mixed(rec(ParentImage="other"))


def test_numeric_comparisons():
    assert compile_field("Size|gt", 10)(rec(Size="11")) and not compile_field("Size|gt", 10)(rec(Size="10"))
    assert compile_field("Size|gte", 10)(rec(Size=10)) and compile_field("Size|lt", 10)(rec(Size="9.5"))
    assert not compile_field("Size|lt", 10)(rec(Size="n/a")) and not compile_field("Size|lt", 10)(rec())


# ---------------------------------------------------------------------------------------- base64


@pytest.mark.parametrize("prefix_len", [0, 1, 2, 3, 4, 5])
def test_base64offset_finds_the_value_at_every_alignment(prefix_len):
    payload = b"P" * prefix_len + b"whoami /priv" + b"tail"
    text = base64.b64encode(payload).decode()
    assert hit("CommandLine|base64offset|contains", "whoami /priv", CommandLine=f"x {text} y")


def test_base64offset_variants_follow_the_spec_shape():
    variants = _b64_variants(b"whoami", offset=True)
    assert len(variants) == 3 and all(v for v in variants)
    assert _b64_variants(b"whoami", offset=False) == [base64.b64encode(b"whoami").decode()]


def test_wide_base64_is_utf16le():
    enc = base64.b64encode("whoami".encode("utf-16-le")).decode()
    assert hit("CommandLine|wide|base64offset|contains", "whoami", CommandLine=f"-enc {enc}")
    assert not hit("CommandLine|base64offset|contains", "whoami", CommandLine=f"-enc {enc}")


def test_base64_is_case_sensitive():
    enc = base64.b64encode(b"whoami").decode()
    assert hit("CommandLine|base64|contains", "whoami", CommandLine=enc)
    assert not hit("CommandLine|base64|contains", "whoami", CommandLine=enc.swapcase())


# ------------------------------------------------------------------------------------ conditions


def cond(text, **selections):
    return compile_condition(text, {k: (lambda r, v=v: v) for k, v in selections.items()})(rec())


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a and b", False), ("a or b", True), ("a and not b", True), ("not a", False), ("not (a and b)", True),
        ("(a or b) and not c", True), ("a or b and c", True), ("(a or b) and c", False),
        ("1 of s*", True), ("all of s*", False), ("1 of them", True), ("all of them", False),
        ("a and not 1 of f*", True), ("a and 1 of f*", False), ("any of s*", True),
    ],
)
def test_condition_truth_table(text, expected):
    sel = {"a": True, "b": False, "c": False, "s1": True, "s2": False, "f1": False, "f2": False}
    assert cond(text, **sel) is expected


def test_and_binds_tighter_than_or_and_not_than_and():
    assert cond("a or b and c", a=True, b=False, c=False) is True
    assert cond("not a and b", a=False, b=True) is True


@pytest.mark.parametrize("text", ["selection | count() > 5", "selection | near other", "nosuch", "1 of nothing*",
                                  "(selection", "selection and", "selection selection"])
def test_unsupported_or_malformed_conditions_raise(text):
    with pytest.raises(Unsupported):
        compile_condition(text, {"selection": lambda r: True})


# --------------------------------------------------------------------------------- whole rules

RULE = """
title: Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
description: test rule
tags: [attack.execution, attack.t1059.001, attack.t1027, attack.g0001, attack.s0002, attack.credential_access]
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains|windash: ' -enc'
  filter:
    ParentImage|endswith: '\\trusted.exe'
  condition: selection and not filter
"""


def test_parse_rule_end_to_end_and_tags():
    r = parse_rule(yaml.safe_load(RULE))
    assert r.unsupported is None and r.level == "high" and r.category == "process_creation"
    assert r.techniques == ["T1059.001", "T1027"] and r.families == {"T1059", "T1027"}
    assert r.tactics == ["execution", "credential-access"]
    bad = {"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell /ENC AAAA"}
    assert r.match(Rec(bad))
    assert not r.match(Rec({**bad, "ParentImage": "C:\\trusted.exe"}))
    assert not r.match(Rec({"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell -file x.ps1"}))


@pytest.mark.parametrize(
    ("detection", "reason"),
    [
        ({"keywords": ["a", "b"], "condition": "keywords"}, "keyword"),
        ({"selection": {"A|fieldref": "B"}, "condition": "selection"}, "modifier fieldref"),
        ({"selection": {"A|weird": "x"}, "condition": "selection"}, "modifier weird"),
        ({"selection": {"A": "x"}, "condition": "selection | count() > 3"}, "aggregation"),
        ({"selection": {}, "condition": "selection"}, "empty"),
        ({"selection": {"A": "x"}}, "malformed"),
    ],
)
def test_unsupported_rules_are_flagged_not_half_evaluated(detection, reason):
    r = parse_rule({"title": "t", "level": "high", "status": "test", "logsource": {"product": "windows"},
                    "detection": detection})
    assert r.match is None and reason in (r.unsupported or "")


def test_multiple_conditions_are_or():
    doc = {"title": "t", "level": "high", "status": "test", "logsource": {"product": "windows"},
           "detection": {"a": {"X": "1"}, "b": {"Y": "2"}, "condition": ["a", "b"]}}
    r = parse_rule(doc)
    assert r.match(Rec({"X": "1"})) and r.match(Rec({"Y": "2"})) and not r.match(Rec({"X": "9"}))


def test_list_of_maps_is_or_of_ands():
    doc = {"title": "t", "level": "high", "status": "test", "logsource": {"product": "windows"},
           "detection": {"selection": [{"A": "1", "B": "2"}, {"C": "3"}], "condition": "selection"}}
    r = parse_rule(doc)
    assert r.match(Rec({"A": "1", "B": "2"})) and r.match(Rec({"C": "3"})) and not r.match(Rec({"A": "1"}))


# ----------------------------------------------------------------------------- the rule set


def write(tmp_path, name, doc):
    (tmp_path / name).write_text(doc if isinstance(doc, str) else yaml.safe_dump(doc))


def simple(title, category=None, service=None, level="high", status="test", product="windows", **detection):
    ls = {"product": product}
    if category:
        ls["category"] = category
    if service:
        ls["service"] = service
    return {"title": title, "id": title, "level": level, "status": status, "logsource": ls,
            "detection": {"selection": detection or {"Image|endswith": "\\x.exe"}, "condition": "selection"}}


def test_ruleset_filters_counts_and_reports(tmp_path):
    write(tmp_path, "keep.yml", simple("keep", "process_creation"))
    write(tmp_path, "low.yml", simple("low", "process_creation", level="low"))
    write(tmp_path, "dep.yml", simple("dep", "process_creation", status="deprecated"))
    write(tmp_path, "linux.yml", simple("linux", "process_creation", product="linux"))
    write(tmp_path, "unmapped.yml", simple("unmapped", "ps_script"))
    write(tmp_path, "kw.yml", {**simple("kw", "process_creation"),
                               "detection": {"keywords": ["a"], "condition": "keywords"}})
    write(tmp_path, "broken.yml", "title: [unclosed")
    rs = load_ruleset(tmp_path)
    s = rs.stats
    assert [r.title for r in rs.rules] == ["keep"]
    assert (s.files, s.rules, s.filtered_out, s.loaded, s.unparseable_files) == (7, 6, 3, 1, 1)
    assert s.unmapped_logsource == {"ps_script": 1} and sum(s.unsupported.values()) == 1


def test_min_level_and_statuses_are_parameters(tmp_path):
    write(tmp_path, "low.yml", simple("low", "process_creation", level="low"))
    write(tmp_path, "stable.yml", simple("stable", "process_creation", status="stable"))
    assert len(load_ruleset(tmp_path, min_level="low")) == 2
    assert [r.title for r in load_ruleset(tmp_path, min_level="low", statuses=("stable",)).rules] == ["stable"]


def test_sysmon_event_ids_select_the_right_category(tmp_path):
    for cat in ("process_creation", "network_connection", "process_access", "image_load", "registry_set",
                "registry_event", "file_event", "dns_query"):
        write(tmp_path, f"{cat}.yml", simple(cat, cat, Marker="1"))
    rs = load_ruleset(tmp_path)
    sysmon = "Microsoft-Windows-Sysmon/Operational"

    def names(event_id, **extra):
        return sorted(r.title for r in rs.match({"Channel": sysmon, "EventID": event_id, "Marker": "1", **extra}))

    assert names(1) == ["process_creation"] and names(3) == ["network_connection"]
    assert names(10) == ["process_access"] and names(7) == ["image_load"] and names(22) == ["dns_query"]
    assert names(13) == ["registry_event", "registry_set"] and names(12) == ["registry_event"]
    assert names(11) == ["file_event"] and names(99) == []


def test_registry_add_and_delete_use_the_event_type(tmp_path):
    write(tmp_path, "add.yml", simple("add", "registry_add", Marker="1"))
    write(tmp_path, "del.yml", simple("del", "registry_delete", Marker="1"))
    rs = load_ruleset(tmp_path)
    base = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 12, "Marker": "1"}
    assert [r.title for r in rs.match({**base, "EventType": "CreateKey"})] == ["add"]
    assert [r.title for r in rs.match({**base, "EventType": "DeleteKey"})] == ["del"]
    assert rs.match({**base, "EventType": "SetValue"}) == []


def test_security_4688_is_process_creation_with_sysmon_field_names(tmp_path):
    write(tmp_path, "p.yml", simple("p", "process_creation", **{"Image|endswith": "\\cmd.exe",
                                                                "ParentImage|endswith": "\\winword.exe"}))
    rs = load_ruleset(tmp_path)
    event = {"Channel": "security", "EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
             "ParentProcessName": "C:\\Office\\WINWORD.EXE", "CommandLine": "cmd /c whoami"}
    assert [r.title for r in rs.match(event)] == ["p"]
    assert rs.match({**event, "EventID": 4689}) == [] and rs.match({**event, "Channel": "system"}) == []


def test_service_rules_match_their_channel_only(tmp_path):
    write(tmp_path, "sec.yml", simple("sec", service="security", EventID=4624))
    write(tmp_path, "sys.yml", simple("sys", service="system", EventID=7045))
    rs = load_ruleset(tmp_path)
    assert [r.title for r in rs.match({"Channel": "security", "EventID": 4624})] == ["sec"]
    assert rs.match({"Channel": "system", "EventID": 4624}) == []
    assert [r.title for r in rs.match({"Channel": "System", "EventID": "7045"})] == ["sys"]


def test_product_only_rules_apply_to_every_record(tmp_path):
    write(tmp_path, "g.yml", simple("generic", Marker="x"))
    rs = load_ruleset(tmp_path)
    assert len(rs.match({"Channel": "anything", "Marker": "x"})) == 1


def test_a_rule_with_category_and_service_needs_both(tmp_path):
    doc = simple("both", "process_creation", "security", **{"Image|endswith": "\\a.exe"})
    write(tmp_path, "b.yml", doc)
    rs = load_ruleset(tmp_path)
    sec = {"Channel": "security", "EventID": 4688, "NewProcessName": "C:\\a.exe"}
    sysmon = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\a.exe"}
    assert len(rs.match(sec)) == 1 and rs.match(sysmon) == []


def test_matching_does_not_mutate_the_input_record(tmp_path):
    write(tmp_path, "p.yml", simple("p", "process_creation", **{"Image|endswith": "\\cmd.exe"}))
    rs = load_ruleset(tmp_path)
    event = {"Channel": "security", "EventID": 4688, "NewProcessName": "C:\\cmd.exe"}
    snapshot = dict(event)
    rs.match(event)
    assert event == snapshot
