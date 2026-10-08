import json
import zipfile

import pytest

from hunterscope import coverage as cov
from hunterscope.config.loader import load_rules_config

CFG = load_rules_config()


def meta(did="SDWIN-1", platform="Windows", techs=(("T1003", "001"),),
         link_dir="windows/credential_access/host", typ="Host"):
    maps = "\n".join(f"  - technique: {t}\n    sub-technique: {repr(s) if s else ''}" for t, s in techs)
    return (f"title: Test {did}\nid: {did}\nplatform:\n- {platform}\nattack_mappings:\n{maps}\nfiles:\n"
            f"  - type: {typ}\n    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
            f"datasets/atomic/{link_dir}/{did}.zip\n")


def make_zip(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("data.json", "\n".join(json.dumps(r) if isinstance(r, dict) else r for r in records))


@pytest.fixture
def otrf(tmp_path):
    (tmp_path / "datasets/atomic/_metadata").mkdir(parents=True)
    return tmp_path


def add(otrf, did, techs, records, **kw):
    (otrf / f"datasets/atomic/_metadata/{did}.yaml").write_text(meta(did, techs=techs, **kw))
    make_zip(otrf / f"datasets/atomic/windows/credential_access/host/{did}.zip", records)


def proc(cmd, when="2026-03-01T10:00:00Z"):
    return {"EventID": 1, "TimeCreated": when, "Hostname": "h", "User": "D\\u", "CommandLine": cmd, "Image": "x.exe"}


def test_subtechnique_ids_are_zero_padded_and_filters_apply(otrf):
    add(otrf, "SDWIN-1", (("T1003", "001"), ("T1059", None)), [proc("x")])
    add(otrf, "SDLIN-2", (("T1003", "001"),), [proc("x")], platform="Linux")      # wrong platform
    add(otrf, "SDWIN-3", (("T1003", "001"),), [proc("x")], typ="Network")         # no host telemetry
    [ds] = cov.load_otrf(otrf)
    assert ds.id == "SDWIN-1" and ds.techniques == ["T1003.001", "T1059"] and len(ds.files) == 1


def test_missing_zip_is_skipped(otrf):
    (otrf / "datasets/atomic/_metadata/SDWIN-9.yaml").write_text(meta("SDWIN-9"))
    assert cov.load_otrf(otrf) == []


def test_covered_by_rule_semantics():
    declared = {"T1003.001", "T1059", "T1218.005"}
    assert cov.covered_by_rule("T1003.001", declared)
    assert not cov.covered_by_rule("T1003.002", declared)   # sibling sub-technique is NOT covered
    assert cov.covered_by_rule("T1003", declared)           # parent of a covered sub-technique
    assert cov.covered_by_rule("T1059.001", declared)       # sub-technique of a covered parent
    assert cov.covered_by_rule("T1218", declared)
    assert not cov.covered_by_rule("T1055", declared)


def test_hit_levels():
    got = {"T1059.001", "T1027"}
    assert cov.exact_hit("T1059.001", got) and cov.exact_hit("T1059", got)
    assert not cov.exact_hit("T1059.005", got) and cov.family_hit("T1059.005", got)
    assert not cov.family_hit("T1003", got)


def test_run_end_to_end_with_hit_miss_and_no_telemetry(otrf):
    enc = "powershell.exe -enc " + "A" * 30
    sysmon_registry = {"EventID": 12, "TimeCreated": "2026-03-01T10:00:00Z"}
    add(otrf, "SDWIN-1", (("T1059", "001"),), [proc(enc)])                 # hit
    add(otrf, "SDWIN-2", (("T1059", "001"),), [proc("notepad.exe")])       # miss, has telemetry
    add(otrf, "SDWIN-3", (("T1059", "001"),), [sysmon_registry])           # nothing the rules can read
    results = cov.run_otrf(cov.load_otrf(otrf), CFG)
    by_id = {r.dataset.id: r for r in results}
    assert by_id["SDWIN-1"].findings and not by_id["SDWIN-2"].findings
    assert by_id["SDWIN-2"].telemetry == 1 and by_id["SDWIN-3"].telemetry == 0
    text = cov.render(results, None, CFG, "abc1234")
    assert "1 / 2" in text                       # evaluable datasets: 2, hit: 1
    assert "no process/logon events" in text and "@ `abc1234`" in text
    rows = {r.technique: r for r in cov.technique_table(results, cov.declared_techniques(CFG))}
    assert (rows["T1059.001"].datasets, rows["T1059.001"].exact) == (3, 1)


def test_off_label_counts(otrf):
    add(otrf, "SDWIN-1", (("T1547", "001"),), [proc("powershell.exe -enc " + "A" * 30)])
    [(rule, (total, off))] = cov.off_label(cov.run_otrf(cov.load_otrf(otrf), CFG)).items()
    assert (rule, total, off) == ("lotl_commandline", 1, 1)


def test_bad_records_are_counted_and_oversize_members_ignored(tmp_path, monkeypatch):
    make_zip(tmp_path / "a.zip", [proc("x"), "{broken", json.dumps({"no": "eventid"})])
    events, skipped = cov.events_from_zip(tmp_path / "a.zip")
    assert len(events) == 1 and skipped == 2
    monkeypatch.setattr(cov, "MAX_MEMBER_BYTES", 5)
    assert cov.events_from_zip(tmp_path / "a.zip") == ([], 0)


def test_lab_config_disables_clock_dependent_rule_without_mutating():
    lab = cov.lab_config(CFG)
    assert lab["rules"]["off_hours_login"]["enabled"] is False
    assert CFG["rules"]["off_hours_login"].get("enabled", True) is True


def test_flatten_evtx_record():
    doc = {"Event": {"System": {"EventID": {"#text": 4688}, "Computer": "WS1",
                                "TimeCreated": {"#attributes": {"SystemTime": "2020-01-01T00:00:00Z"}}},
                     "EventData": {"CommandLine": "whoami /priv", "NewProcessName": "x.exe", "Nested": {"a": 1}}}}
    flat = cov.flatten_evtx_record(doc)
    assert flat["EventID"] == 4688 and flat["Computer"] == "WS1" and "Nested" not in flat
    from hunterscope.ingest.parsers import parse_windows

    assert parse_windows(flat).command_line == "whoami /priv"


def test_render_without_datasets_still_explains_scope():
    text = cov.render(None, None, CFG)
    assert "How to read this" in text and "not an EDR" in text


def test_split_is_deterministic_balanced_and_salted():
    ids = [f"SDWIN-{i:06d}" for i in range(2000)]
    first = [cov.split_of(i) for i in ids]
    assert first == [cov.split_of(i) for i in ids]
    assert 900 < first.count("dev") < 1100
    assert first != [cov.split_of(i, salt="other") for i in ids]
    # frozen expectations: changing SPLIT_SALT or the scheme would silently reshuffle the holdout
    assert cov.SPLIT_SALT == "hunterscope-split-v1"
    assert [cov.split_of(i) for i in ("SDWIN-190518202151", "SDWIN-191027055035", "SDWIN-201018225619")] == [
        "holdout", "dev", "dev"]


def test_wilson_interval():
    assert cov.wilson(0, 0) == (0.0, 0.0)
    lo, hi = cov.wilson(1, 7)
    assert 0.02 < lo < 0.04 and 0.45 < hi < 0.55          # 1/7: wide, as the report says
    assert cov.wilson(10, 10)[1] == 1.0 and cov.wilson(0, 10)[0] == 0.0
    lo, hi = cov.wilson(50, 100)
    assert 0.39 < lo < 0.41 and 0.59 < hi < 0.61


def test_ablation_report_shows_delta_cost_and_newly_hit(otrf):
    access = {"EventID": 10, "TimeCreated": "2026-03-01T10:00:00Z", "Hostname": "h", "SourceImage": "C:\\x\\d.exe",
              "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410"}
    add(otrf, "SDWIN-1", (("T1003", "001"),), [access])
    add(otrf, "SDWIN-2", (("T1547", "001"),), [access])           # off-label: lsass finding, other label
    datasets = cov.load_otrf(otrf)
    now = cov.run_otrf(datasets, CFG)
    before = cov.run_otrf(datasets, CFG, also_disable=("lsass_access",))
    declared = cov.declared_techniques(CFG)
    assert [r.dataset.id for r in cov.gained(now, before, declared)] == ["SDWIN-1"]
    cost = cov.rule_cost(now, "lsass_access")
    assert sum(c[0] for c in cost.values()) == 2 and sum(c[1] for c in cost.values()) == 1
    text = cov.render(now, None, CFG, baseline=before, ablated=("lsass_access",))
    assert "Without `lsass_access`" in text and "became a family hit only because of" in text
    assert "SDWIN-1" in text and "95% CI" in text
