import json
from collections import Counter
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from helpers import ts
from hunterscope import coverage as cov
from hunterscope import sigma_bench as sb
from hunterscope.cli import app
from hunterscope.detect import run_detections
from hunterscope.detect.sigma_rules import sigma_findings
from hunterscope.ingest import load_events
from hunterscope.ingest.parsers import parse_windows
from hunterscope.report import render_html
from hunterscope.score import compute_score
from hunterscope.sigma import load_ruleset
from hunterscope.triage import Dossier

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
runner = CliRunner()
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rule_doc(title, level="high", tags=("attack.execution", "attack.t1059.001"), **selection):
    return {"title": title, "id": f"id-{title}", "status": "test", "level": level, "description": f"{title} desc",
            "tags": list(tags), "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {"selection": selection or {"CommandLine|contains": "-enc"}, "condition": "selection"}}


@pytest.fixture
def rules_dir(tmp_path):
    root = tmp_path / "sigma" / "rules" / "windows"
    root.mkdir(parents=True)
    (root / "enc.yml").write_text(yaml.safe_dump(rule_doc("Encoded PowerShell")))
    (root / "whoami.yml").write_text(yaml.safe_dump(
        rule_doc("Whoami priv", level="medium", tags=("attack.discovery", "attack.t1033"),
                 **{"CommandLine|contains": "whoami /priv"})))
    return tmp_path / "sigma"


def sysmon_record(cmd, host="WS1", when="2026-03-01T10:00:00Z", **extra):
    return {"EventID": 1, "TimeCreated": when, "Computer": host, "User": "D\\u", "CommandLine": cmd,
            "Image": "C:\\Windows\\System32\\powershell.exe", "Channel": SYSMON, **extra}


# ------------------------------------------------------------------------------ raw retention


def test_raw_record_is_kept_only_on_request_and_never_serialized():
    rec = sysmon_record("powershell -enc AAAA")
    assert parse_windows(rec).raw is None
    kept = parse_windows(rec, keep_raw=True)
    assert kept.raw == rec and "raw" not in kept.model_dump() and "raw" not in repr(kept)


def test_loader_keeps_raw_for_windows_only_when_asked(tmp_path):
    p = tmp_path / "w.ndjson"
    p.write_text(json.dumps(sysmon_record("x")) + "\n")
    assert load_events([p]).events[0].raw is None
    assert load_events([p], keep_raw=True).events[0].raw is not None
    ent = tmp_path / "e.ndjson"
    ent.write_text(json.dumps({"createdDateTime": "2026-03-01T10:00:00Z", "userPrincipalName": "a@b.c",
                               "status": {"errorCode": 0}}) + "\n")
    assert load_events([ent], keep_raw=True).events[0].raw is None


# ---------------------------------------------------------------------------------- findings


def events_for(*records):
    return [parse_windows(r, keep_raw=True) for r in records]


def test_one_finding_per_rule_and_host_with_level_weight_and_tags(rules_dir, cfg):
    rs = load_ruleset(rules_dir)
    evs = events_for(sysmon_record("powershell -enc AAA"),
                     sysmon_record("powershell -enc BBB", when="2026-03-01T10:01:00Z"),
                     sysmon_record("powershell -enc CCC", host="WS2"))
    found = sigma_findings(evs, rs, cfg["sigma"])
    assert len(found) == 2  # same rule, two hosts
    ws1 = next(f for f in found if len(f.evidence) == 2)
    assert (ws1.rule_id, ws1.severity, ws1.weight, ws1.tactic) == ("sigma_high", "high", 30.0, "execution")
    assert ws1.mitre == ["T1059.001"] and "2 matching events" in ws1.description
    assert "id-Encoded PowerShell" in ws1.description
    assert ("command", "powershell -enc AAA") in ws1.iocs


def test_medium_level_weighs_less_and_discovery_tactic_is_taken_from_tags(rules_dir, cfg):
    [f] = sigma_findings(events_for(sysmon_record("whoami /priv")), load_ruleset(rules_dir), cfg["sigma"])
    assert (f.rule_id, f.weight, f.tactic, f.mitre) == ("sigma_medium", 15.0, "discovery", ["T1033"])


def test_events_without_a_raw_record_and_non_matching_events_are_ignored(rules_dir, cfg):
    rs = load_ruleset(rules_dir)
    no_raw = [parse_windows(sysmon_record("powershell -enc AAA"))]
    assert sigma_findings(no_raw, rs, cfg["sigma"]) == []
    assert sigma_findings(events_for(sysmon_record("notepad.exe")), rs, cfg["sigma"]) == []


def test_evidence_is_capped(rules_dir, cfg):
    rs = load_ruleset(rules_dir)
    recs = [sysmon_record(f"powershell -enc {i}", when=f"2026-03-01T10:{i % 60:02d}:00Z") for i in range(40)]
    [f] = sigma_findings(events_for(*recs), rs, {**cfg["sigma"], "max_evidence": 5})
    assert len(f.evidence) == 5 and "40 matching events" in f.description


def test_untagged_rule_gets_unknown_tactic_and_does_not_inflate_the_bonus(tmp_path, cfg):
    root = tmp_path / "r"
    root.mkdir()
    (root / "a.yml").write_text(yaml.safe_dump(rule_doc("Untagged", tags=())))
    [f] = sigma_findings(events_for(sysmon_record("powershell -enc A")), load_ruleset(root), cfg["sigma"])
    assert f.tactic == "unknown" and f.mitre == []
    other = type(f)(**{**f.__dict__, "rule_id": "x", "tactic": "execution"})
    score = compute_score([f, other], cfg)
    assert score.bonus == 0  # "unknown" is not a second tactic


def test_run_detections_adds_sigma_only_when_a_ruleset_is_given(rules_dir, cfg):
    evs = events_for(sysmon_record("powershell -enc AAA"))
    assert not [f for f in run_detections(evs, cfg) if f.rule_id.startswith("sigma_")]
    assert [f.rule_id for f in run_detections(evs, cfg, sigma=load_ruleset(rules_dir))
            if f.rule_id.startswith("sigma_")] == ["sigma_high"]


def test_sigma_text_is_escaped_in_the_html_report(tmp_path, cfg):
    root = tmp_path / "r"
    root.mkdir()
    (root / "x.yml").write_text(yaml.safe_dump({**rule_doc("<script>alert(1)</script>"),
                                                "description": '"><img src=x onerror=alert(2)>'}))
    findings = run_detections(events_for(sysmon_record("powershell -enc A")), cfg, sigma=load_ruleset(root))
    d = Dossier("host", "ws1", ts(1, 0, 0), ts(1, 23, 0), [], findings, compute_score(findings, cfg), Counter())
    html = render_html(d, cfg)
    assert "<script>alert" not in html and "<img src=x" not in html and "&lt;script&gt;alert(1)" in html


# ----------------------------------------------------------------------------------- the CLI


def test_cli_sigma_adds_findings_for_the_sample_host(rules_dir):
    base = ["triage", "-i", str(SAMPLES), "-H", "ws-jkowalski", "-f", "json"]
    plain = json.loads(runner.invoke(app, base).stdout)
    r = runner.invoke(app, [*base, "--sigma", str(rules_dir)])
    assert r.exit_code == 0
    with_sigma = json.loads(r.stdout[r.stdout.index("{"):])
    titles = {f["title"] for f in with_sigma["findings"]}
    assert {"Encoded PowerShell", "Whoami priv"} <= titles
    assert not any(f["rule_id"].startswith("sigma_") for f in plain["findings"])
    assert with_sigma["score"]["total"] > plain["score"]["total"]


def test_cli_sigma_leaves_the_benign_user_quiet(rules_dir):
    r = runner.invoke(app, ["triage", "-i", str(SAMPLES), "-u", "akowalska", "-f", "json", "--sigma", str(rules_dir)])
    data = json.loads(r.stdout[r.stdout.index("{"):])
    assert r.exit_code == 0 and data["findings"] == [] and data["score"]["total"] == 0


def test_cli_sigma_accepts_the_repo_root_or_the_rules_folder_and_rejects_an_empty_one(rules_dir, tmp_path):
    base = ["triage", "-i", str(SAMPLES), "-H", "ws-jkowalski", "-f", "json"]
    assert runner.invoke(app, [*base, "--sigma", str(rules_dir / "rules" / "windows")]).exit_code == 0
    empty = tmp_path / "empty"
    empty.mkdir()
    r = runner.invoke(app, [*base, "--sigma", str(empty)])
    assert r.exit_code == 2
    assert runner.invoke(app, [*base, "--sigma", str(tmp_path / "missing")]).exit_code != 0


# --------------------------------------------------------------------------------- benchmark


def _make_dataset(tmp_path, did, techniques, records):
    import zipfile

    z = tmp_path / f"{did}.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("d.json", "\n".join(json.dumps(r) for r in records))
    return cov.Dataset(did, did, techniques, [z])


def _dr(ds):
    return cov.DatasetResult(ds, 0, 0, [])


def test_run_sigma_otrf_counts_hits_and_collects_techniques(tmp_path, rules_dir):
    rs = load_ruleset(rules_dir)
    ds = _make_dataset(tmp_path, "SDWIN-1", ["T1059.001"],
                       [sysmon_record("powershell -enc A"), sysmon_record("powershell -enc B"), sysmon_record("calc")])
    [res] = sb.run_sigma_otrf([ds], rs)
    assert res.records == 3 and sum(res.hits.values()) == 2 and res.got == {"T1059.001"}


def test_family_versus_exact_hit_levels():
    assert sb._hit(["T1003.002"], {"T1003.001"}) and not sb._hit_exact(["T1003.002"], {"T1003.001"})
    assert sb._hit_exact(["T1003.001"], {"T1003.001"}) and sb._hit_exact(["T1003"], {"T1003.001"})
    assert not sb._hit(["T1003"], {"T1059.001"})


def test_compare_counts_hunterscope_sigma_and_union_per_split(tmp_path):
    from hunterscope.models import Finding
    from hunterscope.sigma import parse_rule

    ids = {name: next(f"SDWIN-{i}" for i in range(500) if cov.split_of(f"SDWIN-{i}") == name)
           for name in ("dev", "holdout")}

    def hs_result(ds, techniques):
        findings = [Finding("r", "t", "high", "execution", techniques, 1.0, "", [])] if techniques else []
        return cov.DatasetResult(ds, 0, 0, findings)

    def sigma_result(ds, techniques):
        tags = [f"attack.{t.lower()}" for t in techniques]
        rule = parse_rule({**rule_doc("r", tags=tags), "id": "r1"})
        return sb.SigmaDatasetResult(ds, 0, Counter(), {"r1": rule} if techniques else {})

    pairs = []
    for name, hs, sg in (("dev", ["T1059"], []), ("holdout", [], ["T1059.001"])):
        ds = _make_dataset(tmp_path, ids[name], ["T1059.001"], [])
        pairs.append((hs_result(ds, hs), sigma_result(ds, sg)))
    rows = {r.split: r for r in sb.compare(pairs, lambda d: True)}
    assert (rows["dev"].hunterscope, rows["dev"].sigma, rows["dev"].union) == (1, 0, 1)
    assert (rows["holdout"].hunterscope, rows["holdout"].sigma, rows["holdout"].union) == (0, 1, 1)
    assert (rows["all"].datasets, rows["all"].hunterscope, rows["all"].sigma, rows["all"].union) == (2, 1, 1, 2)


def test_render_sigma_reports_the_filter_the_noise_and_the_strict_check(tmp_path, rules_dir, cfg):
    rs = load_ruleset(rules_dir)
    ds = _make_dataset(tmp_path, "SDWIN-1", ["T1003.002"], [sysmon_record("powershell -enc A")])  # label differs
    results = sb.run_sigma_otrf([ds], rs)
    text = "\n".join(sb.render_sigma(rs, results, [_dr(ds)], cov.declared_techniques(cfg), "abc1234"))
    assert "SigmaHQ `abc1234`" in text and "Loaded and evaluated: **2**" in text
    assert "Noise signal (not precision)" in text and "Stricter check" in text and "Encoded PowerShell" in text
    assert "keyword" not in text.lower() or "unsupported" in text.lower()
