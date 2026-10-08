import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hunterscope.cli import app

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
ARGS = ["-i", str(SAMPLES)]
runner = CliRunner()


def test_attacker_dossier_is_critical_and_complete():
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski"])
    assert r.exit_code == 0
    for needle in ("CRITICAL", "Impossible travel", "MFA fatigue", "Suspicious mailbox rule",
                   "OAuth consent", "T1114/003", "203.0.113.50", "Suspicious email",
                   "Possible account takeover", "hxxp://198[.]51[.]100[.]200/login"):
        assert needle in r.stdout


def test_benign_user_has_no_findings():
    r = runner.invoke(app, ["triage", *ARGS, "-u", "akowalska"])
    assert r.exit_code == 0 and "0/100 (INFO)" in r.stdout


def test_redacted_output_leaks_nothing():
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--redact"])
    low = r.stdout.lower()
    for secret in ("jkowalski", "contoso", "mail-drop.test"):
        assert secret not in low
    # public IPs are IOCs and kept by default (the sample "corporate" IP is public too)
    assert "USER_A" in r.stdout and "203.0.113.50" in r.stdout


def test_strict_redaction_masks_public_ips(tmp_path):
    cfg = tmp_path / "r.yaml"
    cfg.write_text("keep_public_ips: false\n")
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--redact", "--redactor-config", str(cfg)])
    assert "192.0.2.10" not in r.stdout and "203.0.113.50" not in r.stdout and "IP_1" in r.stdout


def test_host_triage_and_unknown_target():
    ok = runner.invoke(app, ["triage", *ARGS, "-H", "ws-jkowalski"])
    assert ok.exit_code == 0 and "lotl_commandline" in ok.stdout
    assert runner.invoke(app, ["triage", *ARGS, "-u", "nobody"]).exit_code == 2


def test_requires_exactly_one_target_and_valid_range():
    assert runner.invoke(app, ["triage", *ARGS]).exit_code != 0
    assert runner.invoke(app, ["triage", *ARGS, "-u", "a", "-H", "b"]).exit_code != 0
    assert runner.invoke(app, ["triage", *ARGS, "-u", "a", "-t", "soon"]).exit_code != 0


def test_json_output_and_mapping_file(tmp_path):
    out, mp = tmp_path / "o.json", tmp_path / "m.mapping.json"
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "-f", "json", "--redact",
                            "-o", str(out), "--mapping-out", str(mp)])
    assert r.exit_code == 0
    data = json.loads(out.read_text())
    assert data["score"]["level"] == "critical" and data["target"] == "USER_A"
    assert json.loads(mp.read_text())["USER_A"] == "jkowalski"


def test_mapping_requires_redact(tmp_path):
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--mapping-out", str(tmp_path / "m")])
    assert r.exit_code != 0


def test_stable_key_env(monkeypatch):
    monkeypatch.setenv("HS_KEY", "secret")
    a = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--redact", "--key-env", "HS_KEY"])
    b = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--redact", "--key-env", "HS_KEY"])
    assert a.exit_code == 0 and "USER_A" not in a.stdout
    def stable(out: str) -> list[str]:
        return [ln for ln in out.splitlines() if "Generated" not in ln]

    assert stable(a.stdout) == stable(b.stdout)
    monkeypatch.delenv("HS_KEY")
    assert runner.invoke(app, ["triage", *ARGS, "-u", "j", "--redact", "--key-env", "HS_KEY"]).exit_code != 0


def _case_args(tmp_path):
    return ["--db", str(tmp_path / "c.db"), "--author", "anna"]


def test_save_creates_then_updates_case(tmp_path):
    base = ["triage", *ARGS, "-u", "jkowalski", "--save", *_case_args(tmp_path)]
    a = runner.invoke(app, base)
    b = runner.invoke(app, base)
    assert a.exit_code == 0 and "opened" in a.stderr + a.output
    assert "updated" in b.stderr + b.output and "0 new finding" in b.stderr + b.output


def test_case_workflow_and_shift_summary(tmp_path):
    db = _case_args(tmp_path)
    runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--save", *db])
    runner.invoke(app, ["triage", *ARGS, "-u", "akowalska", "--save", *db])
    bad = runner.invoke(app, ["case", "status", "2", "closed_fp", *db])
    assert bad.exit_code == 1  # reason required
    ok = runner.invoke(app, ["case", "status", "2", "closed_fp", "-n", "flight, not impossible travel", *db])
    assert ok.exit_code == 0
    assert runner.invoke(app, ["case", "note", "1", "reset password", *db]).exit_code == 0
    assert runner.invoke(app, ["case", "status", "99", "closed_fp", "-n", "x", *db]).exit_code == 2
    shown = runner.invoke(app, ["case", "show", "1", *db[:2]])
    assert "Impossible travel" in shown.stdout and "reset password" in shown.stdout
    listed = runner.invoke(app, ["case", "list", *db[:2]])
    assert "jkowalski" in listed.stdout and "akowalska" not in listed.stdout  # closed hidden by default
    md = runner.invoke(app, ["shift-summary", "--format", "md", *db])
    assert md.exit_code == 0
    assert "flight, not impossible travel" in md.stdout and "reset password" in md.stdout  # last note shown
    assert "user `jkowalski`" in md.stdout
    red = runner.invoke(app, ["shift-summary", "--redact", *db])
    assert "jkowalski" not in red.stdout.lower() and "USER_" in red.stdout


def test_shift_summary_terminal_tables_and_validation(tmp_path):
    db = _case_args(tmp_path)
    runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--save", *db])
    t = runner.invoke(app, ["shift-summary", "--format", "terminal", *db])
    assert t.exit_code == 0 and "Unresolved" in t.stdout and "jkowalski" in t.stdout
    assert runner.invoke(app, ["shift-summary", "--hours", "0", *db]).exit_code != 0
    assert runner.invoke(app, ["shift-summary", "--format", "pdf", *db]).exit_code != 0
    assert runner.invoke(app, ["shift-summary", "--until", "yesterday", *db]).exit_code != 0


def test_coverage_cli_validates_arguments(tmp_path):
    assert runner.invoke(app, ["coverage"]).exit_code != 0                          # needs a dataset
    (tmp_path / "datasets/atomic/_metadata").mkdir(parents=True)
    r = runner.invoke(app, ["coverage", "--otrf", str(tmp_path)])
    assert r.exit_code == 2                                                         # nothing fetched yet


@pytest.mark.parametrize("stamp", ["2026-03-11T20:00:00Z", "2026-03-11T20:00:00z", "2026-03-11T20:00:00+00:00",
                                   "2026-03-11 20:00:00"])
def test_until_and_anchor_accept_z_suffix_and_naive_utc(tmp_path, stamp):
    db = _case_args(tmp_path)
    runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--save", *db])
    assert runner.invoke(app, ["shift-summary", "--format", "md", "--until", stamp, *db]).exit_code == 0
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--anchor", stamp])
    assert r.exit_code == 0 and "2026-03-11 20:00:00" in r.stdout


def test_bad_anchor_is_a_usage_error_not_a_traceback():
    r = runner.invoke(app, ["triage", *ARGS, "-u", "jkowalski", "--anchor", "yesterday"])
    assert r.exit_code != 0 and not isinstance(r.exception, ValueError)
