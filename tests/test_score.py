from helpers import cmd, signin, ts
from hunterscope.detect import run_detections
from hunterscope.score import compute_score, level_for


def test_empty_is_info(cfg):
    s = compute_score([], cfg)
    assert (s.total, s.level) == (0, "info")


def test_repeat_hits_are_dampened_and_capped(cfg):
    evs = [cmd(ts(2, 9, i), "whoami /priv") for i in range(20)]
    s = compute_score(run_detections(evs, cfg), cfg)
    c = s.contributions[0]
    assert c.hits == 20 and c.points == 40.0  # weight 20 * cap 2.0
    assert s.bonus == 0


def test_multi_stage_bonus(cfg):
    evs = [cmd(ts(2, 9, 0), "whoami /priv"), signin(ts(2, 2, 0))]
    s = compute_score(run_detections(evs, cfg), cfg)
    assert s.bonus == 10 and "multi-stage" in s.bonus_reason


def test_total_capped_at_100(loaded, cfg):
    from hunterscope.triage import build_dossier, parse_timerange

    d = build_dossier(loaded.events, "user", "jkowalski", parse_timerange("24h"), cfg)
    assert d.score.total == 100 and d.score.level == "critical"


def test_level_thresholds(cfg):
    lv = cfg["scoring"]["levels"]
    assert [level_for(x, lv) for x in (0, 10, 30, 60, 80)] == [
        "info", "low", "medium", "high", "critical"]
