import http.client
import json
import threading

import pytest
from typer.testing import CliRunner

from hunterscope.cli import app
from hunterscope.trainer import scoring
from hunterscope.trainer.lookups import lookup, lookup_key
from hunterscope.trainer.model import ACTIONS
from hunterscope.trainer.scenarios import REGISTRY, generate, make_token, parse_token, variant_for
from hunterscope.trainer.server import make_server
from hunterscope.trainer.store import TrainerStore

CASES = [(t, d) for t in REGISTRY for d in (1, 2, 3)]


def _find(template: str, difficulty: int, verdict: str, mix: str = "p") -> str:
    for seed in range(2000):
        if variant_for(seed, template, mix) == verdict:
            return make_token(seed, template, difficulty, mix)
    raise AssertionError(f"no seed gives {verdict} for {template}")


def _perfect(scn) -> dict:
    return {
        "verdict": scn.truth.verdict,
        "actions": list(scn.truth.required_actions),
        "evidence": [e.id for e in scn.events if e.role == "key"],
        "lookups": list(scn.truth.expected_lookups),
        "hints": 0,
        "justification": "A reasoned, long enough justification for the next shift.",
    }


def test_token_roundtrip_and_validation():
    assert parse_token("12-ps_encoded-2-p") == (12, "ps_encoded", 2, "p")
    for bad in ("x", "1-nope-1-p", "1-ps_encoded-9-p", "1-ps_encoded-1-z", "1-ps-encoded-1-p"):
        with pytest.raises(ValueError):
            parse_token(bad)


@pytest.mark.parametrize("template,difficulty", CASES)
def test_every_variant_is_well_formed(template, difficulty):
    for verdict in REGISTRY[template].variants:
        scn = generate(_find(template, difficulty, verdict))
        assert scn.truth.verdict == verdict
        assert scn.alert.trigger in scn.events
        assert [e.id for e in scn.events] == [f"E{i:03d}" for i in range(1, len(scn.events) + 1)]
        assert [e.ts for e in scn.events] == sorted(e.ts for e in scn.events)
        assert any(e.role == "key" for e in scn.events), "a verdict needs evidence"
        assert scn.truth.required_actions and not set(scn.truth.required_actions) & set(scn.truth.harmful_actions)
        assert set(scn.truth.required_actions + scn.truth.harmful_actions) <= set(ACTIONS)
        for e in scn.events:
            assert e.summary and e.raw and e.source
            if e.role:
                assert e.note
        # every lookup the model answer relies on must actually return something
        for key in scn.truth.expected_lookups:
            kind, value = key.split(":", 1)
            assert lookup(scn, kind, value)["found"], f"{template}/{verdict}: {key} finds nothing"


def test_generation_is_deterministic():
    token = make_token(4242, "ps_encoded", 2)
    assert generate(token).public() == generate(token).public()
    assert generate(token).truth == generate(token).truth


def test_public_view_does_not_leak_the_answer():
    for template in REGISTRY:
        scn = generate(_find(template, 2, REGISTRY[template].variants[0]))
        blob = json.dumps(scn.public(), ensure_ascii=False)
        assert '"role"' not in blob and '"note"' not in blob
        assert scn.truth.summary not in blob and scn.truth.model_note not in blob
        for e in scn.events:
            if e.role:
                assert e.note not in blob


def test_shift_mix_is_mostly_benign():
    n = 600
    tp = sum(variant_for(s, "ps_encoded", "s") == "tp" for s in range(n))
    assert 0.05 < tp / n < 0.22


def test_lookup_normalisation():
    assert lookup_key("ti", "https://Evil.top/a/b?x=1") == "ti:evil.top"
    assert lookup_key("ti", "SHA256=" + "AB" * 32) == "ti:" + "ab" * 32
    assert lookup_key("asset", "WKS-KSG-001.nordwind.local") == "asset:wks-ksg-001"
    assert lookup_key("user", "NORDWIND\\JNowak") == "user:jnowak"
    assert lookup_key("user", "jnowak@nordwind.example") == "user:jnowak"


def test_unknown_lookup_is_an_answer_not_an_error():
    scn = generate(make_token(1, "ps_encoded", 1))
    res = lookup(scn, "ti", "never-seen.example")
    assert res["found"] is False and "nie oznacza" in res["message"]
    with pytest.raises(ValueError):
        lookup(scn, "bogus", "x")


def test_change_lookup_reports_whether_alert_is_inside_window():
    scn = generate(_find("ps_encoded", 1, "fp"))
    host = scn.alert.host
    res = lookup(scn, "change", host)
    assert res["found"]
    assert dict(res["records"][0])["Czas alertu w oknie"] == "TAK"


def test_perfect_answer_scores_full_marks():
    for template in REGISTRY:
        for verdict in REGISTRY[template].variants:
            scn = generate(_find(template, 2, verdict))
            result = scoring.evaluate(scn, _perfect(scn))
            assert result["score"] == 100 and result["outcome"] == "correct", (template, verdict, result)


def test_missing_a_true_positive_is_capped():
    scn = generate(_find("ps_encoded", 1, "tp"))
    sub = _perfect(scn) | {"verdict": "fp", "actions": ["close"]}
    result = scoring.evaluate(scn, sub)
    assert result["score"] <= scoring.MISSED_TP_CAP and "false_negative" in result["flags"]


def test_benign_vs_false_positive_is_a_partial():
    scn = generate(_find("ps_encoded", 1, "btp"))
    result = scoring.evaluate(scn, _perfect(scn) | {"verdict": "fp"})
    assert result["outcome"] == "partial" and result["breakdown"]["verdict"] == 30


def test_over_escalation_is_flagged_and_harmful_actions_cost_points():
    scn = generate(_find("ps_encoded", 1, "fp"))
    sub = _perfect(scn) | {"verdict": "tp", "actions": ["escalate_l2", "isolate_host"]}
    result = scoring.evaluate(scn, sub)
    assert "over_escalation" in result["flags"] and result["harmful_actions"]


def test_flagging_a_herring_costs_evidence_points_and_hints_cost_five_each():
    scn = generate(_find("ps_encoded", 1, "fp"))
    herring = next(e.id for e in scn.events if e.role == "herring")
    base = scoring.evaluate(scn, _perfect(scn))["score"]
    assert scoring.evaluate(scn, _perfect(scn) | {"evidence": [*_perfect(scn)["evidence"], herring]})["score"] < base
    assert scoring.evaluate(scn, _perfect(scn) | {"hints": 2})["score"] == base - 10


def test_close_with_tuning_satisfies_close():
    scn = generate(_find("ps_encoded", 1, "fp"))
    sub = _perfect(scn) | {"actions": ["close_tune"]}
    assert scoring.evaluate(scn, sub)["breakdown"]["actions"] == 15


def test_debrief_reveals_truth_and_lessons():
    scn = generate(_find("beaconing", 2, "tp"))
    d = scoring.debrief(scn, _perfect(scn))
    assert d["truth"]["verdict"] == "tp" and d["lessons"]["checklist"] and d["key_events"] and d["context"]["ti"]


# --- store ---------------------------------------------------------------------------------------------------------
def test_store_records_and_aggregates(tmp_path):
    store = TrainerStore(tmp_path / "t.db")
    scn = generate(_find("ps_encoded", 1, "tp"))
    for verdict in ("tp", "fp"):
        sub = _perfect(scn) | {"verdict": verdict}
        res = scoring.evaluate(scn, sub)
        store.record(token=scn.token + verdict, template=scn.template, category="Endpoint", difficulty=1, truth="tp", sub=sub, result=res)
    stats = store.stats({"ps_encoded": {"title": "PS", "category": "Endpoint"}})
    assert stats["attempts"] == 2 and stats["correct"] == 1
    assert stats["confusion"]["tp"] == {"tp": 1, "btp": 0, "fp": 1}
    assert stats["bias"]["missed_tp"] == 1
    assert store.attempted(scn.token + "tp") and not store.attempted("nope")


# --- server --------------------------------------------------------------------------------------------------------
@pytest.fixture()
def server(tmp_path):
    srv = make_server("127.0.0.1", 0, TrainerStore(tmp_path / "t.db"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _call(srv, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    hdrs = {"Host": f"localhost:{srv.server_address[1]}", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body)
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=hdrs)
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    return res.status, res.getheader("Content-Type"), raw, res


def test_server_serves_ui_under_strict_csp(server):
    status, ctype, body, res = _call(server, "GET", "/")
    assert status == 200 and ctype.startswith("text/html") and b"Trener SOC" in body
    assert "default-src 'none'" in res.getheader("Content-Security-Policy") and "unsafe-inline" not in res.getheader("Content-Security-Policy")
    assert _call(server, "GET", "/app.js")[0] == 200 and _call(server, "GET", "/style.css")[0] == 200
    assert _call(server, "GET", "/../pyproject.toml")[0] == 404


def test_server_rejects_foreign_host_and_origin(server):
    assert _call(server, "GET", "/api/meta", headers={"Host": "evil.example"})[0] == 403
    assert _call(server, "POST", "/api/new", {}, headers={"Origin": "http://evil.example"})[0] == 403
    assert _call(server, "POST", "/api/new", {}, headers={"Content-Type": "text/plain"})[0] == 415


def test_full_round_trip(server):
    status, _, body, _ = _call(server, "POST", "/api/new", {"difficulty": 2, "template": "beaconing"})
    scn = json.loads(body)
    assert status == 200 and scn["events"] and "truth" not in scn
    token = scn["token"]
    truth = generate(token).truth

    status, _, body, _ = _call(server, "POST", "/api/hint", {"token": token, "level": 1})
    assert status == 200 and json.loads(body)["hint"]
    assert _call(server, "POST", "/api/hint", {"token": token, "level": 4})[0] == 400

    kind, value = truth.expected_lookups[0].split(":", 1)
    status, _, body, _ = _call(server, "POST", "/api/lookup", {"token": token, "kind": kind, "value": value})
    assert status == 200 and json.loads(body)["found"]

    # a decision needs a reason
    assert _call(server, "POST", "/api/submit", {"token": token, "verdict": truth.verdict, "justification": "x"})[0] == 400
    assert _call(server, "POST", "/api/submit", {"token": token, "verdict": "maybe", "justification": "y" * 30})[0] == 400

    sub = {"token": token, "verdict": truth.verdict, "justification": "Wystarczająco długie uzasadnienie dla zmiany.", "actions": list(truth.required_actions)}
    status, _, body, _ = _call(server, "POST", "/api/submit", sub)
    first = json.loads(body)
    assert status == 200 and first["result"]["outcome"] == "correct" and first["repeat"] is False

    again = json.loads(_call(server, "POST", "/api/submit", sub)[2])
    assert again["repeat"] is True
    stats = json.loads(_call(server, "GET", "/api/stats")[2])
    assert stats["attempts"] == 1


def test_shift_contains_mostly_benign_alerts_and_at_least_one_tp(server):
    status, _, body, _ = _call(server, "POST", "/api/shift", {"n": 10})
    items = json.loads(body)["items"]
    assert status == 200 and len(items) == 10
    verdicts = [generate(i["token"]).truth.verdict for i in items]
    assert 1 <= verdicts.count("tp") <= 2 and "tp" not in [i.get("verdict") for i in items]
    assert _call(server, "POST", "/api/shift", {"n": 99})[0] == 400


def test_weak_mode_prefers_templates_the_analyst_fails(tmp_path):
    from hunterscope.trainer.server import TrainerApp

    store = TrainerStore(tmp_path / "t.db")
    app = TrainerApp(store)
    bad, good = "beaconing", "dns_tunnel"
    scn = generate(_find(bad, 1, "tp"))
    for template, verdict in ((bad, "fp"), (good, "tp")):
        sub = _perfect(scn) | {"verdict": verdict}
        res = scoring.evaluate(scn, sub) | {"score": 5 if template == bad else 100, "outcome": "wrong" if template == bad else "correct"}
        for i in range(6):
            store.record(token=f"{template}{i}", template=template, category="Sieć", difficulty=1, truth="tp", sub=sub, result=res)
    picks = [app._pick_template("Sieć", "", True) for _ in range(300)]
    assert picks.count(bad) > picks.count(good)


# --- cli -----------------------------------------------------------------------------------------------------------
def test_cli_export_hides_truth_unless_asked(tmp_path):
    token = _find("exfil", 1, "tp")
    runner = CliRunner()
    out = runner.invoke(app, ["train-export", token])
    assert out.exit_code == 0
    rows = [json.loads(line) for line in out.stdout.splitlines()]
    assert rows and all("role" not in r and "truth" not in r for r in rows)
    spoiled = runner.invoke(app, ["train-export", token, "--with-truth"])
    assert any(json.loads(line).get("truth") == "tp" for line in spoiled.stdout.splitlines())
    assert runner.invoke(app, ["train-export", "garbage"]).exit_code != 0
