"""Scoring and debrief. 100 points: verdict 50, actions 15, evidence 20, investigation 15; hints cost 5 each."""

from __future__ import annotations

from dataclasses import asdict

from hunterscope.trainer.lookups import lookup_key
from hunterscope.trainer.model import ACTIONS, VERDICTS, Scenario

# (truth, answer) -> points. Calling a benign case a false positive (or the reverse) is a small slip, because
# both close the ticket; missing a real incident is worth nothing.
VERDICT_POINTS = {
    ("tp", "tp"): 50, ("tp", "btp"): 0, ("tp", "fp"): 0,
    ("btp", "btp"): 50, ("btp", "fp"): 30, ("btp", "tp"): 15,
    ("fp", "fp"): 50, ("fp", "btp"): 30, ("fp", "tp"): 10,
}
HINT_COST = 5
MISSED_TP_CAP = 30


def _grade(score: int) -> str:
    return "Bardzo dobrze" if score >= 85 else "Dobrze" if score >= 65 else "Do poprawy" if score >= 45 else "Słabo"


def _action_points(truth, chosen: set[str]) -> tuple[float, list[str], list[str]]:
    satisfied = set(chosen)
    if "close_tune" in chosen:
        satisfied.add("close")  # tuning request implies closing
    required = set(truth.required_actions)
    missing = sorted(required - satisfied)
    harmful = sorted(set(truth.harmful_actions) & chosen)
    points = 15.0 * (len(required) - len(missing)) / max(len(required), 1) - 4.0 * len(harmful)
    return max(points, 0.0), missing, harmful


def evaluate(scn: Scenario, sub: dict) -> dict:
    truth = scn.truth
    verdict = sub["verdict"]
    chosen = {a for a in sub.get("actions", []) if a in ACTIONS}
    marked = set(sub.get("evidence", []))
    hints = max(0, min(int(sub.get("hints", 0)), 3))

    v_pts = VERDICT_POINTS[(truth.verdict, verdict)]
    a_pts, missing, harmful = _action_points(truth, chosen)

    key_ids = {e.id for e in scn.events if e.role == "key"}
    herring_ids = {e.id for e in scn.events if e.role == "herring"}
    found = key_ids & marked
    flagged = herring_ids & marked
    e_pts = max(20.0 * len(found) / max(len(key_ids), 1) - 4.0 * len(flagged), 0.0)

    done = {lookup_key(*k.split(":", 1)) for k in sub.get("lookups", []) if ":" in k}
    expected = {lookup_key(*k.split(":", 1)): k for k in truth.expected_lookups}
    hit = sorted(expected[k] for k in expected if k in done)
    miss = sorted(expected[k] for k in expected if k not in done)
    i_pts = 15.0 * len(hit) / len(expected) if expected else 15.0

    raw = v_pts + a_pts + e_pts + i_pts - HINT_COST * hints
    total = int(round(max(raw, 0)))
    flags = []
    if truth.verdict == "tp" and verdict != "tp":
        total = min(total, MISSED_TP_CAP)
        flags.append("false_negative")
    if truth.verdict != "tp" and verdict == "tp":
        flags.append("over_escalation")
    outcome = "correct" if verdict == truth.verdict else "partial" if v_pts >= 30 else "wrong"
    return {
        "outcome": outcome,
        "score": total,
        "grade": _grade(total),
        "flags": flags,
        "breakdown": {"verdict": v_pts, "actions": round(a_pts, 1), "evidence": round(e_pts, 1), "investigation": round(i_pts, 1),
                      "hints": -HINT_COST * hints},
        "missing_actions": missing,
        "harmful_actions": harmful,
        "found_keys": sorted(found),
        "flagged_herrings": sorted(flagged),
        "lookups_hit": hit,
        "lookups_missed": miss,
    }


def debrief(scn: Scenario, sub: dict) -> dict:
    result = evaluate(scn, sub)
    truth = scn.truth
    found, flagged = set(result["found_keys"]), set(result["flagged_herrings"])
    return {
        "token": scn.token,
        "template": scn.lessons.title,
        "category": scn.lessons.category,
        "difficulty": scn.difficulty,
        "truth": {"verdict": truth.verdict, "verdict_label": VERDICTS[truth.verdict], "severity": truth.severity, "summary": truth.summary,
                  "model_note": truth.model_note},
        "your": {"verdict": sub["verdict"], "verdict_label": VERDICTS[sub["verdict"]], "actions": sub.get("actions", []),
                 "justification": sub.get("justification", "")},
        "result": result,
        "actions": {
            "required": [{"id": a, "label": ACTIONS[a]} for a in truth.required_actions],
            "harmful": [{"id": a, "label": ACTIONS[a]} for a in truth.harmful_actions],
            "labels": ACTIONS,
        },
        "key_events": [{"id": e.id, "summary": e.summary, "note": e.note, "found": e.id in found} for e in scn.events if e.role == "key"],
        "herrings": [{"id": e.id, "summary": e.summary, "note": e.note, "flagged": e.id in flagged} for e in scn.events if e.role == "herring"],
        "lessons": asdict(scn.lessons),
        "context": {
            "assets": scn.context.assets, "users": scn.context.users, "changes": scn.context.changes, "ti": scn.context.ti,
        },
    }
