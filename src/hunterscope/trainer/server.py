"""Local web server for the trainer: static single-page UI + a small JSON API. Standard library only.

Binds to localhost, rejects foreign Host/Origin headers (DNS rebinding), and serves the UI under a strict CSP,
because everything in a scenario's logs is untrusted text.
"""

from __future__ import annotations

import json
import random
import re
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from hunterscope.trainer import lookups, scoring
from hunterscope.trainer.model import ACTIONS, LOOKUP_KINDS, TZ_LABEL, VERDICTS
from hunterscope.trainer.scenarios import MIX, generate, make_token, parse_token, templates, variant_for
from hunterscope.trainer.scenarios.base import REGISTRY
from hunterscope.trainer.sources import SOURCES
from hunterscope.trainer.store import TrainerStore

STATIC = Path(__file__).parent / "static"
STATIC_FILES = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/style.css": "style.css"}
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 64 * 1024
LOCAL_HOST = re.compile(r"^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$")
SHIFT_DIFFICULTY = [1, 1, 2, 2, 2, 3]


class ApiError(Exception):
    def __init__(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


class TrainerApp:
    def __init__(self, store: TrainerStore):
        self.store = store
        self.rng = random.SystemRandom()

    # --- scenario selection ----------------------------------------------------------------------------------
    def _pick_template(self, category: str, template: str, weak: bool) -> str:
        if template:
            if template not in REGISTRY:
                raise ApiError("unknown template")
            return template
        pool = [t["id"] for t in templates() if not category or t["category"] == category]
        if not pool:
            raise ApiError("unknown category")
        if not weak:
            return self.rng.choice(pool)
        per = self.store.per_template()
        weights = []
        for tid in pool:
            p = per.get(tid)
            if not p:
                weights.append(0.5)
            else:
                acc = (p["points"] + 60) / (100 * p["n"] + 100)
                weights.append((1.05 - acc) ** 2 + 0.05)
        return self.rng.choices(pool, weights)[0]

    def new_token(self, difficulty: int, category: str, template: str, weak: bool) -> str:
        if difficulty not in (0, 1, 2, 3):
            raise ApiError("difficulty must be 0-3")
        tid = self._pick_template(category, template, weak)
        d = difficulty or self.rng.choice([1, 2, 2, 3])
        return make_token(self.rng.randrange(10**9), tid, d, "p")

    def new_shift(self, n: int, difficulty: int) -> dict:
        if not 3 <= n <= 14:
            raise ApiError("n must be 3-14")
        n_tp = self.rng.choice([1, 1, 2])
        wanted = ["tp"] * n_tp + [self.rng.choices(["fp", "btp"], [3, 1])[0] for _ in range(n - n_tp)]
        self.rng.shuffle(wanted)
        used: list[str] = []
        items = []
        for want in wanted:
            candidates = [t for t in REGISTRY.values() if want in t.variants and t.id not in used] or [t for t in REGISTRY.values() if want in t.variants]
            tpl = self.rng.choice(candidates)
            used.append(tpl.id)
            d = difficulty or self.rng.choice(SHIFT_DIFFICULTY)
            token = ""
            for _ in range(500):
                seed = self.rng.randrange(10**9)
                if variant_for(seed, tpl.id, "s") == want:
                    token = make_token(seed, tpl.id, d, "s")
                    break
            token = token or make_token(self.rng.randrange(10**9), tpl.id, d, "s")
            a = generate(token).alert
            items.append({"token": token, "rule": a.rule, "severity": a.severity, "source": a.source, "host": a.host or a.user})
        return {"shift_id": secrets.token_hex(4), "items": items}

    # --- requests --------------------------------------------------------------------------------------------
    def meta(self) -> dict:
        cats = sorted({t["category"] for t in templates()})
        return {"templates": templates(), "categories": cats, "actions": ACTIONS, "verdicts": VERDICTS, "tz": TZ_LABEL, "sources": SOURCES,
                "mix": {k: v for k, v in MIX.items()}}

    def scenario(self, token: str):
        try:
            parse_token(token)
        except ValueError as exc:
            raise ApiError(str(exc)) from None
        return generate(token)

    def do_lookup(self, body: dict) -> dict:
        scn = self.scenario(str(body.get("token", "")))
        kind, value = str(body.get("kind", "")), str(body.get("value", ""))
        if kind not in LOOKUP_KINDS or not value.strip():
            raise ApiError("kind and value are required")
        return lookups.lookup(scn, kind, value)

    def hint(self, body: dict) -> dict:
        scn = self.scenario(str(body.get("token", "")))
        level = int(body.get("level", 0))
        if level not in (1, 2, 3):
            raise ApiError("level must be 1-3")
        return {"level": level, "hint": scn.lessons.hints[level - 1]}

    def submit(self, body: dict) -> dict:
        scn = self.scenario(str(body.get("token", "")))
        verdict = body.get("verdict")
        if verdict not in VERDICTS:
            raise ApiError("verdict must be one of tp, btp, fp")
        just = str(body.get("justification", "")).strip()
        if len(just) < 20:
            raise ApiError("uzasadnienie jest wymagane (min. 20 znaków): kolejna zmiana potrzebuje go bardziej niż dashboard")
        sub = {
            "verdict": verdict,
            "actions": [a for a in body.get("actions", []) if isinstance(a, str)][:12],
            "evidence": [e for e in body.get("evidence", []) if isinstance(e, str)][:60],
            "lookups": [k for k in body.get("lookups", []) if isinstance(k, str)][:60],
            "hints": int(body.get("hints", 0)),
            "seconds": max(0, min(int(body.get("seconds", 0)), 86400)),
            "justification": just[:4000],
        }
        result = scoring.debrief(scn, sub)
        repeat = self.store.attempted(scn.token)
        if not repeat:
            self.store.record(token=scn.token, template=scn.template, category=scn.lessons.category, difficulty=scn.difficulty,
                              truth=scn.truth.verdict, sub=sub, result=result["result"], shift_id=body.get("shift_id"))
        result["repeat"] = repeat
        return result

    def stats(self) -> dict:
        return self.store.stats({t["id"]: t for t in templates()})


def make_handler(app: TrainerApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HunterScopeTrainer"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quiet: the console is for the analyst
            pass

        # --- plumbing ----------------------------------------------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload, status: int = 200) -> None:
            if status >= 400:
                self.close_connection = True  # an unread request body would otherwise be parsed as the next request
            self._send(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _guard(self) -> bool:
            if not LOCAL_HOST.match(self.headers.get("Host", "")):
                self._json({"error": "forbidden host"}, 403)
                return False
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                self._json({"error": "forbidden origin"}, 403)
                return False
            return True

        def _body(self) -> dict:
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                raise ApiError("content-type must be application/json", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ApiError("body too large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                raise ApiError("invalid JSON") from None
            if not isinstance(data, dict):
                raise ApiError("JSON object expected")
            return data

        # --- routes ------------------------------------------------------------------------------------------
        def do_GET(self):
            if not self._guard():
                return
            url = urlparse(self.path)
            try:
                if url.path in STATIC_FILES:
                    f = STATIC / STATIC_FILES[url.path]
                    self._send(200, f.read_bytes(), TYPES[f.suffix])
                elif url.path == "/favicon.ico":
                    self._send(204, b"", "image/x-icon")
                elif url.path == "/api/meta":
                    self._json(app.meta())
                elif url.path == "/api/stats":
                    self._json(app.stats())
                elif url.path == "/api/scenario":
                    token = parse_qs(url.query).get("token", [""])[0]
                    self._json(app.scenario(token).public())
                else:
                    self._json({"error": "not found"}, 404)
            except ApiError as exc:
                self._json({"error": str(exc)}, exc.status)

        def do_POST(self):
            if not self._guard():
                return
            routes = {"/api/new": self._new, "/api/shift": self._shift, "/api/lookup": lambda b: app.do_lookup(b),
                      "/api/hint": lambda b: app.hint(b), "/api/submit": lambda b: app.submit(b)}
            try:
                handler = routes.get(urlparse(self.path).path)
                if handler is None:
                    raise ApiError("not found", HTTPStatus.NOT_FOUND)
                self._json(handler(self._body()))
            except ApiError as exc:
                self._json({"error": str(exc)}, exc.status)
            except (ValueError, TypeError) as exc:
                self._json({"error": f"bad request: {exc}"}, 400)

        def _new(self, body: dict) -> dict:
            token = app.new_token(int(body.get("difficulty", 0)), str(body.get("category", "")), str(body.get("template", "")),
                                  bool(body.get("weak", False)))
            return app.scenario(token).public()

        def _shift(self, body: dict) -> dict:
            return app.new_shift(int(body.get("n", 8)), int(body.get("difficulty", 0)))

    return Handler


def make_server(host: str, port: int, store: TrainerStore) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(TrainerApp(store)))
