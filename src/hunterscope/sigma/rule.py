"""A small Sigma evaluator: compile a rule once into closures, then match flat event records.

Supported: value lists (OR), field maps (AND), lists of maps (OR); the modifiers contains, startswith, endswith,
all, re (+i, m, s), windash, cidr, base64, base64offset (+wide / utf16le), exists, lt/lte/gt/gte, null values;
wildcards `*` and `?` with Sigma's escaping; conditions with and / or / not, parentheses, `1 of` / `all of`
(`them` or a name pattern). Anything else (aggregations, keyword lists, fieldref, expand) is reported as
`Unsupported` so a rule is never silently half-evaluated.

String comparison is case-insensitive like Sigma's default; `re` is case-sensitive unless `|i`.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class Unsupported(Exception):
    """The rule uses a Sigma feature this engine does not implement."""


class Rec:
    """One event record, lower-cased once: `l` for case-insensitive matching, `o` for case-sensitive."""

    __slots__ = ("l", "o")

    def __init__(self, record: dict[str, Any]) -> None:
        low: dict[str, str] = {}
        orig: dict[str, str] = {}
        for key, value in record.items():
            if value is None:
                continue
            text = value if isinstance(value, str) else str(value)
            k = key.lower()
            orig[k] = text
            low[k] = text.lower()
        self.l = low
        self.o = orig


Matcher = Callable[[Rec], bool]

LEVELS = ("informational", "low", "medium", "high", "critical")
TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "defense_impairment", "credential_access", "discovery", "lateral_movement", "collection",
    "command_and_control", "exfiltration", "impact", "stealth",
}
_KNOWN_MODS = {
    "contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "cidr", "base64", "base64offset",
    "wide", "utf16le", "exists", "lt", "lte", "gt", "gte",
}
_DASHES = "[-/–—―]"


# ----------------------------------------------------------------------------- string values


def _parse_string(value: str, mode: str, windash: bool) -> tuple[str, str]:
    """Sigma string -> ("lit", literal text) or ("rx", regex source) with the mode's anchors applied."""
    out: list[str] = []
    literal: list[str] = []
    wild = False
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == "\\" and i + 1 < n and value[i + 1] in "*?":
            out.append(re.escape(value[i + 1]))
            literal.append(value[i + 1])
            i += 2
        elif c == "\\" and i + 2 < n and value[i + 1] == "\\" and value[i + 2] in "*?":
            out.append(re.escape("\\"))  # `\\*` is a literal backslash followed by a live wildcard
            literal.append("\\")
            i += 2
        elif c == "*":
            out.append(".*")
            wild = True
            i += 1
        elif c == "?":
            out.append(".")
            wild = True
            i += 1
        elif windash and c == "-" and (i == 0 or value[i - 1] == " "):
            out.append(_DASHES)
            wild = True
            literal.append(c)
            i += 1
        else:
            out.append(re.escape(c))
            literal.append(c)
            i += 1
    if not wild:
        return "lit", "".join(literal)
    body = "".join(out)
    anchors = {"equals": (r"\A", r"\Z"), "startswith": (r"\A", ""), "endswith": ("", r"\Z"), "contains": ("", "")}
    head, tail = anchors[mode]
    return "rx", f"{head}{body}{tail}"


def _b64_variants(raw: bytes, offset: bool) -> list[str]:
    if not offset:
        return [base64.b64encode(raw).decode("ascii")]
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(b" " * i + raw).decode("ascii")
        out.append(enc[start[i] : end[(len(raw) + i) % 3]])
    return out


def _numeric(op: str, values: list[Any], field_name: str, all_: bool) -> Matcher:
    compare = {"lt": lambda a, b: a < b, "lte": lambda a, b: a <= b, "gt": lambda a, b: a > b,
               "gte": lambda a, b: a >= b}[op]
    limits = [float(v) for v in values]

    def match(rec: Rec) -> bool:
        raw = rec.o.get(field_name)
        if raw is None:
            return False
        try:
            x = float(raw)
        except ValueError:
            return False
        hits = (compare(x, lim) for lim in limits)
        return all(hits) if all_ else any(hits)

    return match


def compile_field(spec: str, raw_values: Any) -> Matcher:
    name, *mods = spec.split("|")
    field_name = name.lower()
    unknown = [m for m in mods if m not in _KNOWN_MODS]
    if unknown:
        raise Unsupported(f"modifier {unknown[0]}")
    values = raw_values if isinstance(raw_values, list) else [raw_values]
    all_ = "all" in mods

    if "exists" in mods:
        want = bool(values[0])
        return lambda rec: (field_name in rec.l) == want

    has_null = any(v is None for v in values)
    values = [v for v in values if v is not None]
    base: Matcher | None = _compile_values(field_name, mods, values, all_) if values else None

    if not has_null:
        assert base is not None
        return base

    def empty(rec: Rec) -> bool:
        return not rec.o.get(field_name)

    if base is None:
        return empty
    return lambda rec: empty(rec) or base(rec)


def _compile_values(field_name: str, mods: list[str], values: list[Any], all_: bool) -> Matcher:
    for op in ("lt", "lte", "gt", "gte"):
        if op in mods:
            return _numeric(op, values, field_name, all_)

    if "cidr" in mods:
        nets = [ipaddress.ip_network(str(v), strict=False) for v in values]

        def cidr(rec: Rec) -> bool:
            raw = rec.o.get(field_name)
            if raw is None:
                return False
            try:
                addr = ipaddress.ip_address(raw.strip())
            except ValueError:
                return False
            hits = (addr in n for n in nets if n.version == addr.version)
            return all(hits) if all_ else any(hits)

        return cidr

    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        try:
            patterns = [re.compile(str(v), flags) for v in values]
        except re.error as exc:
            raise Unsupported(f"regex does not compile: {exc}") from exc

        def regex(rec: Rec) -> bool:
            raw = rec.o.get(field_name)
            if raw is None:
                return False
            hits = (p.search(raw) for p in patterns)
            return all(hits) if all_ else any(hits)

        return regex

    mode = "contains" if "contains" in mods else "startswith" if "startswith" in mods else \
        "endswith" if "endswith" in mods else "equals"
    windash = "windash" in mods
    b64 = "base64" in mods or "base64offset" in mods
    if ("wide" in mods or "utf16le" in mods) and not b64:
        raise Unsupported("wide/utf16le without base64")

    texts: list[str] = []
    if b64:
        for v in values:
            raw = str(v).encode("utf-16-le" if ("wide" in mods or "utf16le" in mods) else "utf-8")
            texts.extend(_b64_variants(raw, "base64offset" in mods))
    else:
        texts = [str(v) if not isinstance(v, bool) else str(v).lower() for v in values]

    case_sensitive = b64
    literals: list[str] = []
    regexes: list[re.Pattern[str]] = []
    for text in texts:
        if b64:
            literals.append(text)
            continue
        kind, body = _parse_string(text, mode, windash)
        if kind == "lit":
            literals.append(body.lower())
        else:
            regexes.append(re.compile(body, re.I | re.S))

    lit_tuple = tuple(literals)
    lit_set = frozenset(literals)

    def one_literal(v: str, p: str) -> bool:
        return (p in v) if mode == "contains" else v.startswith(p) if mode == "startswith" else \
            v.endswith(p) if mode == "endswith" else v == p

    def any_match(v: str) -> bool:
        if lit_tuple:
            if mode == "contains":
                if any(p in v for p in lit_tuple):
                    return True
            elif mode == "startswith":
                if v.startswith(lit_tuple):
                    return True
            elif mode == "endswith":
                if v.endswith(lit_tuple):
                    return True
            elif v in lit_set:
                return True
        return any(rx.search(v) for rx in regexes)

    def all_match(v: str) -> bool:
        return all(one_literal(v, p) for p in literals) and all(rx.search(v) for rx in regexes)

    check = all_match if all_ else any_match

    def match(rec: Rec) -> bool:
        v = (rec.o if case_sensitive else rec.l).get(field_name)
        return v is not None and check(v)

    return match


# ---------------------------------------------------------------------------------- selections


def compile_selection(value: Any) -> Matcher:
    if isinstance(value, dict):
        if not value:
            raise Unsupported("empty selection")
        parts = [compile_field(k, v) for k, v in value.items()]
        return lambda rec: all(p(rec) for p in parts)
    if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
        alts = [compile_selection(x) for x in value]
        return lambda rec: any(a(rec) for a in alts)
    raise Unsupported("keyword selection")


# ---------------------------------------------------------------------------------- conditions


def compile_condition(condition: str, selections: dict[str, Matcher]) -> Matcher:
    if "|" in condition:
        raise Unsupported("aggregation")
    tokens = re.findall(r"\(|\)|[^\s()]+", condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise Unsupported("condition ended unexpectedly")
        pos += 1
        return tokens[pos - 1]

    def names(pattern: str) -> list[Matcher]:
        if pattern.lower() == "them":
            found = list(selections.values())
        else:
            found = [m for n, m in selections.items() if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise Unsupported(f"no selection matches '{pattern}'")
        return found

    def atom() -> Matcher:
        tok = take()
        low = tok.lower()
        if tok == "(":
            inner = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return inner
        if low == "not":
            inner = atom()
            return lambda rec: not inner(rec)
        if low in {"1", "all", "any"} and peek() == "of":
            take()
            group = names(take())
            if low == "all":
                return lambda rec: all(m(rec) for m in group)
            return lambda rec: any(m(rec) for m in group)
        if tok not in selections:
            raise Unsupported(f"unknown selection '{tok}'")
        return selections[tok]

    def conj() -> Matcher:
        parts = [atom()]
        while peek() == "and":
            take()
            parts.append(atom())
        return parts[0] if len(parts) == 1 else (lambda rec: all(p(rec) for p in parts))

    def expr() -> Matcher:
        parts = [conj()]
        while peek() == "or":
            take()
            parts.append(conj())
        return parts[0] if len(parts) == 1 else (lambda rec: any(p(rec) for p in parts))

    result = expr()
    if pos != len(tokens):
        raise Unsupported(f"unexpected token '{tokens[pos]}'")
    return result


# ------------------------------------------------------------------------------------- rules


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    description: str
    tags: list[str]
    logsource: dict[str, str]
    path: str = ""
    match: Matcher | None = None
    unsupported: str | None = None
    techniques: list[str] = field(default_factory=list)  # T1003.001
    tactics: list[str] = field(default_factory=list)     # credential-access

    @property
    def families(self) -> set[str]:
        return {t.split(".")[0] for t in self.techniques}

    @property
    def category(self) -> str | None:
        return self.logsource.get("category")

    @property
    def service(self) -> str | None:
        return self.logsource.get("service")


_TECH = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$")


def _tags(tags: list[str]) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for tag in tags:
        low = str(tag).lower()
        m = _TECH.match(low)
        if m:
            techniques.append(m.group(1).upper() + (f".{m.group(2)}" if m.group(2) else ""))
        elif low.startswith("attack.") and low[7:] in TACTICS:
            tactics.append(low[7:].replace("_", "-"))
    return techniques, tactics


def parse_rule(doc: dict[str, Any], path: str = "") -> SigmaRule:
    tags = [str(t) for t in doc.get("tags") or []]
    techniques, tactics = _tags(tags)
    logsource = {str(k): str(v).lower() for k, v in (doc.get("logsource") or {}).items()}
    rule = SigmaRule(
        id=str(doc.get("id", "")), title=str(doc.get("title", "")), level=str(doc.get("level", "")).lower(),
        status=str(doc.get("status", "")).lower(), description=str(doc.get("description", "")).strip(),
        tags=tags, logsource=logsource, path=path, techniques=techniques, tactics=tactics,
    )
    try:
        detection = doc["detection"]
        selections = {k: compile_selection(v) for k, v in detection.items() if k not in {"condition", "timeframe"}}
        cond = detection["condition"]
        conditions = cond if isinstance(cond, list) else [cond]
        compiled = [compile_condition(str(c), selections) for c in conditions]
        rule.match = compiled[0] if len(compiled) == 1 else (lambda rec: any(c(rec) for c in compiled))
    except Unsupported as exc:
        rule.unsupported = str(exc)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        rule.unsupported = f"malformed: {type(exc).__name__} {exc}"
    return rule
