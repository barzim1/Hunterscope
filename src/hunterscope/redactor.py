"""Deterministic pseudonymization for safe export (tickets, external sharing).

One regex pass over the text so replacements never cascade. Consistent labels
(USER_A, IP_1) keep relationships readable. With a key, labels become stable
across runs (HMAC-SHA256) and cannot be reversed by brute-forcing small value
spaces such as IPv4 addresses or PESEL numbers.
"""

from __future__ import annotations

import hmac
import re
from collections import defaultdict
from hashlib import sha256
from typing import Any

from hunterscope.netutil import is_internal

_PREFIX = {
    "user": "USER",
    "host": "HOST",
    "ip": "IP",
    "internal_ip": "INTERNAL_IP",
    "pesel": "PII_ID",
    "ext_email": "EXT_EMAIL",
    "domain": "INTERNAL_DOMAIN",
}
_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
_IPV4 = r"\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}"


def valid_pesel(value: str) -> bool:
    if len(value) != 11 or not value.isdigit():
        return False
    digits = [int(c) for c in value]
    checksum = (10 - sum(d * w for d, w in zip(digits[:10], _PESEL_WEIGHTS, strict=True)) % 10) % 10
    return checksum == digits[10]


def _letters(n: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    out = ""
    while n:
        n, rem = divmod(n - 1, 26)
        out = chr(65 + rem) + out
    return out


class Redactor:
    def __init__(
        self,
        cfg: dict[str, Any],
        key: bytes | None = None,
        known_users: list[str] | None = None,
        known_hosts: list[str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.key = key
        self._maps: dict[str, dict[str, str]] = defaultdict(dict)
        self._originals: dict[str, str] = {}
        self._nets: list[str] = cfg["internal_networks"]
        self._domains = [d.lower() for d in cfg["internal_domains"]]
        self._extra = cfg.get("extra_patterns", [])
        self._regex = self._build(known_users or [], known_hosts or [])

    def _build(self, users: list[str], hosts: list[str]) -> re.Pattern[str]:
        parts = [r"(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"]
        if self.cfg.get("netbios_domains"):
            nb = "|".join(re.escape(d) for d in self.cfg["netbios_domains"])
            parts.append(rf"(?P<ntuser>\b(?:{nb})\\[A-Za-z0-9._\-$]+)")
        parts.append(r"(?P<pesel>(?<!\d)\d{11}(?!\d))")
        parts.append(rf"(?P<ip>(?<![\d.])(?:{_IPV4})(?!\d|\.\d))")
        dom_alt = "|".join(re.escape(d) for d in sorted(self._domains, key=len, reverse=True))
        if hosts:
            host_alt = "|".join(re.escape(h) for h in sorted(hosts, key=len, reverse=True))
            suffix = rf"(?:\.(?:[\w-]+\.)*(?:{dom_alt}))?" if dom_alt else ""
            parts.append(rf"(?P<host>(?<![\w-])(?:{host_alt}){suffix}(?![\w-]))")
        if dom_alt:
            parts.append(rf"(?P<domain>(?<![\w-])(?:[\w-]+\.)*(?:{dom_alt})(?![\w-]))")
        if users:
            user_alt = "|".join(re.escape(u) for u in sorted(users, key=len, reverse=True))
            parts.append(rf"(?P<user>(?<![A-Za-z0-9])(?:{user_alt})(?![A-Za-z0-9]))")
        for i, pat in enumerate(self._extra):
            parts.append(f"(?P<x{i}>{pat['regex']})")
        return re.compile("|".join(parts), re.IGNORECASE)

    def _label(self, kind: str, value: str, prefix: str | None = None) -> str:
        norm = value.lower()
        known = self._maps[kind]
        if norm not in known:
            prefix = prefix or _PREFIX[kind]
            if self.key:
                tag = hmac.new(self.key, f"{kind}:{norm}".encode(), sha256).hexdigest()[:6].upper()
                known[norm] = f"{prefix}_{tag}"
            else:
                n = len(known) + 1
                known[norm] = f"{prefix}_{_letters(n) if kind == 'user' else n}"
            self._originals[known[norm]] = value
        return known[norm]

    def _replace(self, m: re.Match[str]) -> str:
        text, kind = m.group(0), m.lastgroup or ""
        if kind == "email":
            local, _, domain = text.rpartition("@")
            dom = domain.lower()
            if any(dom == d or dom.endswith("." + d) for d in self._domains):
                return f"{self._label('user', local)}@{_PREFIX['domain']}"
            if self.cfg.get("keep_external_emails"):
                return text
            return self._label("ext_email", text)
        if kind == "ntuser":
            return self._label("user", text.split("\\", 1)[1])
        if kind == "pesel":
            return self._label("pesel", text) if valid_pesel(text) else text
        if kind == "ip":
            ip = text.replace("[.]", ".")
            if any(int(o) > 255 for o in ip.split(".")):
                return text
            if is_internal(ip, self._nets):
                return self._label("internal_ip", ip)
            return text if self.cfg.get("keep_public_ips") else self._label("ip", ip)
        if kind == "host":
            return self._label("host", text.split(".")[0])
        if kind == "domain":
            if text.lower() in self._domains:
                return self._label("domain", text)
            return self._label("host", text.split(".")[0])  # FQDN: keep host identity
        if kind == "user":
            return self._label("user", text)
        if kind.startswith("x"):
            pat = self._extra[int(kind[1:])]
            return self._label("custom_" + pat["name"], text, prefix=pat["label"])
        return text

    def redact(self, text: str) -> str:
        return self._regex.sub(self._replace, text)

    def mapping(self) -> dict[str, str]:
        """label -> original value. Contains the sensitive data: keep it out of tickets."""
        return dict(sorted(self._originals.items()))
