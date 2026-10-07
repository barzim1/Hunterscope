"""RFC 5322 .eml -> Event(s), one per recipient. Extracts what phishing triage needs."""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path

from hunterscope.models import Event
from hunterscope.netutil import is_internal

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_AUTH_RE = {k: re.compile(rf"\b{k}=(\w+)", re.IGNORECASE) for k in ("spf", "dkim", "dmarc")}
_RECEIVED_IP = re.compile(r"[\[(](\d{1,3}(?:\.\d{1,3}){3})[\])]")
_MAX_RECIPIENTS = 50


class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _auth_results(msg: EmailMessage) -> dict[str, str | None]:
    blob = " ".join(str(h) for h in msg.get_all("Authentication-Results") or [])
    out: dict[str, str | None] = {}
    for key, rx in _AUTH_RE.items():
        m = rx.search(blob)
        out[key] = m.group(1).lower() if m else None
    if out["spf"] is None:
        received_spf = str(msg.get("Received-SPF") or "").split()
        out["spf"] = received_spf[0].lower() if received_spf else None
    return out


def _origin_ip(msg: EmailMessage) -> str | None:
    """Bottom-most Received hop with a non-internal IPv4 address."""
    for hop in reversed(msg.get_all("Received") or []):
        for ip in _RECEIVED_IP.findall(str(hop)):
            if not is_internal(ip):
                return ip
    return None


def _sender(msg: EmailMessage, header: str) -> tuple[str, str]:
    """(display_name, addr_spec) of the first address in a header, '' if absent."""
    addrs = getaddresses([str(v) for v in msg.get_all(header) or []])
    return addrs[0] if addrs else ("", "")


def parse_eml(path: Path) -> list[Event]:
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    if not isinstance(msg, EmailMessage):
        raise ValueError("not an email message")
    if not msg.get("Date") or not msg.get("From"):
        raise ValueError("missing Date or From header")

    from_name, from_addr = _sender(msg, "From")
    _, reply_to = _sender(msg, "Reply-To")
    _, return_path = _sender(msg, "Return-Path")

    links: list[tuple[str, str]] = []
    plain_urls: list[str] = []
    attachments: list[dict[str, object]] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename:
            data = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename, "content_type": ctype,
                "size": len(data), "sha256": sha256(data).hexdigest(),
            })
        elif ctype in {"text/plain", "text/html"}:
            try:
                body = part.get_content()
            except (LookupError, UnicodeDecodeError):
                continue
            if ctype == "text/html":
                parser = _Anchors()
                parser.feed(body)
                links.extend(parser.links)
            else:
                plain_urls.extend(u.rstrip(".,;)") for u in _URL_RE.findall(body))

    seen: set[str] = set()
    urls: list[dict[str, str]] = []
    for href, text in [*links, *((u, "") for u in plain_urls)]:
        if href.lower().startswith(("http://", "https://")) and href not in seen:
            seen.add(href)
            urls.append({"href": href, "text": text})

    detail = {
        "message_id": str(msg.get("Message-ID") or ""),
        "subject": str(msg.get("Subject") or ""),
        "from_name": from_name,
        "from_addr": from_addr.lower(),
        "reply_to": reply_to.lower(),
        "return_path": return_path.lower(),
        **_auth_results(msg),
        "urls": urls,
        "attachments": attachments,
    }
    recipients = {
        addr.lower()
        for _, addr in getaddresses([str(v) for h in ("To", "Cc") for v in msg.get_all(h) or []])
        if addr
    }
    if not recipients:
        raise ValueError("no recipients")
    when = parsedate_to_datetime(str(msg["Date"]))
    origin = _origin_ip(msg)
    return [
        Event(ts=when, source="email", action="email_received", outcome="success",
              user=rcpt, ip=origin, detail=detail)
        for rcpt in sorted(recipients)[:_MAX_RECIPIENTS]
    ]
