from datetime import datetime, timezone

from hunterscope.models import Event


def ts(day: int, hh: int, mm: int, ss: int = 0) -> datetime:
    return datetime(2026, 3, day, hh, mm, ss, tzinfo=timezone.utc)


def signin(when, ok=True, code=None, ip="203.0.113.9", user="u@contoso.com", loc=None):
    city, country, lat, lon = loc or (None, None, None, None)
    return Event(
        ts=when, source="entra", action="signin", outcome="success" if ok else "failure",
        user=user, ip=ip, error_code=0 if ok else (code or 50126),
        city=city, country=country, lat=lat, lon=lon,
    )


def cmd(when, line, host="ws1.contoso.com"):
    return Event(ts=when, source="windows", action="process_create", outcome="success",
                 host=host, user="CONTOSO\\u", command_line=line, app="x.exe")


def ual(when, op, ip="203.0.113.9", **params):
    return Event(ts=when, source="ual", action=op, outcome="success", user="u@contoso.com",
                 ip=ip, detail={"params": params})
