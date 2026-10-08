"""Normalized event model shared by every ingest source and detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Source = Literal["entra", "ual", "windows", "email"]
Outcome = Literal["success", "failure", "unknown"]


class Event(BaseModel):
    ts: datetime
    source: Source
    action: str
    outcome: Outcome = "unknown"
    user: str | None = None
    host: str | None = None
    ip: str | None = None
    app: str | None = None
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    error_code: int | None = None
    command_line: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _to_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


def user_key(user: str | None) -> str:
    """Canonical identity: `CONTOSO\\JKowalski` and `jkowalski@contoso.com` -> `jkowalski`.

    Deliberately ignores the domain part; two users with the same local part in
    different domains are merged. Acceptable for single-tenant triage.
    """
    if not user:
        return ""
    return user.lower().split("\\")[-1].split("@")[0].strip()


def host_key(host: str | None) -> str:
    """`SRV-DB01.contoso.com` -> `srv-db01`."""
    return (host or "").lower().split(".")[0].strip()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    tactic: str
    mitre: list[str]
    weight: float
    description: str
    evidence: list[Event]
    iocs: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ts(self) -> datetime:
        return min(e.ts for e in self.evidence)
