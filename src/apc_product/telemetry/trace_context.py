from __future__ import annotations

import re
from dataclasses import dataclass

_TRACEPARENT = re.compile(r"^(?P<v>[0-9a-f]{2})-(?P<t>[0-9a-f]{32})-(?P<p>[0-9a-f]{16})-(?P<f>[0-9a-f]{2})$")


@dataclass(frozen=True)
class TraceContext:
    version: str
    trace_id: str
    parent_id: str
    flags: str


def parse_traceparent(value: str) -> TraceContext:
    m = _TRACEPARENT.fullmatch(value.strip().lower())
    if not m or m.group("t") == "0" * 32 or m.group("p") == "0" * 16:
        raise ValueError("invalid W3C traceparent")
    if m.group("v") == "ff":
        raise ValueError("reserved traceparent version")
    return TraceContext(m.group("v"), m.group("t"), m.group("p"), m.group("f"))
