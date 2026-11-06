"""Explicit allow-list projection. Unknown fields are dropped, never forwarded."""

from typing import Any


class ProjectionError(ValueError):
    pass


def project(
    source: dict[str, Any],
    allowed_fields: list[str] | tuple[str, ...],
    *,
    required_fields: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    allowed = set(allowed_fields)
    required = set(required_fields)
    missing = required - source.keys()
    if missing:
        raise ProjectionError("missing required projection fields: " + ", ".join(sorted(missing)))
    return {k: source[k] for k in sorted(allowed) if k in source}
