from __future__ import annotations
from importlib import metadata
from typing import Any, Callable

ENTRYPOINT_GROUP = 'apc_y.integrations'


def discover_adapters(group: str = ENTRYPOINT_GROUP) -> list[Any]:
    """Discover third-party APC integration factories without changing APC core."""
    eps = metadata.entry_points()
    selected = eps.select(group=group) if hasattr(eps, 'select') else eps.get(group, ())
    adapters = []
    for ep in selected:
        factory = ep.load()
        adapter = factory() if callable(factory) else factory
        if not hasattr(adapter, 'manifest'):
            raise TypeError(f'integration entry point {ep.name!r} did not return an adapter')
        adapters.append(adapter)
    return adapters
