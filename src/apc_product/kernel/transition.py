from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class TransitionStep:
    transition_id: str
    parent_transition_id: str | None
    action_chain_id: str
    counter: int
    sender_workload: str
    receiver_workload: str


class TransitionGuard:
    """Minimal deterministic transition relation for APC envelopes."""

    def __init__(self, allowed_receivers: Iterable[str] = ()):
        self.allowed_receivers = frozenset(allowed_receivers)

    def validate(self, previous: TransitionStep | None, current: TransitionStep) -> None:
        if current.counter < 0:
            raise ValueError("negative transition counter")
        if previous is None:
            if current.parent_transition_id is not None or current.counter != 0:
                raise ValueError("root transition has invalid parent/counter")
        else:
            if current.action_chain_id != previous.action_chain_id:
                raise ValueError("action chain mismatch")
            if current.parent_transition_id != previous.transition_id:
                raise ValueError("parent transition mismatch")
            if current.counter != previous.counter + 1:
                raise ValueError("transition counter is not monotonic")
        if self.allowed_receivers and current.receiver_workload not in self.allowed_receivers:
            raise ValueError("receiver workload is not in allowed transition set")
