from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ApprovalState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class Approval:
    approval_id: str
    authority_id: str
    approver_id: str
    state: ApprovalState
    created_at: datetime
    reason: str = ""


class ApprovalGate:
    def __init__(self, required: int = 1):
        self.required = required
        self._approvals = {}

    def approve(self, approval: Approval, actor_id: str):
        if approval.approver_id != actor_id:
            raise PermissionError("approver identity mismatch")
        if approval.state is not ApprovalState.APPROVED:
            raise ValueError("approval is not approved")
        self._approvals.setdefault(approval.authority_id, set()).add(approval.approver_id)

    def satisfied(self, authority_id: str) -> bool:
        return len(self._approvals.get(authority_id, set())) >= self.required
