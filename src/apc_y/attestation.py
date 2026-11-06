from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class WorkloadAttestation:
    workload_id: str
    issuer: str
    trust_epoch: int
    measured_identity: str
    issued_at: datetime
    expires_at: datetime
    evidence_digest: str

    def valid(self, now=None):
        now = now or datetime.now(UTC)
        return self.issued_at <= now < self.expires_at


class WorkloadTrustRegistry:
    def __init__(self):
        self._epochs = {}
        self._attestations = {}

    def set_epoch(self, workload_id, epoch):
        self._epochs[workload_id] = epoch

    def current_epoch(self, workload_id, tenant=None):
        return self._epochs.get(workload_id, 0)

    def publish(self, attestation: WorkloadAttestation):
        self._attestations[attestation.workload_id] = attestation
        self._epochs[attestation.workload_id] = attestation.trust_epoch

    def verify(self, workload_id, now=None):
        a = self._attestations.get(workload_id)
        return a is not None and a.trust_epoch == self.current_epoch(workload_id) and a.valid(now)
