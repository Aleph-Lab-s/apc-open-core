from __future__ import annotations

"""Opaque, endpoint-bound runtime credential broker.

APC stores credential references, never plaintext provider secrets. A deployment
supplies a resolver callback; the broker only resolves after egress admission.
"""

from dataclasses import dataclass
import hashlib
from typing import Callable

from .egress_guard import EgressDecision


@dataclass(frozen=True)
class CredentialBinding:
    profile: str
    credential_name: str
    host: str
    port: int
    path_prefix: str = "/"
    revision: str = "1"

    @property
    def digest(self) -> str:
        raw = f"{self.profile}|{self.credential_name}|{self.host.lower()}|{self.port}|{self.path_prefix}|{self.revision}"
        return hashlib.sha256(raw.encode()).hexdigest()


class CredentialBroker:
    def __init__(self, resolver: Callable[[str, str, str], str]):
        self._resolver = resolver
        self._bindings: dict[str, CredentialBinding] = {}

    def issue_placeholder(self, binding: CredentialBinding) -> str:
        placeholder = "APC_CRED_" + binding.digest[:40]
        self._bindings[placeholder] = binding
        return placeholder

    def resolve(self, placeholder: str, *, host: str, port: int, path: str, decision: EgressDecision) -> str:
        binding = self._bindings.get(placeholder)
        if binding is None:
            raise PermissionError("unknown credential placeholder")
        if not decision.allowed:
            raise PermissionError("credential resolution denied before egress admission")
        if binding.host.lower().rstrip(".") != host.lower().rstrip(".") or binding.port != port:
            raise PermissionError("credential endpoint binding mismatch")
        if not path.startswith(binding.path_prefix):
            raise PermissionError("credential path binding mismatch")
        # The resolver returns the current value but APC never persists it.
        return self._resolver(binding.profile, binding.credential_name, binding.revision)

    def forget(self, placeholder: str) -> None:
        self._bindings.pop(placeholder, None)
