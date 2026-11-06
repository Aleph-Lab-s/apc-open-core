from __future__ import annotations

"""Deny-by-default egress admission for APC-controlled agent/tool paths."""

from dataclasses import dataclass
from fnmatch import fnmatchcase
import ipaddress
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class EndpointRule:
    name: str
    hosts: tuple[str, ...]
    ports: tuple[int, ...] = (443,)
    methods: tuple[str, ...] = ("GET",)
    path_prefixes: tuple[str, ...] = ("/",)
    binaries: tuple[str, ...] = ()
    allow_private_ip_literals: bool = False
    credential_profiles: tuple[str, ...] = ()


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str
    rule: str | None = None


class EgressGuard:
    def __init__(self, rules: tuple[EndpointRule, ...] = ()):
        self._rules = rules

    @staticmethod
    def _host_matches(pattern: str, host: str) -> bool:
        pattern = pattern.lower().rstrip(".")
        host = host.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith("." + suffix) and host.count(".") >= suffix.count(".") + 1
        return pattern == host

    @staticmethod
    def _literal_ip(host: str) -> ipaddress._BaseAddress | None:
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    def authorize(
        self,
        *,
        url: str,
        method: str,
        binary: str,
        credential_profile: str | None = None,
    ) -> EgressDecision:
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").strip()
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return EgressDecision(False, "malformed_url")
        if parsed.scheme not in {"https", "http"} or not host:
            return EgressDecision(False, "unsupported_url")
        literal = self._literal_ip(host)
        method = method.upper()
        path = parsed.path or "/"
        for rule in self._rules:
            if port not in rule.ports:
                continue
            if method not in {m.upper() for m in rule.methods} and "*" not in rule.methods:
                continue
            if rule.binaries and binary not in rule.binaries:
                continue
            if not any(path.startswith(prefix) for prefix in rule.path_prefixes):
                continue
            if not any(self._host_matches(pat, host) for pat in rule.hosts):
                continue
            if literal is not None and not rule.allow_private_ip_literals and (literal.is_private or literal.is_loopback or literal.is_link_local or literal.is_reserved):
                return EgressDecision(False, "private_or_reserved_ip_literal", rule.name)
            if credential_profile and rule.credential_profiles and credential_profile not in rule.credential_profiles:
                return EgressDecision(False, "credential_profile_not_allowed", rule.name)
            return EgressDecision(True, "allowed", rule.name)
        return EgressDecision(False, "default_deny")
