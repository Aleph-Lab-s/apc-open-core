# Contributing to APC

We welcome serious criticism, reproducible security research, protocol proposals, bug reports, tests, adapters, documentation and integrations.

## Ground rules

1. Do not claim a feature is supported because a branch, prototype or test stub exists.
2. Every adapter must identify its mode (`REAL`, `SANDBOX`, `SYNTHETIC`, `SIMULATED`, or `UNAVAILABLE`) and its external dependencies.
3. The customer PDP remains authoritative. Do not accept an agent-supplied boolean as production authorization.
4. The final effect boundary must bind exact operation, target/resource, material parameters, actor, tenant, policy state, sink and freshness.
5. Unknown provider outcomes must remain `UNKNOWN` until authoritative provider reconciliation. Do not blindly retry non-idempotent effects.
6. Bypass tests must enumerate alternate execution paths, not only exercise the happy path through the APC wrapper.
7. Do not put credentials, customer data, private endpoints, incident details or exploitable live targets in public issues.

## Development workflow

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,mcp]"
python -m pytest -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python tests/deep_security_test.py
```

Use a focused branch, add regression tests and update the relevant documentation. Keep changes small enough for security review. Do not reformat large security-sensitive modules in the same PR as behavior changes.

## Pull request checklist

- [ ] Explain threat, intended behavior and trust assumptions.
- [ ] Include a failing-before/fixed-after regression test where practical.
- [ ] Test mutation, replay, concurrency, revocation, expiry and bypass cases relevant to the change.
- [ ] Identify whether execution is REAL, SANDBOX, SYNTHETIC, SIMULATED or UNAVAILABLE.
- [ ] State what is not covered.
- [ ] Update threat model, integration status and release notes if appropriate.
- [ ] No secrets, customer data, copied third-party code without license review, or hidden network calls.

## Security reports

Please do not open a public issue for an undisclosed vulnerability. Follow `SECURITY.md` and use GitHub's private vulnerability reporting once the repository is live.

## License of contributions

By submitting a contribution, you agree that it is offered under the Apache License 2.0 unless a separate written agreement says otherwise. This contribution policy must be reviewed by the project owner before accepting outside PRs.
