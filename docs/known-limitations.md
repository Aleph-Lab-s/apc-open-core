# Known limitations

- This alpha source snapshot is not a full enterprise-grade implementation, independent security audit, certification, or compliance attestation.
- Demo mode is synthetic and effect-free.
- Lab mode has a real local SQLite write, but no external provider side effect.
- Production/PILOT modes are blocked by the current service.
- Evaluation keys are generated in-process and are ephemeral; no KMS/HSM or rotation is wired in.
- The current state model and chart are single-replica/local-database; do not horizontally scale it.
- No universal MCP interception or transparent agent-framework instrumentation exists.
- Integration catalog states are SIMULATED, SANDBOX or UNAVAILABLE as documented.
- Bypass paths in user applications are outside APC coverage unless constrained and tested.
- The NVIDIA-inspired patch is experimental and unintegrated.
- Internal test results are not proof of security against all attacks.
