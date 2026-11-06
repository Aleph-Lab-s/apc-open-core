# Release validation report — 0.1.0a1

Date: 2026-11-06. Environment: Linux x86_64 container, Python 3.13.5, local package environment.

## Source provenance

The Python packages `apc`, `apc_y` and `apc_product` were recovered from the supplied APC Enterprise 7.1.4 OCI image. The deployment chart, qualification scripts and candidate documents were taken from the supplied 7.1.4 Kubernetes certification-candidate archive. The NVIDIA-inspired five-module patch was placed under `experiments/` without importing it into the supported runtime. The 288 KB internal master specification and pricing formula were not copied into this repository.

## Existing candidate evidence

The supplied 7.1.4 qualification files report 28/28 deep-kernel checks and 36/36 runtime/delivery campaign checks passing in their controlled environment. The included `tests/deep_security_test.py` is the named deep-kernel script. These are APC-authored internal tests, not independent audit or production validation.

## Local validation performed for this public package build

This report is completed by the release builder at packaging time. See `RELEASE-REPORT.json` for command outputs and actual pass/skip counts. Tests are not represented as external certification.

## Not run / not claimed

- MCP SDK runtime tests if the optional `mcp` dependency is not installed in the build environment.
- MCP Inspector or official MCP Registry publishing/validation.
- PyPI publish or Trusted Publishing setup.
- Helm/Kubernetes cluster deployment, multi-node HA or performance/SLO qualification.
- External dependency vulnerability audit if `pip-audit` could not be run.
- Independent penetration test, cryptographic review, SBOM signing/provenance, Red Hat/AWS Marketplace certification or live provider conformance.

Re-run the release workflow in a clean, network-enabled CI environment before publishing. Replace any skipped item only with a recorded, reproducible result.
