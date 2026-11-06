# Experimental runtime controls — not part of supported APC runtime

This folder preserves the five-module engineering candidate supplied alongside APC 7.1.4: multihop continuity, egress guard, credential broker, policy gate, and topology guard. They are published for inspection and contribution only.

**Status: EXPERIMENTAL / NOT INTEGRATED / NOT PRODUCTION-APPROVED.** These modules are not imported by `apc_product`, are not wired into the evaluation engine or provider adapters, and are not covered by the supported runtime's security guarantees. The companion tests are candidate tests, not proof of complete integration.

Before promotion, contributors must integrate the controls into the actual request-to-effect path, test all bypass paths, test concurrency/replay/revocation, validate secret handling and network enforcement with real infrastructure, update the threat model, and obtain independent review.

The modules were supplied by the APC project as an independently authored candidate. This repository does not include NVIDIA OpenShell code. Before publication, the project owner must still confirm provenance and third-party licensing for every contributed file.
