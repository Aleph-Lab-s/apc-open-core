from pathlib import Path

from apc_y.canonical import CANONICALIZATION_VERSION
from apc_y.continuity import (
    CONTINUITY_PROTOCOL_VERSION, CONTINUITY_SCHEMA_VERSION,
    CONTINUITY_WITNESS_SCHEMA, CONTINUITY_CRYPTO_DOMAIN, WITNESS_CRYPTO_DOMAIN,
)
from apc_y.flagship import SCHEMA_VERSION, CRYPTO_DOMAIN

ROOT = Path(__file__).resolve().parents[1]


def test_public_protocol_draft_matches_runtime_identifiers():
    spec = (ROOT / "spec/APC-Action-Continuity-Protocol-0.1-DRAFT.md").read_text()
    for value in (
        CANONICALIZATION_VERSION, CONTINUITY_PROTOCOL_VERSION, CONTINUITY_SCHEMA_VERSION,
        CONTINUITY_WITNESS_SCHEMA, CONTINUITY_CRYPTO_DOMAIN, WITNESS_CRYPTO_DOMAIN,
        SCHEMA_VERSION, CRYPTO_DOMAIN,
    ):
        assert value in spec
    assert "Draft / non-standard" in spec
    assert "cross-language test vectors" in spec
