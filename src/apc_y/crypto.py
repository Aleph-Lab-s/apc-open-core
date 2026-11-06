from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json
from .errors import APCError, APCErrorCode


class Ed25519KeyPair:

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        key_id: str,
    ):
        if not key_id or not key_id.strip():
            raise ValueError("key_id must be non-empty")

        self._private_key = private_key
        self.key_id = key_id

    @classmethod
    def generate(
        cls,
        key_id: str,
    ) -> "Ed25519KeyPair":
        return cls(
            Ed25519PrivateKey.generate(),
            key_id,
        )

    def sign(
        self,
        payload: Any,
    ) -> str:
        signature = self._private_key.sign(
            canonical_json(payload)
        )

        return base64.urlsafe_b64encode(
            signature
        ).decode("ascii")

    def public_key_pem(self) -> str:
        public_key = self._private_key.public_key()

        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


def verify_signature(
    payload: Any,
    signature_b64: str,
    public_key_pem: str,
) -> None:

    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        if not isinstance(
            public_key,
            Ed25519PublicKey,
        ):
            raise APCError(
                APCErrorCode.INVALID_SIGNATURE,
                "Public key is not an Ed25519 key",
            )

        signature = base64.urlsafe_b64decode(
            signature_b64.encode("ascii")
        )

        public_key.verify(
            signature,
            canonical_json(payload),
        )

    except InvalidSignature as exc:
        raise APCError(
            APCErrorCode.INVALID_SIGNATURE,
            "Signature verification failed",
        ) from exc

    except APCError:
        raise

    except Exception as exc:
        raise APCError(
            APCErrorCode.INVALID_SIGNATURE,
            str(exc),
        ) from exc
