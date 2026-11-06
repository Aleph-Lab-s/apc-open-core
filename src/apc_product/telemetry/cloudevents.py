from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from apc_product.kernel.canonical import sha256_hex


@dataclass(frozen=True)
class CloudEvent:
    id: str
    source: str
    type: str
    specversion: str
    time: datetime
    subject: str | None
    datacontenttype: str
    data: Mapping[str, Any]
    extensions: Mapping[str, Any]

    @classmethod
    def create(
        cls,
        *,
        source: str,
        event_type: str,
        data: Mapping[str, Any],
        subject: str | None = None,
        **extensions: Any,
    ) -> CloudEvent:
        return cls(
            id=str(uuid.uuid4()),
            source=source,
            type=event_type,
            specversion="1.0",
            time=datetime.now(UTC),
            subject=subject,
            datacontenttype="application/json",
            data=dict(data),
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, Any]:
        out = {
            "specversion": self.specversion,
            "id": self.id,
            "source": self.source,
            "type": self.type,
            "time": self.time,
            "datacontenttype": self.datacontenttype,
            "data": dict(self.data),
        }
        if self.subject is not None:
            out["subject"] = self.subject
        out.update(dict(self.extensions))
        return out

    @property
    def digest(self) -> str:
        return sha256_hex(self.to_dict())
