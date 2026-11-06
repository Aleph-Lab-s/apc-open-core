from __future__ import annotations
from typing import Protocol, Any

class ImmutableEvidenceSink(Protocol):
    """Customer-owned immutable/WORM implementation boundary."""
    def append(self, record:dict[str,Any])->None: ...
    def verify_checkpoint(self, checkpoint:dict[str,Any])->bool: ...

class MemoryImmutableEvidenceSink:
    def __init__(self): self.records=[]
    def append(self,record): self.records.append(record)
    def verify_checkpoint(self,checkpoint): return bool(checkpoint)
