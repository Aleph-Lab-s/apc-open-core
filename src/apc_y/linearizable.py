from __future__ import annotations
import threading
from dataclasses import dataclass
from enum import Enum

class DecisionState(str,Enum): ACTIVE='ACTIVE'; RESERVED='RESERVED'; EXECUTING='EXECUTING'; EFFECTED='EFFECTED'; FAILED='FAILED'; UNKNOWN='UNKNOWN'; REVOKED='REVOKED'; EXPIRED='EXPIRED'

@dataclass(frozen=True)
class Transition:
    authority_id:str; old:str; new:str

class LinearizableAuthorityRegister:
    """Reference state machine used for concurrency/fault testing; production storage remains pluggable."""
    def __init__(self): self._lock=threading.Lock(); self._states={}; self.history=[]
    def register(self, aid):
        with self._lock:
            if aid in self._states: raise ValueError('duplicate authority')
            self._states[aid]=DecisionState.ACTIVE.value
    def transition(self, aid, expected, new):
        with self._lock:
            old=self._states.get(aid)
            if old != expected: return False
            self._states[aid]=new; self.history.append(Transition(aid,old,new)); return True
    def state(self, aid):
        with self._lock: return self._states.get(aid)
