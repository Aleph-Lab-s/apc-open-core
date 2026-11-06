from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .constraints import scope_attenuates
from .protocol import domain_digest, DOMAIN_INTENT

@dataclass(frozen=True)
class IntentContractV2:
    intent_id: str
    semantic_class: str
    allowed_operations: tuple[str,...]
    allowed_resources: tuple[str,...]
    allowed_audiences: tuple[str,...]
    constraints: dict[str,Any]
    max_risk: int = 100
    def payload(self):
        return {'intent_id':self.intent_id,'semantic_class':self.semantic_class,'allowed_operations':self.allowed_operations,'allowed_resources':self.allowed_resources,'allowed_audiences':self.allowed_audiences,'constraints':self.constraints,'max_risk':self.max_risk}
    @property
    def digest(self): return domain_digest(DOMAIN_INTENT,self.payload())
    def permits(self, act: dict[str,Any], risk: int) -> bool:
        if risk > self.max_risk or act.get('operation') not in self.allowed_operations or act.get('resource') not in self.allowed_resources: return False
        if self.allowed_audiences and act.get('audience') not in self.allowed_audiences: return False
        params=act.get('parameters',{}); cons=act.get('constraints',{})
        for k,v in self.constraints.items():
            if params.get(k,cons.get(k,'__MISSING__')) != v: return False
        return True
    def allows_transform(self, original: 'IntentContractV2') -> bool:
        child={'operations':self.allowed_operations,'resources':self.allowed_resources,'audience':self.allowed_audiences,'max_risk':self.max_risk,**self.constraints}
        parent={'operations':original.allowed_operations,'resources':original.allowed_resources,'audience':original.allowed_audiences,'max_risk':original.max_risk,**original.constraints}
        return scope_attenuates(child,parent)
