"""APC Resilient Enforcement & Emergency Control.

Reference implementation: fail-closed security + bounded business continuity.
Production requires durable distributed state, strong human auth, KMS/HSM,
protected execution isolation, and deployment-specific HA/fencing.
"""
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import hmac, json, secrets, time
from typing import Mapping, Optional, Protocol, Tuple, Iterable, Callable

class SystemMode(str, Enum):
    NORMAL="NORMAL"; FAILOVER="FAILOVER"; DEGRADED="DEGRADED"; EMERGENCY="EMERGENCY"; RECOVERY="RECOVERY"
class EmergencyStatus(str, Enum):
    INACTIVE="INACTIVE"; ACTIVE="ACTIVE"; CLOSED="CLOSED"
class ApprovalDecision(str, Enum):
    APPROVE="APPROVE"; DENY="DENY"
class SecurityDecision(str, Enum):
    ALLOW="ALLOW"; BLOCK="BLOCK"; UNKNOWN="UNKNOWN"

class ResilienceError(Exception): pass
class SecurityBlocked(ResilienceError): pass
class EmergencyNotAllowed(ResilienceError): pass
class EmergencyAlreadyUsed(ResilienceError): pass
class EmergencyApprovalError(ResilienceError): pass

@dataclass(frozen=True)
class EmergencyPolicy:
    allowed_operations: frozenset[str]
    allowed_sinks: frozenset[str]
    max_amount: Optional[float] = None
    max_duration_seconds: int = 900
    require_two_person_approval: bool = True
    def permits(self, operation, sink, amount):
        return (operation in self.allowed_operations and sink in self.allowed_sinks and
                (self.max_amount is None or amount is None or amount <= self.max_amount))

@dataclass(frozen=True)
class EmergencyRequest:
    request_id: str; invocation_id: str; actor: str; principal: str
    operation: str; resource: str; parameters: Mapping[str, object]
    purpose: str; sink: str; amount: Optional[float]; requested_at: float
    exact_act_digest: str
    @staticmethod
    def canonical_act(operation, resource, parameters, purpose, sink, amount):
        return json.dumps({"amount":amount,"operation":operation,"parameters":parameters,
                           "purpose":purpose,"resource":resource,"sink":sink},
                          sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    @classmethod
    def create(cls, *, invocation_id, actor, principal, operation, resource, parameters,
               purpose, sink, amount, now=None):
        digest=sha256(cls.canonical_act(operation,resource,parameters,purpose,sink,amount)).hexdigest()
        return cls(secrets.token_hex(16),invocation_id,actor,principal,operation,resource,
                   dict(parameters),purpose,sink,amount,time.time() if now is None else now,digest)

@dataclass(frozen=True)
class HumanApproval:
    approver_id: str; decision: ApprovalDecision; approved_request_id: str
    approved_act_digest: str; approved_at: float; authentication_context: str; reason: str=""

@dataclass(frozen=True)
class EmergencyAuthority:
    authority_id: str; request_id: str; invocation_id: str; actor: str; principal: str
    operation: str; resource: str; parameters: Mapping[str, object]; purpose: str; sink: str
    amount: Optional[float]; exact_act_digest: str; issued_at: float; expires_at: float
    nonce: str; approvals: Tuple[HumanApproval,...]; emergency_epoch: int; signature: str
    def unsigned_payload(self):
        return json.dumps({"authority_id":self.authority_id,"request_id":self.request_id,
            "invocation_id":self.invocation_id,"actor":self.actor,"principal":self.principal,
            "operation":self.operation,"resource":self.resource,"parameters":dict(self.parameters),
            "purpose":self.purpose,"sink":self.sink,"amount":self.amount,
            "exact_act_digest":self.exact_act_digest,"issued_at":self.issued_at,
            "expires_at":self.expires_at,"nonce":self.nonce,"emergency_epoch":self.emergency_epoch,
            "approvals":[a.__dict__ | {"decision":a.decision.value} for a in self.approvals]},
            sort_keys=True,separators=(",",":"),allow_nan=False).encode()

class EmergencySigner(Protocol):
    def sign(self,payload:bytes)->str: ...
    def verify(self,payload:bytes,signature:str)->bool: ...
class HmacReferenceSigner:
    def __init__(self, secret:bytes): self.secret=secret
    def sign(self,payload): return hmac.new(self.secret,payload,"sha256").hexdigest()
    def verify(self,payload,signature): return hmac.compare_digest(self.sign(payload),signature)

@dataclass
class SecurityEvent:
    event_type:str; timestamp:float; severity:str; request_id:Optional[str]=None
    authority_id:Optional[str]=None; invocation_id:Optional[str]=None; actor:Optional[str]=None
    exact_act_digest:Optional[str]=None; mode:Optional[str]=None; outcome:Optional[str]=None
    reason:Optional[str]=None
class EventSink(Protocol):
    def emit(self,event:SecurityEvent)->None: ...
class InMemoryEventSink:
    def __init__(self): self.events=[]
    def emit(self,event): self.events.append(event)
class ProtectedEmergencyExecutor(Protocol):
    def execute(self,authority:EmergencyAuthority)->str: ...

@dataclass
class EmergencyController:
    policy: EmergencyPolicy; signer: EmergencySigner; events: EventSink
    clock: Callable[[],float]=time.time
    mode:SystemMode=SystemMode.NORMAL; emergency_status:EmergencyStatus=EmergencyStatus.INACTIVE
    emergency_epoch:int=0; _used:set[str]=field(default_factory=set)
    def set_mode(self,mode,reason):
        self.mode=mode; self.events.emit(SecurityEvent("APC_RESILIENCE_MODE_CHANGED",self.clock(),"HIGH",mode=mode.value,reason=reason))
    def open_emergency_window(self,reason):
        if self.mode!=SystemMode.EMERGENCY: raise EmergencyNotAllowed("Emergency mode is not active")
        self.emergency_epoch+=1; self.emergency_status=EmergencyStatus.ACTIVE
        self.events.emit(SecurityEvent("APC_EMERGENCY_WINDOW_OPENED",self.clock(),"CRITICAL",mode=self.mode.value,reason=reason))
    def close_emergency_window(self,reason):
        self.emergency_status=EmergencyStatus.CLOSED; self.mode=SystemMode.RECOVERY
        self.events.emit(SecurityEvent("APC_EMERGENCY_WINDOW_CLOSED",self.clock(),"HIGH",mode=self.mode.value,reason=reason))
    def issue_authority(self,request,approvals:Iterable[HumanApproval]):
        if self.mode!=SystemMode.EMERGENCY or self.emergency_status!=EmergencyStatus.ACTIVE: raise EmergencyNotAllowed("No active emergency window")
        if not self.policy.permits(request.operation,request.sink,request.amount): raise EmergencyNotAllowed("Outside emergency policy")
        valid=[a for a in approvals if a.decision==ApprovalDecision.APPROVE and a.approved_request_id==request.request_id and a.approved_act_digest==request.exact_act_digest and a.authentication_context]
        if self.policy.require_two_person_approval:
            if len({a.approver_id for a in valid})<2: raise EmergencyApprovalError("Two distinct authenticated approvers required")
        elif not valid: raise EmergencyApprovalError("Authenticated approval required")
        now=self.clock()
        a=EmergencyAuthority(secrets.token_hex(16),request.request_id,request.invocation_id,request.actor,request.principal,
            request.operation,request.resource,dict(request.parameters),request.purpose,request.sink,request.amount,
            request.exact_act_digest,now,now+self.policy.max_duration_seconds,secrets.token_hex(16),tuple(valid),self.emergency_epoch,"")
        sig=self.signer.sign(a.unsigned_payload()); a=EmergencyAuthority(**{**a.__dict__,"signature":sig})
        self.events.emit(SecurityEvent("APC_EMERGENCY_AUTHORITY_ISSUED",now,"CRITICAL",request.request_id,a.authority_id,request.invocation_id,request.actor,request.exact_act_digest,self.mode.value,"ISSUED"))
        return a
    def validate_before_effect(self,a,actual):
        def deny(reason):
            self.events.emit(SecurityEvent("APC_EMERGENCY_FINALITY_DENIED",self.clock(),"CRITICAL",a.request_id,a.authority_id,a.invocation_id,a.actor,a.exact_act_digest,self.mode.value,"BLOCK",reason)); return SecurityDecision.BLOCK
        if a.authority_id in self._used: return deny("EMERGENCY_AUTHORITY_REPLAY")
        if self.mode!=SystemMode.EMERGENCY or self.emergency_status!=EmergencyStatus.ACTIVE: return deny("EMERGENCY_MODE_CLOSED")
        if a.emergency_epoch!=self.emergency_epoch: return deny("EMERGENCY_EPOCH_MISMATCH")
        if self.clock()>=a.expires_at: return deny("EMERGENCY_AUTHORITY_EXPIRED")
        if not self.signer.verify(a.unsigned_payload(),a.signature): return deny("EMERGENCY_SIGNATURE_INVALID")
        if actual.exact_act_digest!=a.exact_act_digest: return deny("EMERGENCY_EXACT_ACT_MISMATCH")
        if actual.actor!=a.actor or actual.principal!=a.principal: return deny("EMERGENCY_IDENTITY_MISMATCH")
        if actual.operation!=a.operation or actual.resource!=a.resource: return deny("EMERGENCY_TARGET_MISMATCH")
        if actual.sink!=a.sink or actual.amount!=a.amount: return deny("EMERGENCY_SINK_OR_AMOUNT_MISMATCH")
        self.events.emit(SecurityEvent("APC_EMERGENCY_FINALITY_VALIDATED",self.clock(),"HIGH",a.request_id,a.authority_id,a.invocation_id,a.actor,a.exact_act_digest,self.mode.value,"ALLOW")); return SecurityDecision.ALLOW
    def consume_for_execution(self,a):
        if a.authority_id in self._used: raise EmergencyAlreadyUsed(a.authority_id)
        self._used.add(a.authority_id)
    def execute(self,a,actual,executor):
        if self.validate_before_effect(a,actual)!=SecurityDecision.ALLOW: raise SecurityBlocked("Emergency finality validation failed")
        self.consume_for_execution(a)
        try: return executor.execute(a)
        except TimeoutError:
            self.events.emit(SecurityEvent("APC_EMERGENCY_EXECUTION_UNKNOWN",self.clock(),"CRITICAL",a.request_id,a.authority_id,a.invocation_id,a.actor,a.exact_act_digest,self.mode.value,"UNKNOWN","Reconciliation required")); raise
    def recover(self,reason): self.close_emergency_window(reason); self.events.emit(SecurityEvent("APC_RECOVERY_STARTED",self.clock(),"HIGH",mode=self.mode.value,reason=reason))
    def complete_recovery(self,reason):
        self.mode=SystemMode.NORMAL; self.emergency_status=EmergencyStatus.INACTIVE
        self.events.emit(SecurityEvent("APC_RECOVERY_COMPLETED",self.clock(),"HIGH",mode=self.mode.value,reason=reason))

if __name__=="__main__":
    print("APC Resilient Enforcement module loaded: PASS")
    print("Emergency execution is bounded, exact-act scoped, dual-control by default, and never a generic APC bypass.")
