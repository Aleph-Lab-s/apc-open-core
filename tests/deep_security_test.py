import os, sys, json, tempfile, threading, concurrent.futures, time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from apc_y.canonical import canonical_json, candidate_act_digest
from apc_y.crypto import Ed25519KeyPair, verify_signature
from apc_y.errors import APCError
from apc_y.models import IdentityContext, DelegationContext, PolicyDecision, CandidateAct, Decision
from apc_y.authority import issue_authority, verify_authority_matches_act, authority_payload
from apc_y.flagship import (IntentContract, WorkloadIdentity, Delegation, SecurityState,
                            ActionContext, AuthorityFactory, DurableAuthorityStore, FinalityEnforcer)
from apc_y.constraints import scope_attenuates
from apc_y.freshness import FreshnessProfile
from apc_y.attestation import WorkloadAttestation, WorkloadTrustRegistry
from apc_y.linearizable import LinearizableAuthorityRegister, DecisionState
from apc_y.evidence import EvidenceChain
from apc_y.persistence import DurableReconciliationQueue, ReconciliationItem

results=[]
def ok(t, detail=''):
    results.append({'id':t,'status':'PASS','detail':detail})
def fail(t, detail):
    results.append({'id':t,'status':'FAIL','detail':detail})
def expect_reject(t, fn, contains=None):
    try:
        fn(); fail(t,'accepted unexpectedly')
    except Exception as e:
        if contains and contains not in str(e): fail(t,f'rejected but wrong error: {e}')
        else: ok(t, type(e).__name__+': '+str(e))

# Canonicalization
expect_reject('CANON-NAN', lambda: canonical_json({'x': float('nan')}), 'non-finite')
expect_reject('CANON-INF', lambda: canonical_json({'x': float('inf')}), 'non-finite')
expect_reject('CANON-NONSTRING-KEY', lambda: canonical_json({1:'x'}), 'string')
try:
    a=canonical_json({'b':1,'a':[2,3],'nested':{'z':True}})
    b=canonical_json({'nested':{'z':True},'a':[2,3],'b':1})
    ok('CANON-DETERMINISTIC', 'equal bytes') if a==b else fail('CANON-DETERMINISTIC','different bytes')
except Exception as e: fail('CANON-DETERMINISTIC',repr(e))

# Authority setup
now=datetime.now(timezone.utc)
key=Ed25519KeyPair.generate('test-key')
identity=IdentityContext(principal_id='principal:1',actor_id='actor:1',actor_type='human',issuer='issuer:test')
deleg=DelegationContext(root_principal_id='principal:1',holder_id='actor:1',delegation_chain=())
act=CandidateAct(invocation_id='inv:1',operation='write',resource='resource:1',parameters={'x':1},audience='sink:test')
pol=PolicyDecision(decision_id='pd:1',issuer='pdp:test',decision=Decision.ALLOW,issued_at=now-timedelta(seconds=1),expires_at=now+timedelta(minutes=5))
# legacy authority API vector
try:
    auth=issue_authority(authority_id='a1',identity=identity,delegation=deleg,policy_decision=pol,candidate_act=act,key_pair=key,issued_at=now-timedelta(seconds=1),expires_at=now+timedelta(minutes=2))
    verify_signature(authority_payload(auth.binding),auth.signature,key.public_key_pem())
    verify_authority_matches_act(auth,act)
    ok('AUTH-SIGNATURE-ROUNDTRIP')
except Exception as e: fail('AUTH-SIGNATURE-ROUNDTRIP',repr(e))

# Flagship authority/finality context
intent=IntentContract('intent:1', {'purpose':'test'}, ('write',), ('resource:1',), {'amount':10} if False else {}, 50)
workload=WorkloadIdentity('workload:1','issuer:test',1)
deleg2=Delegation('principal:1','actor:1',None,{'operations':['write'],'resources':['resource:1']},now+timedelta(minutes=2),50,('sink:test',))
state=SecurityState(policy_epoch=1,identity_epoch=1,delegation_epoch=1,tenant_epoch=1,risk_epoch=1,signer_epoch=1,sink_epoch=1,revocation_epoch=1)
ctx=ActionContext('tenant:1','req:1','inv:1',intent,{'operation':'write','resource':'resource:1','parameters':{'x':1},'audience':'sink:test'},'actor:1','principal:1',workload,deleg2,'app:test',{'r':'v'},'pd:1','v1',1,10,'A1','sink:test',state,policy_issued_at=now-timedelta(seconds=1))
fac=AuthorityFactory(key)
auth2=fac.issue(ctx,now+timedelta(minutes=1),True)
store=DurableAuthorityStore()
store.register(auth2)
enf=FinalityEnforcer(public_key_resolver=lambda kid:key.public_key_pem() if kid==key.key_id else None,store=store,state_provider=lambda tenant:state,freshness_policy=FreshnessProfile())
try:
    enf.verify(auth2,ctx,'actor:1',now=now)
    ok('FINALITY-BASELINE', 'reserved/executing state='+str(store.state(auth2.authority_id)))
except Exception as e: fail('FINALITY-BASELINE',repr(e))
expect_reject('FINALITY-REPLAY', lambda: enf.verify(auth2,ctx,'actor:1',now=now), 'authority cannot be reserved')
# mutation checks use fresh authority/store per test
mutations=[
 ('FINALITY-ACTOR-MISMATCH', ctx.__class__(**{**ctx.__dict__,'actor_id':'actor:evil'}), 'context commitment'),
 ('FINALITY-SINK-MISMATCH', ctx.__class__(**{**ctx.__dict__,'finality_sink':'sink:evil'}), 'context commitment'),
 ('FINALITY-TENANT-MISMATCH', ctx.__class__(**{**ctx.__dict__,'tenant':'tenant:evil'}), 'tenant mismatch'),
 ('FINALITY-POLICY-EPOCH-MISMATCH', ctx.__class__(**{**ctx.__dict__,'policy_epoch':2,'security_state':SecurityState(**{**state.__dict__,'policy_epoch':2})}), 'context commitment'),
 ('FINALITY-ACT-MISMATCH', ctx.__class__(**{**ctx.__dict__,'candidate_act':{'operation':'delete','resource':'resource:1','parameters':{'x':1},'audience':'sink:test'}}), 'context commitment'),
]
for tid,mctx,needle in mutations:
    try:
        a=fac.issue(ctx,now+timedelta(minutes=1),True)
        s=DurableAuthorityStore(); s.register(a)
        e=FinalityEnforcer(public_key_resolver=lambda kid:key.public_key_pem(),store=s,state_provider=lambda tenant:state,freshness_policy=FreshnessProfile())
        e.verify(a,mctx,'actor:1',now=now)
        fail(tid,'mutation accepted')
    except Exception as e:
        ok(tid,type(e).__name__+': '+str(e))

# issue-time violations
bad_ctx=ctx.__class__(**{**ctx.__dict__,'policy_epoch':2})
expect_reject('AUTH-ISSUE-EPOCH', lambda: fac.issue(bad_ctx,now+timedelta(minutes=1)), 'policy epoch/context mismatch')
bad_act={'operation':'delete','resource':'resource:1','parameters':{'x':1},'audience':'sink:test'}
bad_intent=IntentContract('intent:bad', {'purpose':'test'}, ('write',), ('resource:1',), {},50)
bad_ctx2=ctx.__class__(**{**ctx.__dict__,'intent':bad_intent,'candidate_act':bad_act})
expect_reject('AUTH-ISSUE-INTENT', lambda: fac.issue(bad_ctx2,now+timedelta(minutes=1)), 'candidate act violates intent contract')
expect_reject('DELEGATION-WIDEN-AUDIENCE', lambda: (_ for _ in ()).throw(ValueError()) if not scope_attenuates({'audience':['sink:a','sink:b']},{'audience':['sink:a']}) else None)
if scope_attenuates({'operations':['write']},{'operations':['write','delete']}): ok('DELEGATION-ATTENUATION-OPS')
else: fail('DELEGATION-ATTENUATION-OPS','valid subset rejected')
if not scope_attenuates({'operations':['write','delete']},{'operations':['write']}): ok('DELEGATION-EXPANSION-REJECT')
else: fail('DELEGATION-EXPANSION-REJECT','expansion accepted')

# Freshness/time
fp=FreshnessProfile()
expect_reject('FRESH-FUTURE-ISSUE', lambda: fp.validate(issued_at=now+timedelta(minutes=2),expires_at=now+timedelta(minutes=3),now=now), 'future')
expect_reject('FRESH-STALE-AUTHORITY', lambda: fp.validate(issued_at=now-timedelta(minutes=10),expires_at=now+timedelta(minutes=1),now=now), 'maximum age')
expect_reject('FRESH-STALE-POLICY', lambda: fp.validate(issued_at=now-timedelta(seconds=1),expires_at=now+timedelta(minutes=1),now=now,policy_issued_at=now-timedelta(minutes=10)), 'policy decision')

# Workload attestation epochs
reg=WorkloadTrustRegistry(); att=WorkloadAttestation('w1','issuer',1,'measure',now-timedelta(seconds=1),now+timedelta(minutes=1),'ed')
reg.publish(att)
ok('ATTESTATION-VALID') if reg.verify('w1',now) else fail('ATTESTATION-VALID','not valid')
reg.set_epoch('w1',2)
ok('ATTESTATION-EPOCH-REVOKES') if not reg.verify('w1',now) else fail('ATTESTATION-EPOCH-REVOKES','still valid')

# Linearizable concurrency
lr=LinearizableAuthorityRegister(); lr.register('x')
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    rr=list(ex.map(lambda _: lr.transition('x',DecisionState.ACTIVE.value,DecisionState.EXECUTING.value),range(32)))
if sum(rr)==1 and lr.state('x')=='EXECUTING': ok('LINEARIZABLE-ONE-WINNER')
else: fail('LINEARIZABLE-ONE-WINNER',repr((sum(rr),lr.state('x'))))
expect_reject('LINEARIZABLE-DUPLICATE-REGISTER', lambda: lr.register('x'), 'duplicate authority')

# Evidence chain mutation
try:
    ec=EvidenceChain()
    rec=ec.append(record_id='r1', invocation_id='inv',authority_id='a',candidate_act_digest='d',executing_actor_id='actor',event_type='EFFECT',outcome='SUCCESS',execution_reference='ref',metadata={'x':1})
    ec.append(record_id='r2', invocation_id='inv2',authority_id='a2',candidate_act_digest='d2',executing_actor_id='actor2',event_type='BLOCK',outcome='DENY',metadata={})
    ec.verify(); ok('EVIDENCE-CHAIN-BASELINE')
    # tamper in internal list only for verification exercise
    ec._records[0]=rec.__class__(**{**rec.__dict__,'outcome':'TAMPERED'})
    expect_reject('EVIDENCE-CHAIN-TAMPER', ec.verify, 'hash')
except Exception as e: fail('EVIDENCE-CHAIN-BASELINE',repr(e))

# Reconciliation dedupe
try:
    q=DurableReconciliationQueue()
    item=ReconciliationItem('a','idem','sink','reason')
    q.enqueue(item); q.enqueue(item)
    if len(q.pending())==1: ok('RECONCILIATION-DEDUPE')
    else: fail('RECONCILIATION-DEDUPE',str(q.pending()))
    q.resolve('a')
    ok('RECONCILIATION-RESOLVE') if len(q.pending())==0 else fail('RECONCILIATION-RESOLVE','still pending')
finally:
    try:q.close()
    except:pass

print(json.dumps({'summary':{s:sum(1 for r in results if r['status']==s) for s in ['PASS','FAIL']},'results':results},indent=2))
if any(r['status']=='FAIL' for r in results): sys.exit(1)
