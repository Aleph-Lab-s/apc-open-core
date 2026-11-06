from .authority import (
    issue_authority,
    verify_authority_matches_act,
    verify_execution_authority_signature,
)
from .canonical import candidate_act_digest, canonical_json, sha256_hex
from .crypto import Ed25519KeyPair, verify_signature
from .errors import APCError, APCErrorCode
from .evidence import GENESIS_HASH, EvidenceChain, EvidenceRecord
from .execution import APCExecutionGate, ExecutionResult, PaymentLedger, ProtectedExecutor
from .finality import FinalityVerifier
from .flagship import (
    ActionContext,
    AuthorityFactory,
    AuthorityV2,
    Delegation,
    DurableAuthorityStore,
    EffectResult,
    EvidenceLedger,
    FinalityEnforcer,
    FlagshipProtectedExecutor,
    IntentContract,
    ProtectedSink,
    SecurityState,
    WorkloadIdentity,
)
from .models import *
from .state import AuthorityStateStore

__version__ = "0.1.0a1"
from .attestation import WorkloadAttestation, WorkloadTrustRegistry
from .constraints import scope_attenuates
from .continuity import (
    CONTINUITY_PROTOCOL_VERSION,
    ActionSecurityGraph,
    APCAuthorityReference,
    APCNodeAssuranceVerifier,
    APCNodeAttestation,
    APCProtocolEnvelope,
    APCSecurityOperations,
    APCTransitionEnforcer,
    ContinuityFinalityVerifier,
    ContinuityProtectedExecutor,
    ContinuityStore,
    ContinuityWitness,
    ContractMatch,
    SecurityContract,
    SecurityContractRegistry,
    TransitionDecision,
    TransitionState,
    create_attestation,
    sign_envelope,
)
from .controls import Approval, ApprovalGate, ApprovalState
from .crypto_profiles import ED25519_V1, CryptoProfile
from .delegation import DelegationIssuer, SignedDelegation, verify_delegation
from .effect_contract import EffectContract, ProtectedSinkV2
from .entitlement import EnterpriseEntitlement, entitlement_json, issue_entitlement
from .events import MemorySecurityEventSink, SecurityEvent
from .evidence_store import ImmutableEvidenceSink, MemoryImmutableEvidenceSink
from .freshness import FreshnessProfile
from .intent import IntentContractV2
from .linearizable import DecisionState, LinearizableAuthorityRegister
from .persistence import DurableReconciliationQueue, PostgresAuthorityStore, ReconciliationItem
from .protocol import ProtocolProfile
from .vendor import (
    AdapterCapability,
    AdapterHealth,
    AdapterLifecycle,
    ConformanceResult,
    IntegrationManager,
    IntegrationManifest,
    OwnerSet,
    SecretRef,
    SupportBundleBuilder,
    SupportPolicy,
    UpgradePlan,
    VendorAdapter,
    run_conformance,
)
