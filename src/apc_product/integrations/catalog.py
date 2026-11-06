from .contracts import AdapterManifest, UnconfiguredAdapter

CATALOG = [
    AdapterManifest(
        "opa-http",
        "0.1.0",
        "Open Policy Agent",
        "PDP",
        ("authorize",),
        ("input", "decision_path"),
        ("policy_decision",),
        "SIMULATED",
        required_secrets=(),
    ),
    AdapterManifest(
        "cedar-bridge",
        "0.1.0",
        "Cedar",
        "PDP",
        ("authorize",),
        ("principal", "action", "resource", "context"),
        ("policy_decision",),
        "SIMULATED",
    ),
    AdapterManifest(
        "okta-events",
        "0.2.0",
        "Okta",
        "INBOUND",
        ("event.ingest",),
        ("eventType", "actor", "target", "published"),
        ("signed_webhook_validation",),
        "UNAVAILABLE",
    ),
    AdapterManifest(
        "github-events",
        "0.2.0",
        "GitHub",
        "BIDIRECTIONAL",
        ("webhook.ingest", "check.create"),
        ("repository", "sender", "action", "installation"),
        ("webhook_validation",),
        "UNAVAILABLE",
    ),
    AdapterManifest(
        "aws-events",
        "0.2.0",
        "AWS",
        "BIDIRECTIONAL",
        ("event.ingest", "effect.invoke"),
        ("account", "region", "resource", "operation"),
        ("iam_identity",),
        "UNAVAILABLE",
    ),
    AdapterManifest(
        "gcp-events",
        "0.2.0",
        "Google Cloud",
        "BIDIRECTIONAL",
        ("event.ingest", "effect.invoke"),
        ("project", "region", "resource", "operation"),
        ("workload_identity",),
        "UNAVAILABLE",
    ),
    AdapterManifest(
        "stripe-test",
        "0.1.0",
        "Stripe",
        "BIDIRECTIONAL",
        ("payment.create", "event.ingest"),
        ("amount", "currency", "customer_ref", "idempotency_key"),
        ("provider_idempotency", "reconciliation"),
        "SANDBOX",
        True,
        True,
        ("STRIPE_SECRET_KEY",),
    ),
    AdapterManifest(
        "generic-siem-webhook",
        "0.1.0",
        "Generic SIEM",
        "OUTBOUND",
        ("event.forward",),
        ("event_id", "tenant", "kind", "payload", "event_hash"),
        ("https_webhook",),
        "SIMULATED",
        required_secrets=("webhook_token",),
    ),
]


def catalog():
    return [m.to_dict() for m in CATALOG]


def get_adapter(adapter_id):
    for m in CATALOG:
        if m.adapter_id == adapter_id:
            return UnconfiguredAdapter(m)
    raise KeyError(adapter_id)
