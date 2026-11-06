from __future__ import annotations

import argparse
import json
from pathlib import Path

from .service import APCService


def main(argv=None):
    p = argparse.ArgumentParser(prog="apc", description="APC enterprise action-security runtime")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("doctor")
    sub.add_parser("integrations")
    sub.add_parser("evidence-verify")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    a = sub.add_parser("action")
    a.add_argument("--tenant", required=True)
    a.add_argument("--operation", required=True)
    a.add_argument("--target", required=True)
    a.add_argument("--policy-decision", default="DENY")
    a.add_argument("--policy-decision-id")
    a.add_argument("--authority-ref")
    a.add_argument("--sink")
    a.add_argument("--payload", default="{}")
    a.add_argument("--mode", choices=["DEMO", "LAB"], default="DEMO")
    pack = sub.add_parser("package")
    pack.add_argument("--intake", required=True)
    pack.add_argument("--out", required=True)

    args = p.parse_args(argv)
    if args.cmd == "serve":
        from .api.server import serve
        serve(args.host, args.port)
        return 0

    if args.cmd == "package":
        from .delivery import CustomerIntake, DeliveryFactory
        intake = json.loads(Path(args.intake).read_text(encoding="utf-8"))
        manifest = DeliveryFactory(Path.cwd()).build(CustomerIntake.from_mapping(intake), args.out)
        print(json.dumps(json.loads(manifest.read_text(encoding="utf-8")), indent=2))
        return 0

    svc = APCService()
    try:
        if args.cmd in ("status", "doctor"):
            out = svc.health()
        elif args.cmd == "integrations":
            out = {"items": svc.integrations()}
        elif args.cmd == "evidence-verify":
            out = svc.verify_evidence()
        elif args.cmd == "action":
            try:
                payload = json.loads(args.payload)
            except json.JSONDecodeError as exc:
                p.error(f"invalid --payload JSON: {exc}")
            out = svc.submit({
                "tenant": args.tenant,
                "operation": args.operation,
                "target": args.target,
                "policy_decision": args.policy_decision,
                "policy_decision_id": args.policy_decision_id,
                "authority_ref": args.authority_ref,
                "sink": args.sink,
                "payload": payload,
                "mode": args.mode,
            })
        else:
            raise AssertionError(args.cmd)
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0
    finally:
        svc.close()


if __name__ == "__main__":
    raise SystemExit(main())
