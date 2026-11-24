"""Command line: serve the API, seed demo data, run the scripted demo, verify the audit chain."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from importlib import resources
from pathlib import Path

from .models import Agent, Autonomy, Role
from .policy import PolicyError, parse_policy
from .service import GovernanceService
from .store import Store

DEFAULT_DB = os.environ.get("AGENTGOV_DB", "agentgov.db")


def default_policy_text() -> str:
    return resources.files("agentgov").joinpath("default_policy.toml").read_text(encoding="utf-8")


def build_service(db: str) -> GovernanceService:
    return GovernanceService(Store(db))


def bootstrap(service: GovernanceService) -> str | None:
    """Create the first admin if the database has no principals. Returns a newly generated key, if any."""
    if service.store.list_principals():
        return None
    env_key = os.environ.get("AGENTGOV_BOOTSTRAP_ADMIN_KEY")
    _, key = service.create_principal(None, "admin", "Bootstrap administrator", Role.ADMIN, key=env_key)
    if service.store.active_policy_source() is None:
        service.load_policy(None, default_policy_text())
    return None if env_key else key


def seed_demo(service: GovernanceService) -> dict[str, str]:
    """Synthetic organisation for the demo and the dashboard. All names are fictional."""
    keys: dict[str, str] = {}
    if service.store.active_policy_source() is None:
        service.load_policy(None, default_policy_text())
    admin = service.store.get_principal("admin")
    if admin is None:
        admin, keys["admin"] = service.create_principal(None, "admin", "Demo administrator", Role.ADMIN)
    for pid, name, role in (
        ("finance-lead", "Demo finance lead (agent owner)", Role.REVIEWER),
        ("reviewer-a", "Demo reviewer A", Role.REVIEWER),
        ("reviewer-b", "Demo reviewer B", Role.REVIEWER),
        ("auditor", "Demo internal auditor", Role.AUDITOR),
    ):
        _, keys[pid] = service.create_principal(admin, pid, name, role)
    service.register_agent(
        admin,
        Agent(
            id="procurement-agent",
            name="Procurement assistant",
            owner="finance-lead",
            purpose="Looks up suppliers and purchase orders and pays approved invoices.",
            autonomy=Autonomy.SUPERVISED,
            allowed_tools=["erp.suppliers.read", "erp.orders.*", "erp.payments", "email.send"],
            daily_action_limit=200,
            daily_spend_limit=50_000,
            eu_ai_act_risk="minimal",
        ),
    )
    service.register_agent(
        admin,
        Agent(
            id="hr-screening-agent",
            name="CV pre-screening assistant",
            owner="finance-lead",
            purpose="Summarises job applications for recruiters. Classified high-risk (EU AI Act Annex III, employment).",
            autonomy=Autonomy.ASSISTIVE,
            allowed_tools=["ats.applications.read", "ats.notes.write"],
            daily_action_limit=500,
            daily_spend_limit=0,
            eu_ai_act_risk="high",
        ),
    )
    _, keys["procurement-agent"] = service.create_principal(
        admin, "procurement-agent-key", "Procurement agent runtime", Role.AGENT, "procurement-agent"
    )
    _, keys["hr-screening-agent"] = service.create_principal(
        admin, "hr-screening-agent-key", "HR screening agent runtime", Role.AGENT, "hr-screening-agent"
    )
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentgov", description="Governance control plane for AI agents")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--db", default=DEFAULT_DB)
    s.add_argument("--host", default=os.environ.get("AGENTGOV_HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=int(os.environ.get("AGENTGOV_PORT", "8080")))

    sd = sub.add_parser("seed", help="load the default policy and a synthetic demo organisation")
    sd.add_argument("--db", default=DEFAULT_DB)
    sd.add_argument("--keys-out", default=".agentgov-demo-keys.json")

    sub.add_parser("demo", help="run the scripted end-to-end scenario in memory and print the results")

    v = sub.add_parser("verify-audit", help="recompute the audit hash chain")
    v.add_argument("--db", default=DEFAULT_DB)

    c = sub.add_parser("check-policy", help="validate a policy file without loading it")
    c.add_argument("file", type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn

        from .api import create_app

        logging.basicConfig(level=logging.INFO, format="%(message)s")
        service = build_service(args.db)
        key = bootstrap(service)
        if key:
            print(f"Bootstrap admin key (shown once): {key}", file=sys.stderr)
        uvicorn.run(create_app(service), host=args.host, port=args.port, log_level="warning")
        return 0

    if args.cmd == "seed":
        service = build_service(args.db)
        keys = seed_demo(service)
        out = Path(args.keys_out)
        out.write_text(json.dumps(keys, indent=2))
        out.chmod(0o600)
        print(f"Seeded demo organisation. API keys written to {out} (mode 600). They are synthetic demo keys.")
        return 0

    if args.cmd == "demo":
        from .demo import run_demo

        return run_demo()

    if args.cmd == "verify-audit":
        result = build_service(args.db).store.verify_audit()
        print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 2

    if args.cmd == "check-policy":
        try:
            pol = parse_policy(args.file.read_text(encoding="utf-8"))
        except PolicyError as exc:
            print(f"invalid: {exc}", file=sys.stderr)
            return 2
        print(f"valid: version {pol.version}, {len(pol.rules)} rules, default {pol.default_effect.value}, sha256 {pol.sha256[:12]}")
        return 0

    return 1  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
