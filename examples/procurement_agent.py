"""Minimal agent integration against a running control plane.

    agentgov seed && agentgov serve           # terminal 1
    python examples/procurement_agent.py      # terminal 2

Uses the synthetic demo keys written by `agentgov seed`. The "ERP" here is a stub.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentgov.sdk import ActionDenied, ApprovalPending, GovernanceClient

keys = json.loads(Path(".agentgov-demo-keys.json").read_text())
gov = GovernanceClient("http://127.0.0.1:8080", api_key=keys["procurement-agent"], agent_id="procurement-agent")


@gov.governed(tool="erp.payments", action="payment", amount=lambda a: a["amount"], justification=lambda a: a["reference"])
def pay_supplier(supplier_id: str, amount: float, reference: str) -> str:
    return f"(stub) paid {amount:.2f} to {supplier_id} for {reference}"


for supplier, amount, ref in [("SUP-104", 320.0, "INV-1001"), ("SUP-221", 7_500.0, "INV-1002")]:
    try:
        print(pay_supplier(supplier, amount, ref))
    except ApprovalPending as pending:
        print(f"{ref}: waiting for a reviewer -> open http://127.0.0.1:8080/dashboard ({pending.decision['approval_id']})")
    except ActionDenied as denied:
        print(f"{ref}: denied -> {denied.decision['reasons'][0]}")
