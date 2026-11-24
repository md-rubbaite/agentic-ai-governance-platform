"""Client SDK for agents.

Wrap any tool function so that it only runs after the control plane allows it::

    gov = GovernanceClient("http://localhost:8080", api_key=os.environ["AGENTGOV_KEY"], agent_id="procurement-agent")

    @gov.governed(tool="erp.payments", action="payment", data_classification="confidential",
                  amount=lambda args: args["amount"])
    def pay_supplier(supplier_id: str, amount: float, reference: str) -> str:
        ...

Calling ``pay_supplier`` asks the control plane first. On ``allow`` the function runs and
the outcome is reported; on ``deny`` a ``ActionDenied`` is raised; on ``require_approval``
an ``ApprovalPending`` is raised that carries the decision id, so the agent can tell the
user and poll later with ``wait_for_approval``.
"""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Callable
from typing import Any

import httpx


class ActionDenied(Exception):
    def __init__(self, decision: dict[str, Any]) -> None:
        super().__init__(f"denied: {'; '.join(decision.get('reasons', [])[:2])}")
        self.decision = decision


class ApprovalPending(Exception):
    def __init__(self, decision: dict[str, Any]) -> None:
        super().__init__(f"waiting for approval {decision.get('approval_id')} (decision {decision.get('id')})")
        self.decision = decision


class GovernanceClient:
    def __init__(self, base_url: str, api_key: str, agent_id: str, *, http: httpx.Client | None = None, timeout: float = 10.0) -> None:
        self.agent_id = agent_id
        self._http = http or httpx.Client(base_url=base_url, timeout=timeout)
        self._headers = {"x-api-key": api_key}

    def request(
        self,
        tool: str,
        action: str,
        arguments: dict[str, Any],
        *,
        data_classification: str = "internal",
        amount: float | None = None,
        justification: str = "",
    ) -> dict[str, Any]:
        body = {
            "agent_id": self.agent_id,
            "tool": tool,
            "action": action,
            "arguments": arguments,
            "data_classification": data_classification,
            "amount": amount,
            "justification": justification,
        }
        r = self._http.post("/v1/decisions", json=body, headers=self._headers)
        r.raise_for_status()
        return r.json()

    def get(self, decision_id: str) -> dict[str, Any]:
        r = self._http.get(f"/v1/decisions/{decision_id}", headers=self._headers)
        r.raise_for_status()
        return r.json()

    def report(self, decision_id: str, outcome: str, detail: str = "") -> dict[str, Any]:
        r = self._http.post(f"/v1/decisions/{decision_id}/outcome", json={"outcome": outcome, "detail": detail}, headers=self._headers)
        r.raise_for_status()
        return r.json()

    def wait_for_approval(self, decision_id: str, *, timeout: float = 60.0, interval: float = 2.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            d = self.get(decision_id)
            if d["status"] != "pending_approval" or time.monotonic() >= deadline:
                return d
            time.sleep(interval)

    def governed(
        self,
        *,
        tool: str,
        action: str,
        data_classification: str = "internal",
        amount: Callable[[dict[str, Any]], float | None] | None = None,
        justification: Callable[[dict[str, Any]], str] | None = None,
    ):
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
                decision = self.request(
                    tool,
                    action,
                    arguments,
                    data_classification=data_classification,
                    amount=amount(arguments) if amount else None,
                    justification=justification(arguments) if justification else "",
                )
                if decision["effect"] == "deny":
                    raise ActionDenied(decision)
                if decision["effect"] == "require_approval":
                    raise ApprovalPending(decision)
                return self.execute_allowed(decision, fn, *args, **kwargs)

            return wrapper

        return decorator

    def execute_allowed(self, decision: dict[str, Any], fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run ``fn`` for a decision that is allowed (directly or after approval) and report the outcome."""
        if decision["effect"] != "allow":
            raise ActionDenied(decision)
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            self.report(decision["id"], "failed", f"{type(exc).__name__}")
            raise
        self.report(decision["id"], "executed")
        return result
