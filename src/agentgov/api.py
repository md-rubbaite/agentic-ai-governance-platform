"""HTTP API (FastAPI). Thin layer: validation, authentication and error mapping only."""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict
from importlib import resources
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .models import ActionRequest, Agent, AgentStatus, Approval, Autonomy, DataClass, Decision, Principal, Role
from .service import Forbidden, GovernanceError, GovernanceService, risk_to_dict

log = logging.getLogger("agentgov")


# ---- request bodies -----------------------------------------------------------------
class ActionIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:\-]+$")
    action: str = Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    data_classification: DataClass = DataClass.INTERNAL
    amount: float | None = Field(default=None, ge=0, le=1e12)
    justification: str = Field(default="", max_length=2000)


class AgentIn(BaseModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9\-]*$")
    name: str = Field(min_length=1, max_length=120)
    owner: str = Field(min_length=1, max_length=64)
    purpose: str = Field(min_length=10, max_length=1000)
    autonomy: Autonomy
    allowed_tools: list[str] = Field(min_length=1, max_length=100)
    daily_action_limit: int = Field(ge=1, le=1_000_000)
    daily_spend_limit: float = Field(ge=0, le=1e12)
    eu_ai_act_risk: Literal["minimal", "limited", "high"] = "minimal"


class PrincipalIn(BaseModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9\-]*$")
    name: str = Field(min_length=1, max_length=120)
    role: Role
    agent_id: str | None = None


class StatusIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class VoteIn(BaseModel):
    verdict: Literal["approve", "reject"]
    comment: str = Field(min_length=3, max_length=1000)


class OutcomeIn(BaseModel):
    outcome: Literal["executed", "failed"]
    detail: str = Field(default="", max_length=2000)


# ---- serialisers --------------------------------------------------------------------
def decision_out(d: Decision) -> dict[str, Any]:
    return {
        "id": d.id,
        "agent_id": d.agent_id,
        "tool": d.tool,
        "action": d.action,
        "effect": d.effect.value,
        "status": d.status.value,
        "reasons": d.reasons,
        "risk": risk_to_dict(d.risk),
        "policy_version": d.policy_version,
        "matched_rule": d.matched_rule,
        "approval_id": d.approval_id,
        "created_at": d.created_at,
        "data_classification": d.data_classification.value,
        "amount": d.amount,
        "flags": d.flags,
        "arguments_redacted": d.arguments_redacted,
    }


def approval_out(a: Approval) -> dict[str, Any]:
    return asdict(a) | {"required_role": a.required_role.value, "status": a.status.value}


def agent_out(a: Agent) -> dict[str, Any]:
    return asdict(a) | {"autonomy": a.autonomy.value, "status": a.status.value}


def create_app(service: GovernanceService) -> FastAPI:
    app = FastAPI(
        title="Agentic AI Governance Platform",
        version=__version__,
        description="Policy enforcement, risk scoring, human approval gates and a tamper-evident audit log for AI agents.",
    )

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        start = time.perf_counter()
        response = await call_next(request)
        ms = round((time.perf_counter() - start) * 1000, 1)
        response.headers["x-request-id"] = rid
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["cache-control"] = "no-store"
        log.info(json.dumps({"rid": rid, "method": request.method, "path": request.url.path, "status": response.status_code, "ms": ms}))
        return response

    @app.exception_handler(GovernanceError)
    async def governance_error(_: Request, exc: GovernanceError):
        return JSONResponse({"error": type(exc).__name__, "detail": str(exc)}, status_code=exc.status)

    def principal(x_api_key: str | None = Header(default=None)) -> Principal:
        return service.authenticate(x_api_key)

    # ---- operations -----------------------------------------------------------------
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        ok = service.store.ping() and service._policy is not None
        body = {
            "status": "ready" if ok else "not_ready",
            "schema_version": service.store.schema_version,
            "policy_loaded": service._policy is not None,
        }
        return JSONResponse(body, status_code=200 if ok else 503)

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        c = service.store.counts()
        lines = ["# HELP agentgov_decisions_total Decisions by current effect.", "# TYPE agentgov_decisions_total gauge"]
        for effect in ("allow", "deny", "require_approval"):
            lines.append(f'agentgov_decisions_total{{effect="{effect}"}} {c["decisions"].get(effect, 0)}')
        lines += [
            "# TYPE agentgov_approvals_pending gauge",
            f"agentgov_approvals_pending {c['approvals_pending']}",
            "# TYPE agentgov_audit_entries gauge",
            f"agentgov_audit_entries {c['audit_entries']}",
            "# TYPE agentgov_agents_suspended gauge",
            f"agentgov_agents_suspended {c['agents_suspended']}",
        ]
        return "\n".join(lines) + "\n"

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        return resources.files("agentgov").joinpath("dashboard/index.html").read_text(encoding="utf-8")

    # ---- principals & agents --------------------------------------------------------
    @app.post("/v1/principals", status_code=201)
    def create_principal(body: PrincipalIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        created, key = service.create_principal(p, body.id, body.name, body.role, body.agent_id)
        return {
            "id": created.id,
            "role": created.role.value,
            "agent_id": created.agent_id,
            "api_key": key,
            "note": "store this key now; it is not shown again",
        }

    @app.get("/v1/whoami")
    def whoami(p: Principal = Depends(principal)) -> dict[str, Any]:
        return {"id": p.id, "name": p.name, "role": p.role.value, "agent_id": p.agent_id}

    @app.get("/v1/overview")
    def overview(p: Principal = Depends(principal)) -> dict[str, Any]:
        if p.role is Role.AGENT:
            raise Forbidden("agents cannot read the overview")
        return service.store.counts() | {"policy_version": service._policy.version if service._policy else None}

    @app.post("/v1/agents", status_code=201)
    def register_agent(body: AgentIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        agent = Agent(**body.model_dump())
        return agent_out(service.register_agent(p, agent))

    @app.get("/v1/agents")
    def list_agents(p: Principal = Depends(principal)) -> list[dict[str, Any]]:
        if p.role is Role.AGENT:
            agent = service.store.get_agent(p.agent_id or "")
            return [agent_out(agent)] if agent else []
        return [agent_out(a) for a in service.store.list_agents()]

    @app.post("/v1/agents/{agent_id}/suspend")
    def suspend(agent_id: str, body: StatusIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        return agent_out(service.set_agent_status(p, agent_id, AgentStatus.SUSPENDED, body.reason))

    @app.post("/v1/agents/{agent_id}/resume")
    def resume(agent_id: str, body: StatusIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        return agent_out(service.set_agent_status(p, agent_id, AgentStatus.ACTIVE, body.reason))

    # ---- policy ---------------------------------------------------------------------
    @app.get("/v1/policy")
    def get_policy(p: Principal = Depends(principal)) -> dict[str, Any]:
        pol = service.policy
        return {
            "version": pol.version,
            "sha256": pol.sha256,
            "default_effect": pol.default_effect.value,
            "rules": [{"id": r.id, "effect": r.effect.value, "description": r.description, "when": r.when} for r in pol.rules],
            "history": service.store.policy_history() if p.role is not Role.AGENT else [],
        }

    @app.put("/v1/policy")
    async def put_policy(request: Request, p: Principal = Depends(principal)) -> dict[str, Any]:
        text = (await request.body()).decode("utf-8")
        pol = service.load_policy(p, text)
        return {"version": pol.version, "sha256": pol.sha256, "rules": len(pol.rules)}

    @app.post("/v1/policy/simulate")
    def simulate(body: ActionIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        d = service.decide(p, ActionRequest(**body.model_dump()), dry_run=True)
        return decision_out(d) | {"dry_run": True}

    # ---- decisions ------------------------------------------------------------------
    @app.post("/v1/decisions", status_code=201)
    def decide(body: ActionIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        return decision_out(service.decide(p, ActionRequest(**body.model_dump())))

    @app.get("/v1/decisions")
    def list_decisions(
        agent_id: str | None = None, limit: int = Query(50, ge=1, le=500), p: Principal = Depends(principal)
    ) -> list[dict[str, Any]]:
        if p.role is Role.AGENT:
            agent_id = p.agent_id
        return [decision_out(d) for d in service.store.list_decisions(agent_id, limit)]

    @app.get("/v1/decisions/{decision_id}")
    def get_decision(decision_id: str, p: Principal = Depends(principal)) -> dict[str, Any]:
        return decision_out(service.get_decision(p, decision_id))

    @app.post("/v1/decisions/{decision_id}/outcome")
    def outcome(decision_id: str, body: OutcomeIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        return decision_out(service.report_outcome(p, decision_id, body.outcome, body.detail))

    # ---- approvals ------------------------------------------------------------------
    @app.get("/v1/approvals")
    def approvals(
        status: Literal["pending", "approved", "rejected", "expired"] | None = None, p: Principal = Depends(principal)
    ) -> list[dict[str, Any]]:
        out = []
        for a in service.list_approvals(p, status):
            d = service.store.get_decision(a.decision_id)
            out.append(approval_out(a) | {"decision": decision_out(d) if d else None})
        return out

    @app.post("/v1/approvals/{approval_id}/vote")
    def vote(approval_id: str, body: VoteIn, p: Principal = Depends(principal)) -> dict[str, Any]:
        return approval_out(service.vote(p, approval_id, body.verdict, body.comment))

    # ---- audit ----------------------------------------------------------------------
    @app.get("/v1/audit")
    def audit(
        subject: str | None = None,
        limit: int = Query(100, ge=1, le=500),
        after_seq: int = Query(0, ge=0),
        p: Principal = Depends(principal),
    ) -> list[dict[str, Any]]:
        return service.audit(p, subject, limit, after_seq)

    @app.get("/v1/audit/verify")
    def verify(p: Principal = Depends(principal)) -> dict[str, Any]:
        return service.verify_audit(p)

    return app
