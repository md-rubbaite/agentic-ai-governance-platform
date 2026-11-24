"""The governance service: the single place where decisions are made.

Order of checks for an action request (each step can end the evaluation):

1. The caller must be an agent principal bound to the agent it claims to be.
2. The agent must be registered and active (kill switch).
3. The tool must be on the agent's allow-list.
4. Arguments are inspected (injection, secrets, personal data) and redacted for audit.
5. Daily action and spend budgets must not be exceeded.
6. The risk score is computed from transparent factors.
7. The active policy is evaluated (first match wins, default deny).

The decision, the redacted arguments and the reasons are written to the hash-chained
audit log in the same transaction as the decision itself.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any

from . import guards, risk
from .models import (
    ActionRequest,
    Agent,
    AgentStatus,
    Approval,
    ApprovalStatus,
    Autonomy,
    Decision,
    DecisionStatus,
    Effect,
    Principal,
    RiskAssessment,
    Role,
)
from .policy import Facts, Policy, PolicyError, evaluate, parse_policy
from .store import Store


class GovernanceError(Exception):
    status = 400


class NotFound(GovernanceError):
    status = 404


class Forbidden(GovernanceError):
    status = 403


class Conflict(GovernanceError):
    status = 409


class Invalid(GovernanceError):
    status = 422


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_key() -> str:
    return "agk_" + secrets.token_urlsafe(32)


Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class GovernanceService:
    def __init__(self, store: Store, clock: Clock = _utcnow) -> None:
        self.store = store
        self.clock = clock
        self._policy: Policy | None = None
        source = store.active_policy_source()
        if source:
            self._policy = parse_policy(source)

    # ---- helpers --------------------------------------------------------------------
    def _now(self) -> str:
        return self.clock().astimezone(UTC).isoformat(timespec="seconds")

    def _today(self) -> str:
        return self.clock().astimezone(UTC).date().isoformat()

    @property
    def policy(self) -> Policy:
        if self._policy is None:
            raise Conflict("no active policy; load one with PUT /v1/policy or `agentgov seed`")
        return self._policy

    # ---- principals -----------------------------------------------------------------
    def authenticate(self, key: str | None) -> Principal:
        if not key:
            raise Forbidden("missing API key")
        principal = self.store.principal_by_key_hash(hash_key(key))
        if principal is None or not principal.active:
            raise Forbidden("invalid API key")
        return principal

    def create_principal(
        self, actor: Principal | None, pid: str, name: str, role: Role, agent_id: str | None = None, key: str | None = None
    ) -> tuple[Principal, str]:
        if actor is not None:
            _require(actor, Role.ADMIN)
        if self.store.get_principal(pid):
            raise Conflict(f"principal '{pid}' already exists")
        if role is Role.AGENT and not agent_id:
            raise Invalid("agent principals must be bound to an agent_id")
        if role is not Role.AGENT and agent_id:
            raise Invalid("only agent principals can be bound to an agent_id")
        if agent_id and not self.store.get_agent(agent_id):
            raise NotFound(f"agent '{agent_id}' not found")
        if key is not None and len(key) < 24:
            raise Invalid("API keys must be at least 24 characters")
        key = key or new_key()
        principal = Principal(id=pid, name=name, role=role, key_hash=hash_key(key), agent_id=agent_id)
        self.store.add_principal(principal)
        self.store.append_audit(
            self._now(), actor.id if actor else "bootstrap", "principal.created", pid, {"role": role.value, "agent_id": agent_id}
        )
        return principal, key

    # ---- agents ---------------------------------------------------------------------
    def register_agent(self, actor: Principal, agent: Agent) -> Agent:
        _require(actor, Role.ADMIN)
        if self.store.get_agent(agent.id):
            raise Conflict(f"agent '{agent.id}' already exists")
        owner = self.store.get_principal(agent.owner)
        if owner is None or owner.role is Role.AGENT:
            raise Invalid("agent owner must be an existing human principal (admin, reviewer or auditor)")
        if not agent.allowed_tools:
            raise Invalid("allowed_tools must not be empty; agents are deny-by-default")
        if agent.daily_action_limit < 1 or agent.daily_spend_limit < 0:
            raise Invalid("daily_action_limit must be >= 1 and daily_spend_limit >= 0")
        if agent.eu_ai_act_risk not in ("minimal", "limited", "high"):
            raise Invalid("eu_ai_act_risk must be minimal, limited or high")
        agent.created_at = self._now()
        agent.status = AgentStatus.ACTIVE
        self.store.add_agent(agent)
        data = asdict(agent) | {"autonomy": agent.autonomy.value, "status": agent.status.value}
        self.store.append_audit(self._now(), actor.id, "agent.registered", agent.id, data)
        return agent

    def set_agent_status(self, actor: Principal, agent_id: str, status: AgentStatus, reason: str) -> Agent:
        _require(actor, Role.ADMIN, Role.REVIEWER)
        agent = self._agent(agent_id)
        if status is AgentStatus.ACTIVE and actor.role is not Role.ADMIN:
            raise Forbidden("only an admin can resume a suspended agent")
        if not reason.strip():
            raise Invalid("a reason is required")
        with self.store.transaction() as c:
            c.execute("UPDATE agents SET status = ? WHERE id = ?", (status.value, agent_id))
            event = "agent.suspended" if status is AgentStatus.SUSPENDED else "agent.resumed"
            self.store.append_audit(self._now(), actor.id, event, agent_id, {"reason": reason}, conn=c)
            if status is AgentStatus.SUSPENDED:
                for approval in self.store.list_approvals(ApprovalStatus.PENDING.value):
                    if approval.agent_id == agent_id:
                        self._close_approval(c, approval, ApprovalStatus.REJECTED, actor.id, "agent suspended")
        agent.status = status
        return agent

    def _agent(self, agent_id: str) -> Agent:
        agent = self.store.get_agent(agent_id)
        if agent is None:
            raise NotFound(f"agent '{agent_id}' not found")
        return agent

    # ---- policy ---------------------------------------------------------------------
    def load_policy(self, actor: Principal | None, text: str) -> Policy:
        if actor is not None:
            _require(actor, Role.ADMIN)
        try:
            policy = parse_policy(text)
        except PolicyError as exc:
            raise Invalid(str(exc)) from exc
        try:
            self.store.save_policy(policy.version, policy.sha256, text, self._now(), actor.id if actor else "bootstrap")
        except ValueError as exc:
            raise Conflict(str(exc)) from exc
        self.store.append_audit(
            self._now(),
            actor.id if actor else "bootstrap",
            "policy.activated",
            policy.version,
            {"sha256": policy.sha256, "rules": [r.id for r in policy.rules]},
        )
        self._policy = policy
        return policy

    # ---- decisions ------------------------------------------------------------------
    def decide(self, actor: Principal, req: ActionRequest, *, dry_run: bool = False) -> Decision:
        if not dry_run:
            _require(actor, Role.AGENT)
            if actor.agent_id != req.agent_id:
                raise Forbidden(f"this key may only act as agent '{actor.agent_id}'")
        else:
            _require(actor, Role.ADMIN, Role.REVIEWER)

        agent = self._agent(req.agent_id)
        policy = self.policy
        report = guards.inspect(req.arguments, req.justification)
        reasons: list[str] = list(report.findings)
        assessment = risk.assess(
            action=req.action,
            data_classification=req.data_classification.value,
            autonomy=agent.autonomy.value,
            eu_ai_act_risk=agent.eu_ai_act_risk,
            flags=report.flags,
            amount=req.amount,
            overrides=policy.risk_overrides,
        )

        effect: Effect
        matched: str | None = None
        rule = None
        hard_stop = self._hard_stop(agent, req)
        if hard_stop:
            effect = Effect.DENY
            reasons.insert(0, hard_stop)
        else:
            facts = Facts(
                agent=agent.id,
                tool=req.tool,
                action=req.action,
                data_classification=req.data_classification.value,
                autonomy=agent.autonomy.value,
                eu_ai_act_risk=agent.eu_ai_act_risk,
                risk_score=assessment.score,
                risk_tier=assessment.tier,
                flags=report.flags,
                amount=req.amount,
            )
            result = evaluate(policy, facts)
            effect, rule = result.effect, result.rule
            matched = rule.id if rule else None
            reasons.insert(0, result.reason)

        decision = Decision(
            id="dec_" + uuid.uuid4().hex[:20],
            agent_id=agent.id,
            tool=req.tool,
            action=req.action,
            effect=effect,
            status=DecisionStatus.PENDING_APPROVAL if effect is Effect.REQUIRE_APPROVAL else DecisionStatus.DECIDED,
            reasons=reasons,
            risk=assessment,
            policy_version=policy.version,
            matched_rule=matched,
            approval_id=None,
            created_at=self._now(),
            data_classification=req.data_classification,
            amount=req.amount,
            flags=sorted(report.flags),
            arguments_redacted=report.redacted,
        )
        if dry_run:
            return decision

        with self.store.transaction() as c:
            if effect is Effect.REQUIRE_APPROVAL and rule is not None:
                created = self.clock()
                approval = Approval(
                    id="apr_" + uuid.uuid4().hex[:20],
                    decision_id=decision.id,
                    agent_id=agent.id,
                    required_role=rule.approver_role,
                    required_approvals=rule.approvals,
                    status=ApprovalStatus.PENDING,
                    created_at=self._now(),
                    expires_at=(created + timedelta(minutes=rule.expires_minutes)).astimezone(UTC).isoformat(timespec="seconds"),
                )
                decision.approval_id = approval.id
                self.store.save_approval(approval, conn=c)
            if effect is Effect.ALLOW:
                self.store.add_usage(agent.id, self._today(), req.amount or 0.0, c)
            self.store.save_decision(decision, conn=c)
            self.store.append_audit(
                decision.created_at,
                actor.id,
                f"decision.{effect.value}",
                decision.id,
                {
                    "agent_id": agent.id,
                    "tool": req.tool,
                    "action": req.action,
                    "data_classification": req.data_classification.value,
                    "amount": req.amount,
                    "arguments": report.redacted,
                    "justification": guards.inspect({"j": req.justification}).redacted["j"],
                    "risk": {"score": assessment.score, "tier": assessment.tier, "factors": assessment.factors},
                    "policy_version": policy.version,
                    "matched_rule": matched,
                    "reasons": reasons,
                    "approval_id": decision.approval_id,
                },
                conn=c,
            )
        return decision

    def _hard_stop(self, agent: Agent, req: ActionRequest) -> str | None:
        """Checks that no policy can override."""
        if agent.status is not AgentStatus.ACTIVE:
            return "agent is suspended (kill switch)"
        if not any(_tool_allowed(req.tool, pattern) for pattern in agent.allowed_tools):
            return f"tool '{req.tool}' is not on the agent's allow-list"
        actions, spend = self.store.usage(agent.id, self._today())
        if actions + 1 > agent.daily_action_limit:
            return f"daily action limit reached ({agent.daily_action_limit})"
        if req.amount and spend + req.amount > agent.daily_spend_limit:
            return f"daily spend limit would be exceeded ({spend + req.amount:.2f} > {agent.daily_spend_limit:.2f})"
        return None

    def get_decision(self, actor: Principal, decision_id: str) -> Decision:
        decision = self.store.get_decision(decision_id)
        if decision is None:
            raise NotFound(f"decision '{decision_id}' not found")
        if actor.role is Role.AGENT and actor.agent_id != decision.agent_id:
            raise Forbidden("agents can only read their own decisions")
        if decision.status is DecisionStatus.PENDING_APPROVAL and decision.approval_id:
            self.expire_due()
            decision = self.store.get_decision(decision_id) or decision
        return decision

    def report_outcome(self, actor: Principal, decision_id: str, outcome: str, detail: str = "") -> Decision:
        _require(actor, Role.AGENT)
        decision = self.store.get_decision(decision_id)
        if decision is None:
            raise NotFound(f"decision '{decision_id}' not found")
        if actor.agent_id != decision.agent_id:
            raise Forbidden("agents can only report outcomes for their own decisions")
        if decision.effect is not Effect.ALLOW or decision.status not in (DecisionStatus.DECIDED, DecisionStatus.APPROVED):
            raise Conflict("outcomes can only be reported for allowed or approved actions that were not yet reported")
        if outcome not in ("executed", "failed"):
            raise Invalid("outcome must be 'executed' or 'failed'")
        decision.status = DecisionStatus.EXECUTED if outcome == "executed" else DecisionStatus.FAILED
        redacted = guards.inspect({"d": detail}).redacted["d"]
        with self.store.transaction() as c:
            self.store.save_decision(decision, conn=c)
            self.store.append_audit(self._now(), actor.id, f"outcome.{outcome}", decision_id, {"detail": redacted}, conn=c)
        return decision

    # ---- approvals ------------------------------------------------------------------
    def vote(self, actor: Principal, approval_id: str, verdict: str, comment: str) -> Approval:
        _require(actor, Role.REVIEWER, Role.ADMIN)
        self.expire_due()
        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise NotFound(f"approval '{approval_id}' not found")
        if approval.status is not ApprovalStatus.PENDING:
            raise Conflict(f"approval is already {approval.status.value}")
        if approval.required_role is Role.ADMIN and actor.role is not Role.ADMIN:
            raise Forbidden("this approval requires an admin")
        agent = self._agent(approval.agent_id)
        if agent.owner == actor.id:
            raise Forbidden("separation of duties: the agent's owner cannot approve its actions")
        if any(v["principal"] == actor.id for v in approval.votes):
            raise Conflict("this principal has already voted")
        if verdict not in ("approve", "reject"):
            raise Invalid("verdict must be 'approve' or 'reject'")
        if not comment.strip():
            raise Invalid("a comment is required for every approval decision")

        approval.votes.append({"principal": actor.id, "verdict": verdict, "comment": comment, "at": self._now()})
        with self.store.transaction() as c:
            self.store.append_audit(
                self._now(),
                actor.id,
                f"approval.vote.{verdict}",
                approval.id,
                {"comment": comment, "decision_id": approval.decision_id},
                conn=c,
            )
            if verdict == "reject":
                self._close_approval(c, approval, ApprovalStatus.REJECTED, actor.id, comment)
            elif sum(v["verdict"] == "approve" for v in approval.votes) >= approval.required_approvals:
                self._close_approval(c, approval, ApprovalStatus.APPROVED, actor.id, comment)
            else:
                self.store.save_approval(approval, conn=c)
        return approval

    def _close_approval(self, c, approval: Approval, status: ApprovalStatus, actor_id: str, reason: str) -> None:
        approval.status = status
        self.store.save_approval(approval, conn=c)
        decision = self.store.get_decision(approval.decision_id)
        if decision is None:  # pragma: no cover - referential integrity
            return
        if status is ApprovalStatus.APPROVED:
            agent = self._agent(decision.agent_id)
            stop = self._hard_stop(agent, ActionRequest(agent.id, decision.tool, decision.action, amount=decision.amount))
            if stop:
                # Budgets or the kill switch may have changed while the request waited.
                decision.effect, decision.status = Effect.DENY, DecisionStatus.REJECTED
                decision.reasons.append(f"approved, but denied at execution time: {stop}")
                approval.status = ApprovalStatus.REJECTED
                self.store.save_approval(approval, conn=c)
            else:
                decision.effect, decision.status = Effect.ALLOW, DecisionStatus.APPROVED
                decision.reasons.append(f"approved by {', '.join(v['principal'] for v in approval.votes if v['verdict'] == 'approve')}")
                self.store.add_usage(decision.agent_id, self._today(), decision.amount or 0.0, c)
        elif status is ApprovalStatus.REJECTED:
            decision.effect, decision.status = Effect.DENY, DecisionStatus.REJECTED
            decision.reasons.append(f"rejected: {reason}")
        else:
            decision.effect, decision.status = Effect.DENY, DecisionStatus.EXPIRED
            decision.reasons.append("approval expired without a decision")
        self.store.save_decision(decision, conn=c)
        self.store.append_audit(
            self._now(),
            actor_id,
            f"approval.{approval.status.value}",
            approval.id,
            {"decision_id": decision.id, "effect": decision.effect.value},
            conn=c,
        )

    def expire_due(self) -> int:
        now = self._now()
        expired = [a for a in self.store.list_approvals(ApprovalStatus.PENDING.value) if a.expires_at <= now]
        if expired:
            with self.store.transaction() as c:
                for a in expired:
                    self._close_approval(c, a, ApprovalStatus.EXPIRED, "system", "expired")
        return len(expired)

    def list_approvals(self, actor: Principal, status: str | None) -> list[Approval]:
        _require(actor, Role.REVIEWER, Role.ADMIN, Role.AUDITOR)
        self.expire_due()
        return self.store.list_approvals(status)

    # ---- audit ----------------------------------------------------------------------
    def audit(self, actor: Principal, subject: str | None, limit: int, after_seq: int) -> list[dict[str, Any]]:
        _require(actor, Role.AUDITOR, Role.ADMIN, Role.REVIEWER)
        return self.store.audit_entries(subject, min(max(limit, 1), 500), after_seq)

    def verify_audit(self, actor: Principal) -> dict[str, Any]:
        _require(actor, Role.AUDITOR, Role.ADMIN)
        return self.store.verify_audit()


def _require(actor: Principal, *roles: Role) -> None:
    if actor.role not in roles:
        raise Forbidden(f"role '{actor.role.value}' is not allowed to do this (needs {', '.join(r.value for r in roles)})")


def _tool_allowed(tool: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(tool, pattern)


def risk_to_dict(r: RiskAssessment) -> dict[str, Any]:
    return {"score": r.score, "tier": r.tier, "factors": r.factors}


__all__ = [
    "GovernanceService",
    "GovernanceError",
    "NotFound",
    "Forbidden",
    "Conflict",
    "Invalid",
    "Autonomy",
    "hash_key",
    "new_key",
]
