"""Domain types shared by the service, the store and the HTTP API."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Role(StrEnum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"
    AGENT = "agent"


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Autonomy(StrEnum):
    """How much the agent acts without a human in the loop."""

    ASSISTIVE = "assistive"  # proposes, a human executes
    SUPERVISED = "supervised"  # executes, a human can intervene
    AUTONOMOUS = "autonomous"  # executes without routine human review


class AgentStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class DecisionStatus(StrEnum):
    DECIDED = "decided"  # final effect known (allow / deny)
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(slots=True)
class Principal:
    id: str
    name: str
    role: Role
    key_hash: str
    agent_id: str | None = None  # set for role=agent: the agent this key may act as
    active: bool = True


@dataclass(slots=True)
class Agent:
    id: str
    name: str
    owner: str  # principal id of the accountable human owner
    purpose: str
    autonomy: Autonomy
    allowed_tools: list[str]
    daily_action_limit: int
    daily_spend_limit: float
    eu_ai_act_risk: str = "minimal"  # minimal | limited | high (as classified by the deployer)
    status: AgentStatus = AgentStatus.ACTIVE
    created_at: str = ""


@dataclass(slots=True)
class ActionRequest:
    agent_id: str
    tool: str
    action: str
    arguments: dict[str, Any] = field(default_factory=dict)
    data_classification: DataClass = DataClass.INTERNAL
    amount: float | None = None
    justification: str = ""


@dataclass(slots=True)
class RiskAssessment:
    score: int
    tier: str
    factors: dict[str, int]


@dataclass(slots=True)
class Decision:
    id: str
    agent_id: str
    tool: str
    action: str
    effect: Effect
    status: DecisionStatus
    reasons: list[str]
    risk: RiskAssessment
    policy_version: str
    matched_rule: str | None
    approval_id: str | None
    created_at: str
    data_classification: DataClass = DataClass.INTERNAL
    amount: float | None = None
    flags: list[str] = field(default_factory=list)
    arguments_redacted: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Approval:
    id: str
    decision_id: str
    agent_id: str
    required_role: Role
    required_approvals: int
    status: ApprovalStatus
    created_at: str
    expires_at: str
    votes: list[dict[str, str]] = field(default_factory=list)
