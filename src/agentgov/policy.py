"""Declarative, versioned policy: ordered rules, first match wins, default deny.

Policies are TOML documents. Example::

    version = "2026-11-24.1"
    default_effect = "deny"

    [[rules]]
    id = "large-payments-need-two-reviewers"
    effect = "require_approval"
    approver_role = "reviewer"
    approvals = 2
    [rules.when]
    action = ["payment"]
    amount_gt = 10000

Every condition inside ``when`` must hold for a rule to match. A rule with an empty
``when`` matches everything, which is how a policy can end with an explicit catch-all.
"""

from __future__ import annotations

import fnmatch
import hashlib
import tomllib
from dataclasses import dataclass, field
from typing import Any

from .models import Effect, Role

_LIST_CONDITIONS = {
    "tool",  # glob patterns, e.g. "erp.*"
    "action",
    "data_classification",
    "autonomy",
    "eu_ai_act_risk",
    "risk_tier",
    "flags_any",
    "agent",
}
_NUMERIC_CONDITIONS = {"min_risk", "amount_gt", "amount_lte"}
_ALLOWED_RULE_KEYS = {"id", "description", "effect", "approver_role", "approvals", "expires_minutes", "when"}


class PolicyError(ValueError):
    """Raised when a policy document is invalid. Invalid policies are never activated."""


@dataclass(slots=True, frozen=True)
class Rule:
    id: str
    effect: Effect
    when: dict[str, Any]
    description: str = ""
    approver_role: Role = Role.REVIEWER
    approvals: int = 1
    expires_minutes: int = 60


@dataclass(slots=True, frozen=True)
class Policy:
    version: str
    default_effect: Effect
    rules: tuple[Rule, ...]
    sha256: str
    source: str
    risk_overrides: dict[str, dict[str, int]] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class Facts:
    """Everything a rule may test. Built by the service for each action request."""

    agent: str
    tool: str
    action: str
    data_classification: str
    autonomy: str
    eu_ai_act_risk: str
    risk_score: int
    risk_tier: str
    flags: frozenset[str]
    amount: float | None


@dataclass(slots=True, frozen=True)
class PolicyResult:
    effect: Effect
    rule: Rule | None
    reason: str


def parse_policy(text: str) -> Policy:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy is not valid TOML: {exc}") from exc

    version = doc.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PolicyError("policy must have a non-empty string 'version'")

    default_effect = _effect(doc.get("default_effect", "deny"), "default_effect")
    if default_effect is Effect.REQUIRE_APPROVAL:
        raise PolicyError("default_effect must be 'allow' or 'deny'")

    raw_rules = doc.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be an array of tables ([[rules]])")

    rules: list[Rule] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule #{i + 1} must be a table")
        unknown = set(raw) - _ALLOWED_RULE_KEYS
        if unknown:
            raise PolicyError(f"rule #{i + 1}: unknown keys {sorted(unknown)}")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid:
            raise PolicyError(f"rule #{i + 1}: 'id' is required")
        if rid in seen:
            raise PolicyError(f"duplicate rule id '{rid}'")
        seen.add(rid)
        effect = _effect(raw.get("effect"), f"rule '{rid}' effect")
        when = raw.get("when", {})
        if not isinstance(when, dict):
            raise PolicyError(f"rule '{rid}': 'when' must be a table")
        _validate_when(rid, when)
        approvals = raw.get("approvals", 1)
        if not isinstance(approvals, int) or not 1 <= approvals <= 5:
            raise PolicyError(f"rule '{rid}': 'approvals' must be an integer from 1 to 5")
        expires = raw.get("expires_minutes", 60)
        if not isinstance(expires, int) or not 1 <= expires <= 7 * 24 * 60:
            raise PolicyError(f"rule '{rid}': 'expires_minutes' must be 1..10080")
        try:
            approver_role = Role(raw.get("approver_role", "reviewer"))
        except ValueError as exc:
            raise PolicyError(f"rule '{rid}': unknown approver_role") from exc
        if approver_role in (Role.AGENT, Role.AUDITOR):
            raise PolicyError(f"rule '{rid}': approver_role must be 'reviewer' or 'admin'")
        rules.append(
            Rule(
                id=rid,
                effect=effect,
                when=when,
                description=str(raw.get("description", "")),
                approver_role=approver_role,
                approvals=approvals,
                expires_minutes=expires,
            )
        )

    risk_overrides = doc.get("risk", {})
    if not isinstance(risk_overrides, dict) or not all(
        isinstance(v, dict) and all(isinstance(w, int) and 0 <= w <= 100 for w in v.values()) for v in risk_overrides.values()
    ):
        raise PolicyError("[risk] must contain tables of integer weights between 0 and 100")

    return Policy(
        version=version.strip(),
        default_effect=default_effect,
        rules=tuple(rules),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        source=text,
        risk_overrides=risk_overrides,
    )


def evaluate(policy: Policy, facts: Facts) -> PolicyResult:
    for rule in policy.rules:
        if _matches(rule.when, facts):
            return PolicyResult(rule.effect, rule, f"rule '{rule.id}' matched")
    return PolicyResult(policy.default_effect, None, f"no rule matched; default_effect={policy.default_effect.value}")


def _effect(value: Any, where: str) -> Effect:
    try:
        return Effect(value)
    except ValueError as exc:
        raise PolicyError(f"{where}: must be one of allow, deny, require_approval") from exc


def _validate_when(rid: str, when: dict[str, Any]) -> None:
    for key, value in when.items():
        if key in _LIST_CONDITIONS:
            if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
                raise PolicyError(f"rule '{rid}': condition '{key}' must be a non-empty list of strings")
        elif key in _NUMERIC_CONDITIONS:
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise PolicyError(f"rule '{rid}': condition '{key}' must be a number")
        else:
            raise PolicyError(f"rule '{rid}': unknown condition '{key}'")


def _matches(when: dict[str, Any], f: Facts) -> bool:
    for key, value in when.items():
        if key == "tool":
            if not any(fnmatch.fnmatchcase(f.tool, pattern) for pattern in value):
                return False
        elif key == "action":
            if f.action not in value:
                return False
        elif key == "data_classification":
            if f.data_classification not in value:
                return False
        elif key == "autonomy":
            if f.autonomy not in value:
                return False
        elif key == "eu_ai_act_risk":
            if f.eu_ai_act_risk not in value:
                return False
        elif key == "risk_tier":
            if f.risk_tier not in value:
                return False
        elif key == "flags_any":
            if not f.flags.intersection(value):
                return False
        elif key == "agent":
            if f.agent not in value:
                return False
        elif key == "min_risk":
            if f.risk_score < value:
                return False
        elif key == "amount_gt":
            if f.amount is None or f.amount <= value:
                return False
        elif key == "amount_lte" and (f.amount is None or f.amount > value):
            return False
    return True
