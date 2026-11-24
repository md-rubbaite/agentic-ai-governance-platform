from __future__ import annotations

import pytest

from agentgov.models import Effect, Role
from agentgov.policy import Facts, PolicyError, evaluate, parse_policy


def facts(**kw) -> Facts:
    base = dict(
        agent="a1",
        tool="erp.payments",
        action="payment",
        data_classification="internal",
        autonomy="supervised",
        eu_ai_act_risk="minimal",
        risk_score=30,
        risk_tier="medium",
        flags=frozenset(),
        amount=None,
    )
    base.update(kw)
    return Facts(**base)


def test_default_policy_parses(policy_text):
    p = parse_policy(policy_text)
    assert p.version == "2026-11-24.1"
    assert p.default_effect is Effect.DENY
    assert [r.id for r in p.rules][0] == "deny-secrets-in-arguments"
    assert len(p.sha256) == 64


def test_first_match_wins_and_default_applies():
    p = parse_policy(
        """
        version = "t1"
        default_effect = "deny"
        [[rules]]
        id = "big"
        effect = "require_approval"
        approvals = 2
        [rules.when]
        amount_gt = 100
        [[rules]]
        id = "payments"
        effect = "allow"
        [rules.when]
        action = ["payment"]
        """
    )
    r = evaluate(p, facts(amount=500))
    assert r.effect is Effect.REQUIRE_APPROVAL and r.rule.id == "big" and r.rule.approvals == 2
    assert evaluate(p, facts(amount=50)).rule.id == "payments"
    none = evaluate(p, facts(action="read"))
    assert none.effect is Effect.DENY and none.rule is None


@pytest.mark.parametrize(
    "when, f, expected",
    [
        ({"tool": ["erp.*"]}, {}, True),
        ({"tool": ["crm.*"]}, {}, False),
        ({"data_classification": ["restricted"]}, {"data_classification": "restricted"}, True),
        ({"autonomy": ["autonomous"]}, {}, False),
        ({"eu_ai_act_risk": ["high"]}, {"eu_ai_act_risk": "high"}, True),
        ({"risk_tier": ["high", "critical"]}, {"risk_tier": "critical"}, True),
        ({"flags_any": ["secret", "pii"]}, {"flags": frozenset({"pii"})}, True),
        ({"flags_any": ["secret"]}, {"flags": frozenset({"pii"})}, False),
        ({"agent": ["a2"]}, {}, False),
        ({"min_risk": 50}, {"risk_score": 50}, True),
        ({"min_risk": 51}, {"risk_score": 50}, False),
        ({"amount_gt": 100}, {"amount": None}, False),
        ({"amount_lte": 100}, {"amount": 100}, True),
        ({"amount_lte": 100}, {"amount": 100.01}, False),
        ({}, {}, True),
    ],
)
def test_conditions(when, f, expected):
    lines = ["[rules.when]"] + [f"{k} = {v!r}".replace("'", '"') for k, v in when.items()]
    p = parse_policy('version = "v"\n[[rules]]\nid = "r"\neffect = "allow"\n' + "\n".join(lines))
    assert (evaluate(p, facts(**f)).rule is not None) is expected


@pytest.mark.parametrize(
    "doc, message",
    [
        ("not toml = = =", "not valid TOML"),
        ('default_effect = "deny"', "version"),
        ('version = "v"\ndefault_effect = "require_approval"', "default_effect"),
        ('version = "v"\n[[rules]]\neffect = "allow"', "'id' is required"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "maybe"', "must be one of"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "allow"\n[[rules]]\nid = "a"\neffect = "deny"', "duplicate"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "allow"\n[rules.when]\ncolour = ["red"]', "unknown condition"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "allow"\n[rules.when]\naction = "payment"', "non-empty list"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "allow"\n[rules.when]\nmin_risk = "high"', "must be a number"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "require_approval"\napprovals = 9', "approvals"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "require_approval"\napprover_role = "agent"', "approver_role"),
        ('version = "v"\n[[rules]]\nid = "a"\neffect = "allow"\nnotes = "x"', "unknown keys"),
        ('version = "v"\n[risk.action]\npayment = 500', "[risk]"),
    ],
)
def test_invalid_policies_are_rejected(doc, message):
    with pytest.raises(PolicyError, match=message.replace("[", r"\[").replace("]", r"\]")):
        parse_policy(doc)


def test_admin_approver_role_is_kept():
    p = parse_policy('version = "v"\n[[rules]]\nid = "a"\neffect = "require_approval"\napprover_role = "admin"')
    assert p.rules[0].approver_role is Role.ADMIN
