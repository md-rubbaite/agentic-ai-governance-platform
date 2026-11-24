from __future__ import annotations

from datetime import timedelta

import pytest

from agentgov.models import ActionRequest, Agent, AgentStatus, Autonomy, DataClass, Effect, Role
from agentgov.service import Conflict, Forbidden, Invalid, NotFound


def principal(service, key):
    return service.authenticate(key)


def req(**kw) -> ActionRequest:
    base = dict(agent_id="procurement-agent", tool="erp.suppliers.read", action="read", arguments={"id": "SUP-1"})
    base.update(kw)
    return ActionRequest(**base)


@pytest.fixture
def ctx(seeded):
    service, keys = seeded
    return service, {k: service.authenticate(v) for k, v in keys.items()}


def test_authentication(seeded):
    service, keys = seeded
    assert service.authenticate(keys["auditor"]).role is Role.AUDITOR
    with pytest.raises(Forbidden):
        service.authenticate("nope")
    with pytest.raises(Forbidden):
        service.authenticate(None)


def test_keys_are_stored_hashed(seeded):
    service, keys = seeded
    raw = keys["admin"]
    stored = [p.key_hash for p in service.store.list_principals()]
    assert raw not in stored and all(len(h) == 64 for h in stored)


def test_low_risk_read_is_allowed_and_counted(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req())
    assert d.effect is Effect.ALLOW and d.matched_rule == "allow-low-and-medium-risk"
    assert service.store.usage("procurement-agent", "2026-11-24") == (1, 0.0)


def test_agent_key_cannot_act_as_another_agent(ctx):
    service, p = ctx
    with pytest.raises(Forbidden):
        service.decide(p["procurement-agent"], req(agent_id="hr-screening-agent", tool="ats.applications.read"))


def test_humans_cannot_submit_decisions_but_can_simulate(ctx):
    service, p = ctx
    with pytest.raises(Forbidden):
        service.decide(p["reviewer-a"], req())
    before = service.store.verify_audit()["entries"]
    d = service.decide(p["reviewer-a"], req(), dry_run=True)
    assert d.effect is Effect.ALLOW
    assert service.store.verify_audit()["entries"] == before  # dry runs are not audited
    with pytest.raises(Forbidden):
        service.decide(p["auditor"], req(), dry_run=True)


def test_allow_list_is_a_hard_stop(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req(tool="crm.export"))
    assert d.effect is Effect.DENY and "allow-list" in d.reasons[0] and d.matched_rule is None


def test_glob_allow_list(ctx):
    service, p = ctx
    assert service.decide(p["procurement-agent"], req(tool="erp.orders.list")).effect is Effect.ALLOW


def test_secret_is_denied_and_redacted_in_audit(ctx):
    service, p = ctx
    d = service.decide(
        p["procurement-agent"], req(tool="email.send", action="external_communication", arguments={"body": "AKIAABCDEFGHIJKLMNOP"})
    )
    assert d.effect is Effect.DENY and d.matched_rule == "deny-secrets-in-arguments"
    dump = str(service.store.audit_entries(d.id))
    assert "AKIAABCDEFGHIJKLMNOP" not in dump and "REDACTED" in dump


def test_payment_thresholds(ctx):
    service, p = ctx
    small = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=400))
    mid = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=4000))
    big = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=20000))
    assert small.effect is Effect.ALLOW
    assert mid.effect is Effect.REQUIRE_APPROVAL and mid.matched_rule == "review-payments-over-1000"
    assert big.matched_rule == "two-reviewers-for-large-payments"
    assert service.store.get_approval(big.approval_id).required_approvals == 2


def test_spend_limit_and_action_limit(ctx):
    service, p = ctx
    admin = p["admin"]
    service.register_agent(
        admin,
        Agent(
            id="tiny",
            name="Tiny",
            owner="finance-lead",
            purpose="Budget test agent with small limits.",
            autonomy=Autonomy.SUPERVISED,
            allowed_tools=["t.*"],
            daily_action_limit=2,
            daily_spend_limit=100,
        ),
    )
    _, key = service.create_principal(admin, "tiny-key", "tiny", Role.AGENT, "tiny")
    tiny = service.authenticate(key)
    r = ActionRequest(agent_id="tiny", tool="t.pay", action="payment", amount=80)
    assert service.decide(tiny, r).effect is Effect.ALLOW
    over = service.decide(tiny, ActionRequest(agent_id="tiny", tool="t.pay", action="payment", amount=30))
    assert over.effect is Effect.DENY and "spend limit" in over.reasons[0]
    service.decide(tiny, ActionRequest(agent_id="tiny", tool="t.read", action="read"))
    third = service.decide(tiny, ActionRequest(agent_id="tiny", tool="t.read", action="read"))
    assert third.effect is Effect.DENY and "action limit" in third.reasons[0]


def test_budgets_reset_daily(ctx, clock):
    service, p = ctx
    service.store.add_usage("procurement-agent", "2026-11-24", 49_900, service.store._conn)
    d = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=500))
    assert d.effect is Effect.DENY
    clock.now += timedelta(days=1)
    assert service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=500)).effect is Effect.ALLOW


def test_separation_of_duties_single_vote_and_comment(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=5000))
    with pytest.raises(Forbidden, match="separation of duties"):
        service.vote(p["finance-lead"], d.approval_id, "approve", "mine")
    with pytest.raises(Forbidden):
        service.vote(p["auditor"], d.approval_id, "approve", "x")
    with pytest.raises(Invalid):
        service.vote(p["reviewer-a"], d.approval_id, "approve", "  ")
    a = service.vote(p["reviewer-a"], d.approval_id, "approve", "PO matches")
    assert a.status.value == "approved"
    after = service.store.get_decision(d.id)
    assert after.effect is Effect.ALLOW and after.status.value == "approved"
    assert service.store.usage("procurement-agent", "2026-11-24") == (1, 5000.0)
    with pytest.raises(Conflict):
        service.vote(p["reviewer-b"], d.approval_id, "approve", "late")


def test_four_eyes_and_double_vote(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=20000))
    service.vote(p["reviewer-a"], d.approval_id, "approve", "ok")
    assert service.store.get_decision(d.id).status.value == "pending_approval"
    with pytest.raises(Conflict, match="already voted"):
        service.vote(p["reviewer-a"], d.approval_id, "approve", "again")
    service.vote(p["reviewer-b"], d.approval_id, "approve", "ok too")
    assert service.store.get_decision(d.id).effect is Effect.ALLOW


def test_reject_closes_immediately(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=20000))
    service.vote(p["reviewer-a"], d.approval_id, "reject", "no contract")
    dec = service.store.get_decision(d.id)
    assert dec.effect is Effect.DENY and dec.status.value == "rejected"
    assert service.store.usage("procurement-agent", "2026-11-24") == (0, 0.0)


def test_admin_only_approval(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req(tool="erp.orders.acl", action="change_permissions"))
    assert d.matched_rule == "admin-approval-for-permission-changes"
    with pytest.raises(Forbidden, match="requires an admin"):
        service.vote(p["reviewer-a"], d.approval_id, "approve", "ok")
    service.vote(p["admin"], d.approval_id, "approve", "ticket CHG-7")
    assert service.store.get_decision(d.id).effect is Effect.ALLOW


def test_expiry_denies(ctx, clock):
    service, p = ctx
    d = service.decide(p["hr-screening-agent"], ActionRequest(agent_id="hr-screening-agent", tool="ats.notes.write", action="write"))
    assert d.matched_rule == "human-oversight-for-high-risk-systems"
    clock.now += timedelta(minutes=61)
    got = service.get_decision(p["hr-screening-agent"], d.id)
    assert got.effect is Effect.DENY and got.status.value == "expired"
    with pytest.raises(Conflict):
        service.vote(p["reviewer-a"], d.approval_id, "approve", "too late")


def test_kill_switch(ctx):
    service, p = ctx
    pending = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=5000))
    with pytest.raises(Forbidden):
        service.set_agent_status(p["auditor"], "procurement-agent", AgentStatus.SUSPENDED, "x")
    with pytest.raises(Invalid):
        service.set_agent_status(p["reviewer-a"], "procurement-agent", AgentStatus.SUSPENDED, " ")
    service.set_agent_status(p["reviewer-a"], "procurement-agent", AgentStatus.SUSPENDED, "incident INC-4")
    assert service.store.get_decision(pending.id).status.value == "rejected"  # pending approvals are closed
    d = service.decide(p["procurement-agent"], req())
    assert d.effect is Effect.DENY and "kill switch" in d.reasons[0]
    with pytest.raises(Forbidden, match="only an admin"):
        service.set_agent_status(p["reviewer-a"], "procurement-agent", AgentStatus.ACTIVE, "done")
    service.set_agent_status(p["admin"], "procurement-agent", AgentStatus.ACTIVE, "incident closed")
    assert service.decide(p["procurement-agent"], req()).effect is Effect.ALLOW


def test_approval_rechecks_hard_stops(ctx):
    service, p = ctx
    d = service.decide(p["procurement-agent"], req(tool="erp.payments", action="payment", amount=20000))
    service.vote(p["reviewer-a"], d.approval_id, "approve", "ok")
    service.store.add_usage("procurement-agent", "2026-11-24", 45_000, service.store._conn)  # budget consumed meanwhile
    service.vote(p["reviewer-b"], d.approval_id, "approve", "ok")
    dec = service.store.get_decision(d.id)
    assert dec.effect is Effect.DENY and "denied at execution time" in dec.reasons[-1]


def test_outcome_reporting_rules(ctx):
    service, p = ctx
    allowed = service.decide(p["procurement-agent"], req())
    denied = service.decide(p["procurement-agent"], req(tool="crm.export"))
    with pytest.raises(Conflict):
        service.report_outcome(p["procurement-agent"], denied.id, "executed")
    with pytest.raises(Invalid):
        service.report_outcome(p["procurement-agent"], allowed.id, "maybe")
    done = service.report_outcome(p["procurement-agent"], allowed.id, "executed", "sent to jane@example.com")
    assert done.status.value == "executed"
    with pytest.raises(Conflict):
        service.report_outcome(p["procurement-agent"], allowed.id, "executed")
    assert "jane@example.com" not in str(service.store.audit_entries(allowed.id))
    with pytest.raises(NotFound):
        service.report_outcome(p["procurement-agent"], "dec_missing", "executed")


def test_agent_registration_rules(ctx):
    service, p = ctx
    good = dict(
        id="x",
        name="X",
        owner="finance-lead",
        purpose="A test agent with a purpose.",
        autonomy=Autonomy.ASSISTIVE,
        allowed_tools=["a"],
        daily_action_limit=1,
        daily_spend_limit=0,
    )
    with pytest.raises(Forbidden):
        service.register_agent(p["reviewer-a"], Agent(**good))
    with pytest.raises(Invalid, match="owner"):
        service.register_agent(p["admin"], Agent(**(good | {"owner": "procurement-agent-key"})))
    with pytest.raises(Invalid, match="allowed_tools"):
        service.register_agent(p["admin"], Agent(**(good | {"allowed_tools": []})))
    with pytest.raises(Invalid, match="eu_ai_act_risk"):
        service.register_agent(p["admin"], Agent(**(good | {"eu_ai_act_risk": "unacceptable"})))
    service.register_agent(p["admin"], Agent(**good))
    with pytest.raises(Conflict):
        service.register_agent(p["admin"], Agent(**good))


def test_principal_rules(ctx):
    service, p = ctx
    with pytest.raises(Invalid):
        service.create_principal(p["admin"], "a1", "a", Role.AGENT)
    with pytest.raises(Invalid):
        service.create_principal(p["admin"], "r1", "r", Role.REVIEWER, "procurement-agent")
    with pytest.raises(NotFound):
        service.create_principal(p["admin"], "a2", "a", Role.AGENT, "ghost")
    with pytest.raises(Conflict):
        service.create_principal(p["admin"], "auditor", "dup", Role.AUDITOR)
    with pytest.raises(Invalid):
        service.create_principal(None, "short", "s", Role.ADMIN, key="too-short")


def test_policy_versions_are_immutable(ctx, policy_text):
    service, p = ctx
    with pytest.raises(Conflict, match="already exists"):
        service.load_policy(p["admin"], policy_text)
    with pytest.raises(Invalid):
        service.load_policy(p["admin"], 'version = "x"\ndefault_effect = "maybe"')
    with pytest.raises(Forbidden):
        service.load_policy(p["reviewer-a"], policy_text.replace("2026-11-24.1", "2026-11-24.2"))
    new = service.load_policy(p["admin"], policy_text.replace("2026-11-24.1", "2026-11-24.2"))
    assert service.policy.version == new.version
    history = service.store.policy_history()
    assert [h["active"] for h in history] == [False, True]


def test_service_without_policy(service):
    with pytest.raises(Conflict, match="no active policy"):
        _ = service.policy


def test_policy_survives_restart(tmp_path, clock, policy_text):
    from agentgov.service import GovernanceService
    from agentgov.store import Store

    db = str(tmp_path / "g.db")
    GovernanceService(Store(db), clock=clock).load_policy(None, policy_text)
    assert GovernanceService(Store(db), clock=clock).policy.version == "2026-11-24.1"


def test_restricted_data_blocked_for_autonomous_agents(ctx):
    service, p = ctx
    service.register_agent(
        p["admin"],
        Agent(
            id="auto",
            name="Auto",
            owner="finance-lead",
            purpose="Autonomous reporting agent for tests.",
            autonomy=Autonomy.AUTONOMOUS,
            allowed_tools=["dw.*"],
            daily_action_limit=10,
            daily_spend_limit=0,
        ),
    )
    _, key = service.create_principal(p["admin"], "auto-key", "auto", Role.AGENT, "auto")
    d = service.decide(
        service.authenticate(key), ActionRequest(agent_id="auto", tool="dw.query", action="read", data_classification=DataClass.RESTRICTED)
    )
    assert d.matched_rule == "deny-restricted-data-for-autonomous-agents"
