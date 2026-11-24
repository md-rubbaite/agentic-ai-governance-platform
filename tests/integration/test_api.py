from __future__ import annotations

import json
import stat

import pytest
from fastapi.testclient import TestClient

from agentgov.api import create_app
from agentgov.cli import bootstrap, main
from agentgov.sdk import ActionDenied, ApprovalPending, GovernanceClient


@pytest.fixture
def api(seeded):
    service, keys = seeded
    return TestClient(create_app(service)), keys, service


def H(keys, who):
    return {"x-api-key": keys[who]}


def test_health_ready_metrics_dashboard(api):
    client, keys, _ = api
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["schema_version"] == 1
    client.post(
        "/v1/decisions",
        json={"agent_id": "procurement-agent", "tool": "crm.export", "action": "read"},
        headers=H(keys, "procurement-agent"),
    )
    m = client.get("/metrics").text
    assert 'agentgov_decisions_total{effect="deny"} 1' in m and "agentgov_audit_entries" in m
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Agent <span>Governance</span> Console" in page.text
    r = client.get("/healthz", headers={"x-request-id": "abc"})
    assert r.headers["x-request-id"] == "abc" and r.headers["x-content-type-options"] == "nosniff"


def test_readyz_without_policy():
    from agentgov.service import GovernanceService
    from agentgov.store import Store

    client = TestClient(create_app(GovernanceService(Store())))
    assert client.get("/readyz").status_code == 503


def test_auth_and_validation_errors(api):
    client, keys, _ = api
    assert client.get("/v1/agents").status_code == 403
    assert client.get("/v1/agents", headers={"x-api-key": "bad"}).status_code == 403
    bad = client.post(
        "/v1/decisions", json={"agent_id": "procurement-agent", "tool": "bad tool!", "action": "read"}, headers=H(keys, "procurement-agent")
    )
    assert bad.status_code == 422
    neg = client.post(
        "/v1/decisions",
        json={"agent_id": "procurement-agent", "tool": "erp.payments", "action": "payment", "amount": -5},
        headers=H(keys, "procurement-agent"),
    )
    assert neg.status_code == 422
    assert client.get("/v1/overview", headers=H(keys, "procurement-agent")).status_code == 403
    assert client.get("/v1/decisions/dec_nope", headers=H(keys, "admin")).status_code == 404


def test_full_approval_flow_over_http(api):
    client, keys, _ = api
    d = client.post(
        "/v1/decisions",
        json={"agent_id": "procurement-agent", "tool": "erp.payments", "action": "payment", "amount": 3000, "justification": "INV-9"},
        headers=H(keys, "procurement-agent"),
    ).json()
    assert d["effect"] == "require_approval" and d["risk"]["factors"]["amount"] == 20
    pending = client.get("/v1/approvals?status=pending", headers=H(keys, "reviewer-a")).json()
    assert [a["id"] for a in pending] == [d["approval_id"]] and pending[0]["decision"]["amount"] == 3000
    r = client.post(
        f"/v1/approvals/{d['approval_id']}/vote", json={"verdict": "approve", "comment": "fine by me"}, headers=H(keys, "finance-lead")
    )
    assert r.status_code == 403
    r = client.post(
        f"/v1/approvals/{d['approval_id']}/vote", json={"verdict": "approve", "comment": "PO-1 ok"}, headers=H(keys, "reviewer-a")
    )
    assert r.json()["status"] == "approved"
    got = client.get(f"/v1/decisions/{d['id']}", headers=H(keys, "procurement-agent")).json()
    assert got["effect"] == "allow"
    done = client.post(f"/v1/decisions/{d['id']}/outcome", json={"outcome": "executed"}, headers=H(keys, "procurement-agent")).json()
    assert done["status"] == "executed"
    events = [e["event"] for e in client.get(f"/v1/audit?subject={d['id']}", headers=H(keys, "auditor")).json()]
    assert events == ["decision.require_approval", "outcome.executed"]
    assert client.get("/v1/audit/verify", headers=H(keys, "auditor")).json()["valid"] is True
    assert client.get("/v1/audit/verify", headers=H(keys, "reviewer-a")).status_code == 403


def test_agents_only_see_their_own_data(api):
    client, keys, _ = api
    hr = client.post(
        "/v1/decisions",
        json={"agent_id": "hr-screening-agent", "tool": "ats.applications.read", "action": "read"},
        headers=H(keys, "hr-screening-agent"),
    ).json()
    assert client.get(f"/v1/decisions/{hr['id']}", headers=H(keys, "procurement-agent")).status_code == 403
    assert [a["id"] for a in client.get("/v1/agents", headers=H(keys, "procurement-agent")).json()] == ["procurement-agent"]
    assert all(d["agent_id"] == "procurement-agent" for d in client.get("/v1/decisions", headers=H(keys, "procurement-agent")).json())
    assert client.get("/v1/policy", headers=H(keys, "procurement-agent")).json()["history"] == []


def test_policy_endpoints(api, policy_text):
    client, keys, _ = api
    assert client.get("/v1/policy", headers=H(keys, "auditor")).json()["version"] == "2026-11-24.1"
    sim = client.post(
        "/v1/policy/simulate",
        json={"agent_id": "procurement-agent", "tool": "erp.payments", "action": "payment", "amount": 50000},
        headers=H(keys, "reviewer-a"),
    )
    assert sim.json()["dry_run"] is True and sim.json()["matched_rule"] == "two-reviewers-for-large-payments"
    assert client.put("/v1/policy", content="version = ", headers=H(keys, "admin")).status_code == 422
    r = client.put("/v1/policy", content=policy_text.replace("2026-11-24.1", "2026-11-25.1"), headers=H(keys, "admin"))
    assert r.status_code == 200 and r.json()["version"] == "2026-11-25.1"


def test_principals_and_agents_endpoints(api):
    client, keys, _ = api
    r = client.post("/v1/principals", json={"id": "ops", "name": "Ops", "role": "reviewer"}, headers=H(keys, "admin"))
    assert r.status_code == 201 and r.json()["api_key"].startswith("agk_")
    assert client.get("/v1/whoami", headers={"x-api-key": r.json()["api_key"]}).json()["role"] == "reviewer"
    body = {
        "id": "ops-agent",
        "name": "Ops",
        "owner": "ops",
        "purpose": "Restarts failed batch jobs.",
        "autonomy": "supervised",
        "allowed_tools": ["batch.*"],
        "daily_action_limit": 10,
        "daily_spend_limit": 0,
    }
    assert client.post("/v1/agents", json=body, headers=H(keys, "admin")).status_code == 201
    assert client.post("/v1/agents", json=body | {"id": "Bad Id"}, headers=H(keys, "admin")).status_code == 422
    s = client.post("/v1/agents/ops-agent/suspend", json={"reason": "maintenance"}, headers=H(keys, "reviewer-a"))
    assert s.json()["status"] == "suspended"
    assert client.post("/v1/agents/ops-agent/resume", json={"reason": "done now"}, headers=H(keys, "admin")).json()["status"] == "active"
    ov = client.get("/v1/overview", headers=H(keys, "auditor")).json()
    assert ov["agents"] == 3 and ov["policy_version"] == "2026-11-24.1"


def test_sdk_decorator(api):
    client, keys, _ = api
    gov = GovernanceClient("http://testserver", keys["procurement-agent"], "procurement-agent", http=client)
    calls = []

    @gov.governed(tool="erp.payments", action="payment", amount=lambda a: a["amount"])
    def pay(supplier: str, amount: float) -> str:
        calls.append(amount)
        return "ok"

    @gov.governed(tool="crm.export", action="read")
    def export() -> None:
        calls.append("export")

    @gov.governed(tool="erp.orders.create", action="write")
    def boom() -> None:
        raise RuntimeError("downstream failed")

    assert pay("SUP-1", 100) == "ok" and calls == [100]
    with pytest.raises(ApprovalPending) as pending:
        pay("SUP-2", 5000)
    with pytest.raises(ActionDenied):
        export()
    with pytest.raises(RuntimeError):
        boom()
    statuses = {d["tool"]: d["status"] for d in client.get("/v1/decisions", headers=H(keys, "admin")).json()}
    assert statuses["erp.orders.create"] == "failed"
    assert pending.value.decision["approval_id"].startswith("apr_")
    assert calls == [100]
    assert gov.wait_for_approval(pending.value.decision["id"], timeout=0)["status"] == "pending_approval"


def test_cli_demo_and_check_policy(tmp_path, capsys, policy_text):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "INVALID" in out and "kill switch" in out and "four-eyes" in out
    good = tmp_path / "p.toml"
    good.write_text(policy_text)
    assert main(["check-policy", str(good)]) == 0
    bad = tmp_path / "bad.toml"
    bad.write_text('version = "x"\n[[rules]]\nid = "a"\neffect = "sometimes"')
    assert main(["check-policy", str(bad)]) == 2


def test_cli_seed_and_verify(tmp_path, capsys):
    db = str(tmp_path / "g.db")
    keys_file = tmp_path / "keys.json"
    assert main(["seed", "--db", db, "--keys-out", str(keys_file)]) == 0
    assert stat.S_IMODE(keys_file.stat().st_mode) == 0o600
    assert set(json.loads(keys_file.read_text())) >= {"admin", "reviewer-a", "procurement-agent"}
    assert main(["verify-audit", "--db", db]) == 0
    assert '"valid": true' in capsys.readouterr().out


def test_bootstrap_with_env_key(tmp_path, monkeypatch):
    from agentgov.service import GovernanceService
    from agentgov.store import Store

    monkeypatch.setenv("AGENTGOV_BOOTSTRAP_ADMIN_KEY", "x" * 32)
    svc = GovernanceService(Store(str(tmp_path / "b.db")))
    assert bootstrap(svc) is None
    assert svc.authenticate("x" * 32).role.value == "admin"
    assert svc.policy.version == "2026-11-24.1"
    assert bootstrap(svc) is None  # second start: nothing to do
    monkeypatch.delenv("AGENTGOV_BOOTSTRAP_ADMIN_KEY")
    svc2 = GovernanceService(Store(str(tmp_path / "c.db")))
    assert bootstrap(svc2).startswith("agk_")
