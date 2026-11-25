<p align="center"><img src="assets/banner.svg" alt="Agentic AI Governance Platform: agents ask before they act" width="100%"></p>

# Agentic AI Governance Platform

[![ci](https://github.com/md-rubbaite/agentic-ai-governance-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/md-rubbaite/agentic-ai-governance-platform/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-1f2b46)
![license](https://img.shields.io/badge/license-MIT-1f2b46)

A governance control plane for autonomous AI agents. Before an agent calls a tool that moves
money, sends email, changes records or grants access, it asks this service. The answer comes
from **policy, budgets and people**, not from the model: `allow`, `deny` or
`require_approval`. Every request, approval and outcome goes into a **tamper-evident audit log**.

It targets the failure modes OWASP lists as **LLM06:2025 Excessive Agency** and
**LLM01:2025 Prompt Injection**, and produces the oversight and record-keeping evidence that
the **EU AI Act** (Art. 12, 14, 26) and **NIST AI RMF** ask for.

## What it does

| Control | How |
|---|---|
| **Agent registry** | Each agent has an accountable human owner, a purpose, an autonomy level, an EU AI Act risk class, a tool allow-list and daily budgets |
| **Hard stops** | Kill switch, tool allow-list, daily action and spend limits. No policy can override them |
| **Argument guards** | Prompt-injection markers, credentials (AWS, GitHub, API keys, private keys, passwords) and personal data are flagged; the audit log stores a redacted copy |
| **Risk scoring** | Transparent additive score (action, data class, autonomy, EU AI Act class, amount, flags) with every factor returned to the reviewer |
| **Policy engine** | Versioned TOML rules, first match wins, **default deny**, strict validation, dry-run simulation |
| **Human approval** | Approval gates by role, four-eyes rules, mandatory comments, expiry, separation of duties (an agent's owner cannot approve it), re-check of budgets at approval time |
| **Audit** | SHA-256 hash chain written in the same transaction as each decision; `verify` names the first tampered entry |
| **Operations** | Governance console, OpenAPI, Prometheus metrics, health/readiness, JSON access logs, non-root read-only container |

## Quick start

```bash
pip install -e ".[dev]"
agentgov demo                 # scripted end-to-end scenario, in memory, synthetic data
```

```text
Agentic AI Governance Platform - scripted demo (synthetic data)

1 read supplier record             allow (decided)                     allow-low-and-medium-risk
2 pay 450.00                       allow (decided)                     executed via SDK; outcome reported
3 pay 4,800.00                     require_approval (pending_approval)  review-payments-over-1000
3a owner tries to approve          HTTP 403                            separation of duties: the agent's owner cannot approve its actions
3b after reviewer-a approves       allow (executed)                    executed after approval
4 pay 25,000.00                    require_approval (pending_approval)  two-reviewers-for-large-payments
4a same reviewer votes twice       HTTP 409                            this principal has already voted
4b after reviewer-b approves       allow (approved)                    four-eyes rule satisfied
5 email with injected instruction  require_approval (pending_approval)  injection, pii
5a reviewer rejects                deny (rejected)                     review-suspected-injection
6 email containing an AWS key      deny (decided)                      deny-secrets-in-arguments; stored as key [REDACTED:aws_access_key]
7 tool not on allow-list           deny (decided)                      tool 'crm.export' is not on the agent's allow-list
8 high-risk system writes a note   require_approval (pending_approval)  human-oversight-for-high-risk-systems
8a 61 minutes later                deny (expired)                      approval expired -> deny
9 any action after suspension      deny (decided)                      agent is suspended (kill switch)
10 auditor verifies audit chain    valid                               30 entries
10a after editing one audit row    INVALID                             first invalid entry: #18

Payments actually executed: SUP-104:450.00, SUP-221:4800.00
```

Run the service and the console:

```bash
agentgov seed      # default policy + synthetic demo organisation; keys in .agentgov-demo-keys.json (mode 600)
agentgov serve     # http://127.0.0.1:8080/dashboard  ·  OpenAPI at /docs
python examples/procurement_agent.py
```

Or in a container: `cp .env.example .env`, set a key, `docker compose up -d --build`.

<p align="center"><img src="assets/console-approvals.png" alt="Governance console: approvals waiting for a reviewer, with risk score, matched rule and redacted arguments (synthetic demo data)" width="100%"></p>
<p align="center"><sub>Governance console with the synthetic demo organisation. Arguments are shown redacted; the email address was replaced before storage.</sub></p>

## Integrating an agent

```python
from agentgov.sdk import ApprovalPending, ActionDenied, GovernanceClient

gov = GovernanceClient("https://governance.internal", api_key=AGENT_KEY, agent_id="procurement-agent")

@gov.governed(tool="erp.payments", action="payment", amount=lambda a: a["amount"],
              justification=lambda a: a["reference"])
def pay_supplier(supplier_id: str, amount: float, reference: str) -> str:
    return erp.pay(supplier_id, amount, reference)

try:
    pay_supplier("SUP-221", 4800, "INV-2026-0388")   # runs only on allow; outcome is reported
except ApprovalPending as p:
    tell_user(f"Sent for approval ({p.decision['approval_id']})")
except ActionDenied as d:
    tell_user(d.decision["reasons"][0])
```

If the control plane is unreachable the SDK raises and the tool is not called (fail closed).

## Policy

Policies are short, reviewable TOML. The [reference policy](src/agentgov/default_policy.toml)
has nine rules; an excerpt:

```toml
version = "2026-11-24.1"
default_effect = "deny"

[[rules]]
id = "deny-secrets-in-arguments"
effect = "deny"
[rules.when]
flags_any = ["secret"]

[[rules]]
id = "two-reviewers-for-large-payments"
effect = "require_approval"
approver_role = "reviewer"
approvals = 2
expires_minutes = 240
[rules.when]
action = ["payment"]
amount_gt = 10000
```

Conditions: `tool` (globs), `action`, `data_classification`, `autonomy`, `eu_ai_act_risk`,
`risk_tier`, `min_risk`, `flags_any`, `amount_gt`, `amount_lte`, `agent`. Unknown keys are
errors. `agentgov check-policy file.toml` validates in CI; `POST /v1/policy/simulate` shows
what a request would get without recording it. Versions are immutable and every activation is
audited with its SHA-256.

## API

| Method | Path | Role |
|---|---|---|
| POST | `/v1/decisions` | agent (bound to its own `agent_id`) |
| GET | `/v1/decisions/{id}` · POST `/v1/decisions/{id}/outcome` | agent, humans |
| GET | `/v1/approvals?status=pending` · POST `/v1/approvals/{id}/vote` | reviewer, admin |
| POST | `/v1/agents` · `/v1/agents/{id}/suspend` · `/resume` | admin (reviewers may suspend) |
| GET/PUT | `/v1/policy` · POST `/v1/policy/simulate` | admin (PUT), reviewer (simulate) |
| GET | `/v1/audit` · `/v1/audit/verify` | auditor, admin |
| POST | `/v1/principals` | admin; returns the key once, stores only its hash |
| GET | `/healthz` · `/readyz` · `/metrics` · `/dashboard` · `/docs` | – |

## Architecture

```mermaid
flowchart LR
    agent[AI agent + SDK] -- "may I?" --> api[HTTP API]
    console[Governance console] --> api
    api --> svc[Governance service]
    svc --> hs{hard stops<br/>kill switch · allow-list · budgets}
    svc --> g[guards] --> r[risk score] --> p[policy<br/>default deny]
    svc --> db[(SQLite: decisions, approvals,<br/>hash-chained audit)]
    agent -- "only if allowed" --> tools[business systems]
```

The control plane never calls business systems and holds no business credentials
([ADR 0001](docs/adr/0001-control-plane-not-proxy.md)). Details:
[architecture](docs/architecture/overview.md) (C4, sequence, trust boundaries, failure modes) ·
[threat model](docs/security/threat-model.md) (STRIDE) ·
[EU AI Act and NIST AI RMF mapping](docs/eu-ai-act-mapping.md) ·
[deployment](docs/deployment.md) · ADRs [0002 SQLite first](docs/adr/0002-sqlite-first.md),
[0003 policy format](docs/adr/0003-own-policy-format.md),
[0004 audit chain](docs/adr/0004-hash-chained-audit.md).

## Quality and verification

- **102 tests** (unit and HTTP integration): policy parsing and every condition, guards and
  redaction, risk bands and tiers, audit tamper and deletion detection, migrations, every
  service rule (RBAC, separation of duties, four-eyes, expiry, kill switch, budgets including
  re-check at approval time), the SDK decorator and the CLI.
- **CI**: Python 3.11–3.13, ruff, pytest, policy validation, the scripted demo (output in the
  job summary), and a container job that builds the image, starts it read-only as a non-root
  user, waits for readiness and verifies the audit chain through the API.
- All demo data is **synthetic** and labelled as such.

## Limitations (v1.0)

- Guards are pattern-based heuristics; they reduce risk but will miss novel injection phrasing
  and unusual data formats. Allow-lists, budgets and approvals are the primary controls.
- Enforcement depends on the agent runtime calling the control plane before the tool
  (ADR 0001). Combine with credentials only the governed runtime holds.
- Single-node SQLite; PostgreSQL and multi-replica operation are on the roadmap (ADR 0002).
- No API key expiry/rotation endpoint, SSO or CSP header yet.
- Budgets count allowed and approved actions; requests waiting for approval do not reserve budget
  (they are re-checked when approved).

See [ROADMAP.md](ROADMAP.md).

## Related work by the author

`mcp-security-gateway` (enforcement in front of MCP tool servers) ·
`ai-agent-orchestration-dotnet` (guarded .NET agent runtime) ·
`eu-ai-act-compliance-kit` (classify an AI system and list its obligations).

---

Author: **Rubbaite T. Hassain** ([tanvir.info.bd](https://tanvir.info.bd)) ([LinkedIn](https://www.linkedin.com/in/rubbaite/)) · Founder of Datazo InfoTech · MIT License.

Architecture, requirements and review by Rubbaite T. Hassain; implementation AI-assisted.
This project provides engineering controls and evidence; it is not legal advice and does not by itself make a system compliant with any regulation.
