# Threat model (STRIDE)

Scope: the control plane process, its database, the agent SDK and the governance console.
Out of scope: the business tools themselves and the model provider.

| # | STRIDE | Threat | Mitigation in v1.0 | Residual risk |
|---|---|---|---|---|
| 1 | Spoofing | An agent runtime acts as a different, more privileged agent | Agent keys are bound to one `agent_id`; mismatches are rejected (403) | Key theft from the runtime host |
| 2 | Spoofing | Stolen API key | Keys are random (256 bits), stored only as SHA-256; admins can create new principals; deactivate the old one in the database | No built-in rotation endpoint or expiry yet (roadmap) |
| 3 | Tampering | Audit rows edited or deleted to hide an action | Hash chain; `verify` names the first broken entry; append in the same transaction | Whole-chain rewrite by a DB admin: anchor the head hash externally (ADR 0004) |
| 4 | Tampering | Policy changed silently to widen permissions | Versions immutable, hashed, author recorded, activation audited; unknown keys rejected | Admin key compromise |
| 5 | Repudiation | Reviewer denies having approved | Votes carry principal, timestamp and mandatory comment; audited | Shared reviewer keys defeat attribution; issue one key per person |
| 6 | Information disclosure | Secrets or personal data stored in the audit log | Guards redact secrets, emails, international phone numbers, IBANs and Luhn-valid card numbers before storage | Pattern-based; unusual formats can pass. Classify data at the source as well |
| 7 | Information disclosure | Agent reads other agents' decisions | Agent keys see only their own agent, decisions and no policy history | – |
| 8 | Denial of service | Flood of decision requests | Daily action budgets per agent; FastAPI validation limits sizes | No network rate limiting in-process; use a reverse proxy |
| 9 | Elevation of privilege | Prompt injection makes the agent request a harmful action | Injection markers flagged and routed to a human; allow-list and budgets are hard stops; risk scoring | Heuristic detection; novel phrasing is missed, which is why allow-lists and approvals matter more than detection |
| 10 | Elevation of privilege | Agent owner approves their own agent's risky action | Separation of duties enforced in code | Collusion between owner and a reviewer |
| 11 | Elevation of privilege | Approval granted after the situation changed (budget spent, agent suspended) | Hard stops re-checked at approval time; suspension closes pending approvals | – |
| 12 | Tampering | XSS in the console through agent-supplied text | All values HTML-escaped; same-origin fetch; `nosniff`, `no-store` headers | No CSP header yet (roadmap) |

## Assumptions

- TLS is terminated by a reverse proxy or platform load balancer in front of the service.
- The database file lives on encrypted storage with backups.
- Agent runtimes call the control plane **before** each governed tool call (ADR 0001).
