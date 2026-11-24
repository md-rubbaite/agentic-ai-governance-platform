# Changelog

## 1.0.0 — 2026-11-24
- Governance service: agent registry, hard stops (kill switch, allow-list, daily budgets), argument guards with redaction, additive risk scoring, TOML policy engine (first match, default deny), approvals with roles, four-eyes, expiry and separation of duties, outcome reporting.
- Hash-chained audit log with verification; versioned SQLite migrations.
- FastAPI HTTP API, governance console, Prometheus metrics, health and readiness, JSON access logs.
- Python SDK with a `governed` decorator; CLI (`serve`, `seed`, `demo`, `verify-audit`, `check-policy`).
- Non-root, read-only container; CI with tests on Python 3.11–3.13, scripted demo and container smoke test.
- Docs: architecture (C4, sequence, trust boundaries), STRIDE threat model, EU AI Act / NIST AI RMF mapping, deployment guide, ADRs 0001–0004.
