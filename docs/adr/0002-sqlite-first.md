# ADR 0002: SQLite first, PostgreSQL when scale requires it

- Status: accepted
- Date: 2026-11-24

## Context
The reference deployment should run with one command and no external services, while keeping
decisions, approvals and audit entries consistent.

## Decision
Use SQLite (WAL mode) with versioned migrations. All SQL lives in `store.py`. Decisions,
usage counters and audit entries are written in a single `BEGIN IMMEDIATE` transaction.

## Consequences
- Zero-dependency local and container deployment; easy backups (one file).
- Single-writer: fine for tens of agents, not for a large fleet. The migration path is a
  PostgreSQL implementation of the store with the same transaction boundaries, plus
  `SELECT … FOR UPDATE` on the audit head to keep the chain linear across replicas.
