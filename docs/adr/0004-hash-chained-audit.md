# ADR 0004: Hash-chained audit log in the same transaction as the decision

- Status: accepted
- Date: 2026-11-24

## Context
Auditors and, for high-risk AI systems, regulators expect records that show what an AI
system did and who approved it (EU AI Act Art. 12 and Art. 26(6)). A plain table can be edited
without trace.

## Decision
Every event is appended with `hash = SHA-256(previous hash + canonical JSON of the entry)`.
The append happens in the same transaction as the state change it describes. Arguments are
redacted (secrets, personal data) before they are written. `GET /v1/audit/verify` recomputes
the chain and returns the first invalid entry.

## Consequences
- Edits and deletions are detectable; insertions in the middle break the chain.
- A chain alone does not stop someone with database access from rewriting the *whole* chain.
  Export the head hash periodically to a separate system (ticket, WORM storage or a signed
  log) to anchor it. This is documented as a deployment step, not automated in v1.0.
