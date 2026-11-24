# ADR 0003: A small TOML policy language instead of embedding OPA/Rego

- Status: accepted
- Date: 2026-11-24

## Context
Policies must be readable by risk and compliance staff, versioned, reviewable in pull requests
and validated before activation. Open Policy Agent is powerful but adds a runtime and a
language most reviewers do not read.

## Decision
Policies are ordered TOML rules with a fixed set of conditions (tool glob, action, data class,
autonomy, EU AI Act risk class, risk score/tier, flags, amount) and three effects. First match
wins; anything unmatched gets `default_effect`, which may only be `allow` or `deny`. Unknown keys
and conditions are errors, so typos cannot silently widen a policy. Every activated version is
stored with its SHA-256 and author, and versions are immutable.

## Consequences
- Policies are short and reviewable (`agentgov check-policy` in CI).
- Expressiveness is limited on purpose. Organisations that already run OPA can evaluate Rego
  in front of this service or replace `policy.evaluate`; the `Facts` structure is the contract.
