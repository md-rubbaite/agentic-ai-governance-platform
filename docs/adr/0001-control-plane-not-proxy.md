# ADR 0001: A decision service (control plane), not a proxy in the data path

- Status: accepted
- Date: 2026-11-24

## Context
Agents call many different tools: SaaS APIs, internal services, databases, email. A proxy that
sits in front of every tool would have to understand every protocol and hold every credential.
That makes it the most valuable target in the system and a single point of failure for all
business traffic.

## Decision
The platform answers one question, *may this agent perform this action now?*, and records the
answer. The agent (through the SDK) calls the tool itself only after an `allow`. The control
plane holds no business credentials and cannot perform actions.

## Consequences
- Small blast radius: compromising the control plane does not give access to business systems.
- Works with any agent framework and any tool; integration is one call before the tool call.
- Enforcement depends on the agent runtime honouring the answer. Where that is not acceptable,
  combine the control plane with credentials that only the governed runtime holds, or put
  gateway enforcement in front of specific high-risk tools (for MCP servers, see the
  author's `mcp-security-gateway`).
