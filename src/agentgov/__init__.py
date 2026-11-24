"""agentgov: a governance control plane for autonomous AI agents.

Agents ask the control plane before they act. The control plane checks the agent's
registration and tool allow-list, scans the arguments, applies budgets, scores the risk,
evaluates a versioned policy and returns allow, deny or require_approval. Every decision,
approval and outcome is written to a hash-chained, tamper-evident audit log.
"""

__version__ = "1.0.0"
