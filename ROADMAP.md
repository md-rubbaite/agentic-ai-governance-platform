# Roadmap

| Item | Why |
|---|---|
| PostgreSQL store and multi-replica operation | Larger agent fleets (ADR 0002) |
| API key expiry and rotation endpoint; OIDC sign-in for the console | Credential hygiene |
| Signed export of the audit head hash (scheduled) | Anchor the chain outside the database (ADR 0004) |
| Budget reservation for pending approvals | Avoid over-commitment while requests wait |
| OpenTelemetry traces across agent → control plane → tool | End-to-end investigation |
| Optional Rego evaluation behind the `Facts` contract | Organisations already standardised on OPA (ADR 0003) |
| Content-Security-Policy for the console | Defence in depth against XSS |
| TypeScript and .NET SDKs | Agents outside Python |
