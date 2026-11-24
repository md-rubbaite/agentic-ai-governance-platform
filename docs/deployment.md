# Deployment and operations

## Local (Python 3.11+)

```bash
pip install -e ".[dev]"
agentgov seed            # default policy + synthetic demo organisation; keys in .agentgov-demo-keys.json (mode 600)
agentgov serve           # http://127.0.0.1:8080, console at /dashboard, OpenAPI at /docs
```

## Container

```bash
cp .env.example .env     # set AGENTGOV_BOOTSTRAP_ADMIN_KEY to a long random value
docker compose up -d --build
curl -s localhost:8080/readyz
```

The image runs as UID 10001 with a read-only root filesystem, no capabilities and
`no-new-privileges`; data lives in the `agentgov-data` volume. CI builds the image, starts it,
waits for readiness, checks the policy and verifies the audit chain on every push.

## Production checklist

- Terminate TLS in a reverse proxy or load balancer; add network rate limits there.
- One API key per person; agent keys per runtime; store them in a secrets manager.
- Back up the database file (or move to PostgreSQL, see ADR 0002); keep at least six months
  of audit history if you deploy high-risk AI systems (EU AI Act Art. 26(6)).
- Export the audit head hash (`GET /v1/audit/verify` → `head`) daily to a separate system so a
  whole-chain rewrite would be detectable (ADR 0004).
- Review policy changes in pull requests; run `agentgov check-policy` in CI before `PUT /v1/policy`.
- Scrape `/metrics` and alert on `agentgov_approvals_pending` growing and on suspended agents.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AGENTGOV_DB` | `agentgov.db` | SQLite file |
| `AGENTGOV_HOST` / `AGENTGOV_PORT` | `127.0.0.1` / `8080` | Bind address |
| `AGENTGOV_BOOTSTRAP_ADMIN_KEY` | unset | Key for the first admin on an empty database; if unset, a key is generated and printed once |

## Operations endpoints

| Endpoint | Use |
|---|---|
| `GET /healthz` | liveness |
| `GET /readyz` | readiness: database reachable and a policy is active |
| `GET /metrics` | Prometheus text format |
| `GET /v1/audit/verify` | integrity check of the audit chain (auditor or admin) |

Logs are one JSON object per request on stdout (`rid`, `method`, `path`, `status`, `ms`).
The `x-request-id` header is propagated or generated.
