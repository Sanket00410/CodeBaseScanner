# CodeSentinel X Architecture

## Product Identity
- Name: CodeSentinel X
- Tagline: Scan every line. Quantify every risk.
- Logo concept: hexagonal shield with `</>` brackets and telemetry pulse.

## Control Plane
- API Gateway (REST + GraphQL)
- Identity Service (SSO, RBAC, SCIM)
- Scan Orchestrator (job lifecycle)
- Finding Service (dedupe, suppression, triage)
- Report Service (PDF/HTML/JSON/SARIF)
- Integration Service (CI, SIEM, ticketing)
- Audit Service (immutable event trail)

## Data Plane
- Distributed scanning workers
- Language plugins via plugin SDK
- Queue/event backbone: RabbitMQ + Kafka

## Data Stores
- PostgreSQL: canonical findings, users, policies
- Elasticsearch: fast search and faceting
- Redis: caching, sessions, short-lived scan state
- Object storage: report artifacts and evidence blobs

## Security and Enterprise Controls
- RBAC with organization/project scopes
- SSO using SAML/OAuth2/OIDC
- Audit logs for every mutation and policy action
- Multi-project workspace isolation
- Team collaboration with finding comments and ownership

## Scan Engine Layers
1. Recursive source discovery and filtering
2. Pattern rules and signatures
3. Language plugin semantic checks
4. Dependency vulnerability checks
5. Risk scoring and normalization
6. Executive and technical reporting

## Deployment Modes
- CLI local scan
- Docker Compose enterprise stack
- Kubernetes Helm chart
- CI plugins (GitHub/GitLab)
- On-prem or SaaS control plane
