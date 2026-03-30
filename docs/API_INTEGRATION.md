# API Integration Guide

## REST Contract
Use `integration-contracts/openapi.yaml` for endpoint definitions.

## GraphQL Contract
Use `integration-contracts/graphql/schema.graphql` for dashboard-friendly query integration.

## SOC Integration Pattern
- Poll `/v1/findings` for batch ingestion.
- Subscribe to integration-service webhooks for near-real-time events.
- Export SARIF/JSON reports and push into SIEM/SOAR playbooks.

