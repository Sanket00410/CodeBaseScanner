# CodeSentinelX Threat Model Guide

## What this workflow is
The Threat Model workflow is a separate analysis mode from the canonical scan pipeline.
It inspects a selected codebase and builds a code-backed architecture and threat model.

## Supported frameworks
- STRIDE
- DREAD
- OWASP
- PASTA

## How to use it
1. Open the Threat Model section in the app.
2. Browse to a file or folder containing the codebase you want to analyze.
3. Select a framework.
4. Click Create Threat Model.
5. Review the generated report, diagram, JSON, and Mermaid source.

## What the report includes
- System overview
- Assets and security objectives
- Entry points and attack surface
- Trust boundaries
- Data flows
- Threats and abuse cases
- Code-level mappings
- Risk ranking
- Mitigations
- Validation and traceability
- Residual risk and assumptions

## How to read the diagram
The diagram shows the path from user interaction to analysis and artifact generation.
It is meant to explain trust boundaries and high-level flow, not to replace the detailed threat tables.

## Evidence rules
- Only code-backed evidence is included by default.
- Empty sections are hidden.
- Placeholder text is avoided.
- If a threat lacks strong evidence, it is marked for reviewer validation.

## Relationship to normal scans
Threat modeling is independent from the canonical code scanning workflow.
It does not reuse the vulnerability scan pipeline or its role-based projections.

## Notes
- STRIDE is the default framework when no framework is selected.
- DREAD is used as a risk-ranking overlay.
- OWASP and PASTA use the same evidence with framework-specific framing.
