# CodeSentinelX Report Dashboard

Modern enterprise report UI for vulnerability exports.

## Load Data

The dashboard supports two modes:

1. Embedded payload (`window.__REPORT_DATA__`)  
   Used automatically by `codesentinelx_desktop` HTML vulnerability export.
2. External JSON (`report.json`)  
   Open `index.html?report=report.json`.

## Schema Compatibility

Supported report roots:

- `vulnerability_fixed_code_report` (primary)
- `original_suggested_fix_report` (fallback)
- `executive_summary` (summary fallback)

## Libraries

- `Chart.js` for charts
- `DataTables` for large-table filtering/sorting/search
- `Prism.js` for code syntax highlighting

## Pages

- Overview
- Vulnerabilities
- Dependencies
- Secrets
- Metrics
- Compliance
- Trends
- Remediation
- Rules

