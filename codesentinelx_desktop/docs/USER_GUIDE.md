# CodeSentinelX Step-by-Step User Guide

This guide explains how to install, run, scan, review, export, manage tools, and recover local state in CodeSentinelX.

## 1. What CodeSentinelX Does

CodeSentinelX is a desktop security scanner for:

- Source codebase scanning (local folders and repositories)
- Unified enterprise reporting (Secure Coding Controls, Code Findings, and Fix reports)
- Analyzer catalog visibility (coverage mapping and policy status)

## 2. Prerequisites

For development mode:

1. Node.js 20+ (`node -v`)
2. npm 10+ (`npm -v`)
3. Python 3.10+ (`python --version`)
For packaged EXE usage:

- No frontend build tooling is needed.
- Python/scanner runtime is still required according to your deployment model.

## 3. Project Locations and Important Paths

Default local state paths on Windows:

- App state store: `%APPDATA%\\Electron\\codesentinelx-store.json`
- App-managed tool cache: disabled by policy (no `.toolchain` cache is required)
- Tool run outputs: `%USERPROFILE%\\Documents\\CodeSentinelX\\tool-runs`
- Report exports: `%USERPROFILE%\\Documents\\CodeSentinelX\\exports`

These are automatically managed by the app.

## 4. Start the App (Development)

From terminal:

```powershell
cd C:\Users\sanketa\Documents\UniversalSecurityScanner\codesentinelx_desktop
npm install
npm run dev
```

What each process does:

- `dev:renderer`: React UI on `http://localhost:5182`
- `dev:main:watch`: Electron main process TypeScript watch build
- `dev:electron`: launches desktop app shell

## 5. Build the Windows Portable EXE

```powershell
cd C:\Users\sanketa\Documents\UniversalSecurityScanner\codesentinelx_desktop
npm run build
```

Output:

- `codesentinelx_desktop/release/CodeSentinelX-<version>-portable.exe`

Build is native-only and does not package app-managed external tool caches or seeded binaries.

## 6. First Launch Checklist

1. Open app.
2. Choose role from header dropdown:
   - Admin
   - Security Analyst
   - Developer
   - Auditor
3. Enter target in `Codebase Folder`.
4. Confirm the header mode reads `Codebase Secure Analysis`.

## 7. Supported Target Formats

### 7.1 Codebase Targets

- Local folder:
  - `C:\projects\my-app`
- Relative path:
  - `..\\my-app`

## 8. Run a Scan

1. Enter target.
2. Click `Run Scan`.
3. Watch live progress:
   - Header progress bar
   - Sidebar progress bar
   - Live log stream
4. On success, dashboard loads automatically.

Desktop runtime is locked to native codebase analysis. App-managed external tool binaries are disabled by policy; Analyzer Catalog shows code-analysis families for visibility/governance only.

Risk intelligence and prioritization:

- Findings are enriched with CVE IDs (when available), CVSS score, exploit maturity, and release-gate action.
- Severity action policy:
  - Critical => Block release
  - High => Fix before prod
  - Medium => Scheduled fix
  - Low/Info => Track
- Optional KEV feed override (local file with CVE IDs):
  - `USS_KEV_CVE_PATH=C:\security-feeds\known_exploited_vulnerabilities.json`
- Mandatory enterprise coverage enforced in scanner rules/reporting:
  - OWASP Top 10 (2021): A01..A10 mapped in findings and compliance views
  - OWASP API Security Top 10 (2023), ASVS 5.0, WSTG 4.2 profile mapping
  - Critical code risks: RCE, SQLi, command injection, path traversal, deserialization, buffer overflow, unsafe upload
  - Auth/token risks: JWT signature/expiry issues, missing MFA, weak/default credentials, session fixation
  - Crypto/transport risks: weak hashing, insecure randomness, weak TLS configuration, hardcoded secrets
  - Misconfiguration quick wins: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, cookie flags
  - Supply-chain risk context: CVSS >= 7 prioritization + CISA KEV tagging + release-gate classification

If scan fails, error appears in status line and logs.

## 9. Understand Main Tabs

### 9.1 Dashboard

- Risk score and severity totals
- OWASP category breakdown
- Affected modules
- Action plan
- Enterprise readiness verdict:
  - Status (`READY` / `WARNING` / `BLOCKED`)
  - Readiness score
  - Required tool coverage (%)
  - Tool success rate (%)
  - Blockers and recommendation
- Toolchain status and coverage matrix
- Tool execution telemetry:
  - Execution status per tool (`success`, `failed`, `unavailable`, `skipped_*`)
  - Per-tool duration and findings count
  - Failure table for triage
- Affected files/folders views

### 9.2 Existing Security Report

Shows implemented controls only:

- Input validation
- Auth/Authz controls
- Crypto controls
- Logging/monitoring controls
- Compliance mapping (OWASP/ISO/NIST)

### 9.3 Vulnerability Report

- Queue table with severity, issue, file, line, CVSS, status
- Click a row to open detail
- Detail view includes:
  - Original code
  - Suggested fix
  - Patch preview
  - Business impact
  - Source tool

### 9.4 Compliance

- Compliance matrix and mapped controls
- Remediation action plan

### 9.5 Scan History

- Past scan list
- Re-open previous scan results
- Audit log timeline

### 9.6 Analyzer Catalog

Sub-tabs:

- Codebase Tools
- Role Drill-Down
- Execution Policy

Actions:

- Direct tool execution and provisioning are disabled by policy
- The desktop app does not download, bootstrap, or run external binaries

Owner access lock:

- Analyzer Catalog can be configured as owner-only access.
- Only one configured email is allowed.
- Default access flow is SMTP-free TOTP-only (owner email + authenticator code).
- Without valid owner session, tool list/actions are locked.
- Configure with:
  - `CODESENTINELX_TOOLMANAGER_ALLOWED_EMAIL`
  - `CODESENTINELX_TOOLMANAGER_AUTH_MODE=totp_only`
  - `CODESENTINELX_TOOLMANAGER_MFA_SECRET`

Optional SMTP mode (legacy):

- `CODESENTINELX_TOOLMANAGER_AUTH_MODE=smtp_otp_mfa`
- `CODESENTINELX_SMTP_HOST`, `CODESENTINELX_SMTP_PORT`, `CODESENTINELX_SMTP_SECURE`, `CODESENTINELX_SMTP_USER`, `CODESENTINELX_SMTP_PASS`, `CODESENTINELX_SMTP_FROM`

Compliance note:

- App-managed external tool binaries are disabled by policy in the desktop runtime.
- Host installers (`winget`, `npm -g`, `gem`, `go install`) are blocked unless explicitly enabled outside the desktop runtime.
- Finding-cap is disabled by default (`USS_MAX_FINDINGS=0`), so scans do not stop at 5000 findings.
- Runtime compatibility fallback findings are disabled by default (`USS_ENABLE_BUILTIN_RUNTIME_COMPAT=0`) to avoid synthetic tool output.
- Strict authentic results mode is enabled by default (`USS_STRICT_AUTHENTIC_RESULTS_ONLY=1`).
- Embedded compatibility wrapper bootstrap is disabled by default (`USS_ALLOW_EMBEDDED_COMPAT_WRAPPERS=0`).
- Git diff-based vulnerability context is automatically added for local git repositories (changed file/line tracking).

## 10. New Feature: Reset Local State/Cache (One Click)

Location:

- `Analyzer Catalog` -> `Execution Policy`
- Button: `Reset Local State/Cache`

What it does:

1. Clears local app state store (history/audit/review state).
2. Clears local tool-run cache.
3. Clears local preview/export cache and resets in-memory runtime state.
4. Re-initializes scanner and UI state.

When to use:

- Store corruption or oversized local state
- Broken local cache after environment changes
- Before sharing demo environment with clean state

## 11. Export Reports

From sidebar `Exports` panel:

- Existing report: HTML/PDF
- Vulnerability report: HTML/PDF/JSON/SARIF/CSV/Patch
- Fix report: HTML/PDF

Use `Open Last Export` to open the latest generated file.

## 12. Keyboard Shortcuts

- Main navigation: `Alt + 1..6`
- Section-level tabs in current view: `1..9`

## 13. Role Behavior

- Admin: full access including provisioning/reset
- Security Analyst: full operational security workflow
- Developer: scan and remediation focus, restricted provisioning/tool management
- Auditor: read-only analysis and evidence access

## 14. Recommended Operational Workflow

1. Open `Analyzer Catalog` to confirm desktop policy is still codebase-only.
2. Run codebase scan on target repo.
3. Triage Critical/High findings first in the findings detail view.
4. Export Findings HTML/PDF for review board.
5. Export Controls report for control-compliance evidence.
6. Track reviewed findings and audit logs.

## 15. Troubleshooting

### 15.1 App starts but scan fails immediately

- Verify target path/URL format.
- Check Python availability and scanner root environment.
- Check live log panel for exact failure stage.

### 15.2 Analyzer catalog is locked

- Verify your role allows Analyzer Catalog access.
- Complete owner access authentication if owner lock is enabled.
- The desktop app intentionally blocks direct installs and external tool execution.

### 15.3 Store/caching issues

- Use `Reset Local State/Cache` in Analyzer Catalog.
- If still needed, inspect:
  - `%APPDATA%\\Electron\\codesentinelx-store.json`

### 15.4 Renderer/Electron dev session exits unexpectedly

- Re-run `npm run dev`.
- Ensure no stale process blocks port `5182`.
- Check terminal output from `dev:main:watch` for TypeScript errors.

## 16. Security and Data Handling Notes

- CodeSentinelX does not auto-edit source code.
- Suggested fixes are recommendations only.
- Local state can contain sensitive metadata; protect workstation/user profile access.
- Use role controls and audit logs for enterprise governance.

## 17. Advanced Environment Variables

Optional desktop controls:

- `CODESENTINELX_SCANNER_ROOT`
- `CODESENTINELX_PYTHON`
- `USS_MAX_FINDINGS` (`0` = unlimited)

Use these when customizing deployment paths and scanner behavior.

## 18. Quick Start (5 Steps)

1. Launch app.
2. Set role to `Security Analyst`.
3. Enter a local codebase folder path.
4. Click `Run Scan`.
5. Review secure coding findings and export HTML/PDF.


