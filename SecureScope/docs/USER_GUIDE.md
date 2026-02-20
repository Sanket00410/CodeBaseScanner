# CodeSentinelX Step-by-Step User Guide

This guide explains how to install, run, scan, review, export, manage tools, and recover local state in CodeSentinelX.

## 1. What CodeSentinelX Does

CodeSentinelX is a desktop security scanner for:

- Source codebase scanning (local folders, repositories, SSH codebase targets)
- Runtime/web target scanning (HTTP/HTTPS URLs, localhost, IP:port targets)
- Unified enterprise reporting (Existing Security, Vulnerability, and Fix reports)
- Toolchain management (check/install/run/bootstrap scanner tools)

## 2. Prerequisites

For development mode:

1. Node.js 20+ (`node -v`)
2. npm 10+ (`npm -v`)
3. Python 3.10+ (`python --version`)
4. Optional for runtime tools: Docker Desktop (for Nikto/Nmap/ZAP container mode)

For packaged EXE usage:

- No frontend build tooling is needed.
- Python/scanner runtime is still required according to your deployment model.

## 3. Project Locations and Important Paths

Default local state paths on Windows:

- App state store: `%APPDATA%\\Electron\\codesentinelx-store.json`
- Tool cache: `C:\\Users\\sanketa\\Documents\\UniversalSecurityScanner\\.toolchain` (or `<scanner-root>\\.toolchain`)
- Tool run outputs: `%USERPROFILE%\\Documents\\CodeSentinelX\\tool-runs`
- Report exports: `%USERPROFILE%\\Documents\\CodeSentinelX\\exports`

These are automatically managed by the app.
If a legacy `%APPDATA%\\Electron\\.toolchain` exists, first launch can seed from it into `<scanner-root>\\.toolchain`.

## 4. Start the App (Development)

From terminal:

```powershell
cd C:\Users\sanketa\Documents\UniversalSecurityScanner\SecureScope
npm install
npm run dev
```

What each process does:

- `dev:renderer`: React UI on `http://localhost:5182`
- `dev:main:watch`: Electron main process TypeScript watch build
- `dev:electron`: launches desktop app shell

## 5. Build the Windows Portable EXE

```powershell
cd C:\Users\sanketa\Documents\UniversalSecurityScanner\SecureScope
npm run build
```

Output:

- `SecureScope/release/CodeSentinelX-<version>-portable.exe`

Build includes pre-seeded toolchain resources when available.

Build speed notes:

- Default: fast seed copy from existing `.toolchain` cache (recommended).
- Slow mode (fresh bundle rebuild): downloads/prepares bundled tools again.
  - `CODESENTINELX_REBUILD_BUNDLED_TOOLCHAIN=1`

## 6. First Launch Checklist

1. Open app.
2. Choose role from header dropdown:
   - Admin
   - Security Analyst
   - Developer
   - Auditor
3. Enter target in `Target Folder / IP / SSH`.
4. Verify mode text changes correctly:
   - `Codebase Security Scan` for local folders
   - `Runtime/Remote Target Scan` for URL/IP targets

## 7. Supported Target Formats

### 7.1 Codebase Targets

- Local folder:
  - `C:\projects\my-app`
- Relative path:
  - `..\\my-app`
- SSH codebase target:
  - `ssh://user@10.0.0.10:22/opt/app`

### 7.2 Runtime/Web Targets

- URL:
  - `https://example.com`
  - `http://localhost:8080`
- IP/port:
  - `10.0.0.12:8080`

## 8. Run a Scan

1. Enter target.
2. Click `Run Scan`.
3. Watch live progress:
   - Header progress bar
   - Sidebar progress bar
   - Live log stream
4. On success, dashboard loads automatically.

By default, every scan automatically enables the full integrated tool profiles:

- Codebase/SSH:
  `bandit, brakeman, checkov, clair, codeql, cppcheck, eslint-security, findsecbugs, flawfinder, gitleaks, gosec, govulncheck, grype, hadolint, infer, npm-audit, osv-scanner, owasp-dependency-check, pip-audit, safety, semgrep, snyk, sonarqube, spotbugs, tfsec, trivy`
- Runtime URL/IP/localhost:
  `runtime_http_probe, amass, ffuf, kube-bench, kube-hunter, nikto, nmap, nuclei, sqlmap, wapiti, zap-baseline`

If scan fails, error appears in status line and logs.

## 9. Understand Main Tabs

### 9.1 Dashboard

- Risk score and severity totals
- OWASP category breakdown
- Affected modules
- Action plan
- Toolchain status and coverage matrix
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

### 9.6 Tool Manager

Sub-tabs:

- Codebase Tools
- Website Tools
- IP Tools
- Role Drill-Down
- Provisioning

Actions:

- `Check` tool availability
- `Install` tool
- `Run` single tool against current target
- `Install Core Profile` / `Install Full Profile`

Compliance note:

- By default, CodeSentinelX uses local `.toolchain` bootstrap only.
- Host installers (`winget`, `npm -g`, `gem`, `go install`) are blocked unless explicitly enabled.
- For enforced enterprise local-only tools, CodeSentinelX resolves from `.toolchain` only (downloaded binaries/venv tools or embedded compatibility wrappers), not host PATH.
- Finding-cap is disabled by default (`USS_MAX_FINDINGS=0`), so scans do not stop at 5000 findings.
- To allow host installers in a controlled environment, start app/CLI with:
  - `USS_ALLOW_HOST_INSTALLERS=1`

## 10. New Feature: Reset Local State/Cache (One Click)

Location:

- `Tool Manager` -> `Provisioning`
- Button: `Reset Local State/Cache`

What it does:

1. Clears local app state store (history/audit/review state).
2. Clears local tool-run cache.
3. Clears and re-seeds local `.toolchain` cache.
4. Re-initializes scanner/tool manager runtime state.
5. Runs core toolchain warmup.

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

1. Provision tools (`Tool Manager` -> `Provisioning` -> Core profile).
2. Run codebase scan on target repo.
3. Triage Critical/High findings first in Vulnerability detail.
4. Export Vulnerability HTML/PDF for review board.
5. Export Existing report for control-compliance evidence.
6. Track reviewed findings and audit logs.

## 15. Troubleshooting

### 15.1 App starts but scan fails immediately

- Verify target path/URL format.
- Check Python availability and scanner root environment.
- Check live log panel for exact failure stage.

### 15.2 Runtime tool not available

- Use Tool Manager `Check` and `Install`.
- For container runtime adapters, ensure Docker Desktop is running.
- If policy blocks host installers, only local-cache/bootstrap-capable tools are installable.

### 15.3 Store/caching issues

- Use `Reset Local State/Cache` in Tool Manager.
- If still needed, inspect:
  - `%APPDATA%\\Electron\\codesentinelx-store.json`
  - `<scanner-root>\\.toolchain`

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

Optional runtime controls:

- `CODESENTINELX_SCANNER_ROOT`
- `CODESENTINELX_PYTHON`
- `CODESENTINELX_TOOLCHAIN_SEED`
- `USS_CODEBASE_TOOLS`
- `USS_RUNTIME_TOOLS`
- `USS_TOOLS_DIR`
- `USS_MAX_FINDINGS` (`0` = unlimited)
- `USS_RUNTIME_AUTH_TOKEN` (Bearer token without `Bearer ` prefix)
- `USS_RUNTIME_AUTH_COOKIE` (raw `Cookie` header value)
- `USS_RUNTIME_AUTH_HEADER_NAME` + `USS_RUNTIME_AUTH_HEADER_VALUE` (custom auth header pair)

Use these when customizing deployment paths or toolchains.

## 18. Quick Start (5 Steps)

1. Launch app.
2. Set role to `Security Analyst`.
3. Enter target path or URL.
4. For runtime URL/IP targets, optionally fill `Authenticated Crawl` fields (token/cookie/custom header).
5. Click `Run Scan`.
6. Review Vulnerability detail and export HTML/PDF.

