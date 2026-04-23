# CodeSentinelX

CodeSentinelX is a Windows desktop application that uses the CodeSentinelX engine and presents enterprise-style interactive security analysis in a dark desktop UI.

Detailed usage guide:

- `docs/USER_GUIDE.md`
- `docs/ENTERPRISE_ARCHITECTURE.md`

## What This App Uses

- Electron + React + TypeScript desktop shell/UI
- Existing Python scan engine: `python -m codesentinelx_engine.cli scan`
- Full scanner coverage inherited from the CodeSentinelX engine:
  - Built-in rules and plugin engine
  - Expanded backend webapp coverage (file/line-level):
    SQLi, NoSQLi, Command Injection, LDAP Injection, SSRF, XSS, SSTI, Path Traversal, XXE,
    auth/authz flaws, JWT misconfiguration, open redirect, mass assignment, prototype pollution,
    weak crypto, weak TLS config, insecure RNG, hardcoded secrets, default credentials, insecure cookie flags,
    CSRF disabled, permissive CORS, unrestricted upload, session fixation risks,
    missing input validation controls, disabled logging/monitoring controls,
    software/data integrity verification disabled, and security misconfiguration
  - OWASP coverage baselines:
    - OWASP Top 10 (2021)
    - OWASP API Security Top 10 (2023)
    - OWASP ASVS 5.0
    - OWASP WSTG 4.2
  - Runtime/API endpoint hardening checks:
    endpoint discovery crawl, API/doc exposure checks, auth-aware API coverage, TRACE method exposure,
    cookie security flags, stack trace disclosure, sensitive API payload keys, auth endpoint cache-control checks
  - Existing security implementation detection
  - Vulnerability and fixed-code findings
  - CVE/CVSS/KEV enrichment for dependency and code findings:
    - CVSS-aware prioritization (`CVSS >= 7` highlighted as high-priority)
    - Known exploited vulnerability tagging (CISA KEV)
    - Exploit maturity context (known exploited / public PoC / likely / unconfirmed)
    - Release gate action mapping (`Block release`, `Fix before prod`, `Scheduled fix`, `Track`)
  - Git diff-based vulnerability tracking for local repositories:
    - Whether finding is on changed file/line relative to current git diff
    - Repo-relative path and git status marker in finding payload
  - Native code analyzers and local secure coding rules:
    Semgrep, CodeQL, OSV-Scanner, Grype, Gitleaks, Bandit, Checkov, tfsec, Hadolint, gosec, and CodeSentinelX built-in rules
  - Reference catalog mapping for additional code-analysis families (SAST, SCA, IaC, container policy)
- One canonical scan with role-projected reports:
  - Admin: Full Scope Export
  - Security Analyst: Security Analysis Export
  - Developer: Remediation Export
  - Auditor: Audit / Compliance Export
  - Management: Executive Summary Export
- Supports local codebase targets:
  - Folder scan
  - Single-file scan

## Features

- Real-time scan progress in desktop UI
- Live scan event log stream (stage, file/module, scanner message)
- Drill-down findings with severity filtering, search, grouped alert navigation, and file/line anchors
- Original code vs suggested fix and patch preview
- Mark finding as reviewed
- Toolchain intelligence panel:
  - Selected vs available tools
  - Tool-to-vulnerability coverage mapping
  - Hover descriptions for each tool
  - Enterprise assurance metrics:
    - Readiness verdict (`READY` / `WARNING` / `BLOCKED`)
    - Readiness score, required-tool coverage %, tool success rate
    - Blocker list and tool execution failure list
- Dedicated Analyzer Catalog tab:
  - Profile tabs: `Codebase Tools`, `Role Drill-Down`, `Execution Policy`
  - Visibility-only analyzer catalog for secure coding coverage
  - `Reset Local State/Cache` in `Execution Policy`
  - Clears local app state/history cache
  - Role drill-down guidance (Admin, Security Analyst, Developer, Auditor)
  - Desktop policy:
    - App-managed external binaries are disabled by policy
    - Desktop startup runs in native codebase mode only
    - Packaged builds do not bundle or seed a `.toolchain` cache
  - Catalog visibility:
    - Global analyzer families are shown as catalog-only reference entries
    - Direct one-click execution is disabled in the desktop app
- Embedded standalone report preview inside the app (HTML dashboard iframe)
- PDF exports rendered from the same HTML dashboard (mirrors layout, charts, and code blocks)
- Scan history and audit logs
- Keyboard shortcuts:
  - Main navigation: `Alt+1..6`
  - Active section tabs: `1..9`
- Export model:
  - One scan is stored once as the canonical scan.
  - Role changes redraw the current projection and do not rerun analyzers.
  - Exports carry projection metadata so the selected role scope is auditable.
- Export formats by role:
  - Admin: HTML, PDF, JSON, XML
  - Security Analyst: HTML, PDF, JSON, XML, CSV, SARIF
  - Developer: HTML, PDF, JSON, patch
  - Auditor: HTML, PDF, JSON, XML
  - Management: HTML, PDF, JSON
  - Finding Details: HTML, PDF, JSON, CSV for non-Management roles

## Run in Development

```powershell
cd codesentinelx_desktop
npm install
npm run dev
```

In the app target field, provide a local project folder path only.
In the app target field, provide a local project folder path or a single source file path.

## Validation

Use the ordered canonical-flow verifier before pushing report/projection changes:

```powershell
npm run verify:canonical-flow
```

This runs, in order:

- TypeScript typecheck for main and renderer
- Main-process build
- Canonical scan / role projection / report export regression tests
- Renderer production build

Do not run `build:main` and `test:projection` in parallel. `build:main` cleans `dist-main`, while `test:projection` imports compiled files from that folder.

## Build EXE

```powershell
npm run build
```

Portable build output:

`release\CodeSentinelX-<version>-portable.exe`

## Environment Notes

If Electron starts in Node mode by mistake:

```powershell
[Environment]::SetEnvironmentVariable("ELECTRON_RUN_AS_NODE", $null, "User")
[Environment]::SetEnvironmentVariable("ELECTRON_RUN_AS_NODE", $null, "Machine")
```

If scanner root is not auto-detected, set:

```powershell
$env:CODESENTINELX_SCANNER_ROOT = "C:\Users\sanketa\Documents\CodeSentinelX"
```

App-managed `.toolchain` packaging has been removed. `npm run build` now produces a native-only desktop package.

If Python path is custom:

```powershell
$env:CODESENTINELX_PYTHON = "C:\Path\To\python.exe"
```

Desktop runtime now clears app-managed external-tool selectors automatically. `USS_MAX_FINDINGS` still applies.

Codebase scan tuning (optional overrides):

```powershell
$env:USS_FILE_SCAN_WORKERS = "8"
$env:USS_EXTERNAL_TOOL_WORKERS = "4"
```

Threat-intel enrichment tuning:

```powershell
# Optional: path to local CISA KEV JSON/CSV/text containing CVE IDs.
$env:USS_KEV_CVE_PATH = "C:\security-feeds\known_exploited_vulnerabilities.json"
```

Enterprise gate enforcement (CLI runs):

```powershell
$env:USS_ENFORCE_ENTERPRISE_GATE = "1"
python -m codesentinelx_engine.cli scan --path "C:\projects\app" --format json --enforce-enterprise-gate
```

For authenticated runtime crawl (logged-in APIs behind auth/session):

No runtime authentication settings are used in the desktop app. CodeSentinelX only scans local codebase folders.

For owner-only Analyzer Catalog access (single email, SMTP-free TOTP-only mode):

```powershell
$env:CODESENTINELX_TOOLMANAGER_ALLOWED_EMAIL = "your.email@company.com"
$env:CODESENTINELX_TOOLMANAGER_AUTH_MODE = "totp_only"
$env:CODESENTINELX_TOOLMANAGER_MFA_SECRET = "<TOTP-SECRET-BASE32-OR-STRING>"
```

Optional SMTP mode (legacy): 

```powershell
$env:CODESENTINELX_TOOLMANAGER_AUTH_MODE = "smtp_otp_mfa"
$env:CODESENTINELX_SMTP_HOST = "smtp.company.com"
$env:CODESENTINELX_SMTP_PORT = "587"
$env:CODESENTINELX_SMTP_SECURE = "false"
$env:CODESENTINELX_SMTP_USER = "smtp-user"
$env:CODESENTINELX_SMTP_PASS = "smtp-password"
$env:CODESENTINELX_SMTP_FROM = "CodeSentinelX <no-reply@company.com>"
```

Optional Analyzer Catalog auth tuning:

```powershell
$env:CODESENTINELX_TOOLMANAGER_OTP_TTL_SECONDS = "300"
$env:CODESENTINELX_TOOLMANAGER_SESSION_TTL_SECONDS = "3600"
$env:CODESENTINELX_TOOLMANAGER_MAX_OTP_ATTEMPTS = "5"
$env:CODESENTINELX_TOOLMANAGER_MFA_WINDOW = "1"
```

Authenticity guardrails:

- App-managed external binaries are disabled in the desktop app.
- Codebase analysis runs through the native scanner bridge only.
- Strict authentic mode is enabled by default (`USS_STRICT_AUTHENTIC_RESULTS_ONLY=1`).
- Embedded compatibility wrappers are disabled by default (`USS_ALLOW_EMBEDDED_COMPAT_WRAPPERS=0`).

## Role Behavior

- `Admin`: full access, including scan start, finding review, analyzer catalog policy, and reset.
- `Security Analyst`: full operational access like Admin for triage workflows.
- `Developer`: scan + remediation views; read-only Analyzer Catalog and no reset.
- `Auditor`: read-only operational posture (history, audits, exports), no scan start/review/reset.

## Security Defaults

- `contextIsolation: true`
- `nodeIntegration: false`
- IPC-only renderer/backend bridge
- Fix suggestions and patch previews only (no automatic source rewrite)


