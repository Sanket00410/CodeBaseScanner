# CodeSentinelX

CodeSentinelX is a Windows desktop application that uses the existing `UniversalSecurityScanner` Python engine and presents enterprise-style interactive security analysis in a dark desktop UI.

Detailed usage guide:

- `docs/USER_GUIDE.md`

## What This App Uses

- Electron + React + TypeScript desktop shell/UI
- Existing Python scan engine: `python -m universal_security_scanner.cli scan`
- Full scanner coverage inherited from `UniversalSecurityScanner`:
  - Built-in rules and plugin engine
  - Existing security implementation detection
  - Vulnerability and fixed-code findings
  - External analyzers with target-aware routing:
    - Codebase/SSH (auto-enabled by default):
      Semgrep, Trivy, Gitleaks, CodeQL, Bandit, Checkov, pip-audit, Grype, OSV-Scanner, tfsec, Hadolint, gosec, OWASP Dependency-Check
    - Runtime URL/IP: built-in Runtime HTTP probe, Nuclei, Nikto, Nmap, ZAP baseline
  - Enterprise catalog mapping for additional global tools (SAST, SCA, DAST, IaC, container, Kubernetes)
- Three separate reports in UI and exports:
  - Existing Security Implementation Report
  - Vulnerability Report
  - Original and Suggested Fix Report
- Supports two scan target modes:
  - Codebase scan via local folder path
  - Runtime/remote scan via IP, URL, or SSH target (e.g., `https://10.0.0.8`, `ssh://user@10.0.0.8/opt/app`)

## Features

- Real-time scan progress in desktop UI
- Live scan event log stream (stage, file/module, scanner message)
- Drill-down findings with severity filtering and search
- Original code vs suggested fix and patch preview
- Mark finding as reviewed
- Toolchain intelligence panel:
  - Selected vs available tools
  - Tool-to-vulnerability coverage mapping
  - Hover descriptions for each tool
- Dedicated Tool Manager tab:
  - Profile tabs: `Codebase Tools`, `Website Tools`, `IP Tools`
  - `Check` one tool
  - `Install` one tool
  - `Run` one tool against current target (outside full scan workflow)
  - One-click profile provisioning:
    - Core integrated toolchain
    - Full catalog (best effort)
  - One-click environment recovery:
    - `Reset Local State/Cache` button in Tool Manager -> Provisioning
    - Clears local app state/history cache and rehydrates local tool cache
  - Role drill-down guidance (Admin, Security Analyst, Developer, Auditor)
  - Runtime scanner auto-integration:
    - `nuclei` via GitHub binary bootstrap
    - `bandit` via pip / `python -m bandit` fallback
    - `nikto`, `nmap`, `zap-baseline` via Docker runtime adapters when Docker is present
  - Startup auto-warmup:
    - Integrated toolchain profile bootstraps automatically in background on app launch
    - New users get plug-and-play startup without manual bootstrap steps
  - Installer seed cache:
    - Build pipeline packages a pre-seeded `.toolchain` snapshot into app resources
    - First launch hydrates a writable cache under scanner root (`<UniversalSecurityScanner>\\.toolchain`) for faster startup on fresh systems
    - Legacy `%APPDATA%\\Electron\\.toolchain` is auto-used as migration seed when present
    - Default packaging path is fast (`seed copy`) if local `.toolchain` already exists
    - Full bundled-toolchain rebuild is opt-in for slower, fresh artifact hydration
  - Catalog visibility:
    - Global catalog tools are shown as ready profile entries for enterprise coverage mapping
    - Direct one-click execution remains enabled for integrated runners
- Embedded standalone report preview inside the app (HTML dashboard iframe)
- PDF exports rendered from the same HTML dashboard (mirrors layout, charts, and code blocks)
- Scan history and audit logs
- Keyboard shortcuts:
  - Main navigation: `Alt+1..6`
  - Active section tabs: `1..9`
- Export formats:
  - Existing: JSON, HTML, PDF
  - Vulnerability: JSON, HTML, PDF, CSV, SARIF, patch
  - Fixes: HTML, PDF

## Run in Development

```powershell
cd C:\Users\sanketa\Documents\UniversalSecurityScanner\SecureScope
npm install
npm run dev
```

In the app target field, you can provide either:

- Local project folder path
- IP/URL (`http://host`, `https://host`, `10.0.0.8:8080`)
- SSH URI (`ssh://user@host:22/path/to/codebase`)

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
$env:CODESENTINELX_SCANNER_ROOT = "C:\Users\sanketa\Documents\UniversalSecurityScanner"
```

If you want to package with a specific pre-seeded cache location:

```powershell
$env:CODESENTINELX_TOOLCHAIN_SEED = "C:\Path\To\Seeded\.toolchain"
npm run build
```

To force a fresh bundled toolchain rebuild (slower, downloads binaries):

```powershell
$env:CODESENTINELX_REBUILD_BUNDLED_TOOLCHAIN = "1"
npm run build
```

If Python path is custom:

```powershell
$env:CODESENTINELX_PYTHON = "C:\Path\To\python.exe"
```

To customize active scanner sets:

```powershell
$env:USS_CODEBASE_TOOLS = "semgrep,trivy,gitleaks,codeql,bandit"
$env:USS_RUNTIME_TOOLS = "runtime_http_probe,nuclei,nikto,nmap,zap-baseline"
$env:USS_MAX_FINDINGS = "0"
```

Per-tool bootstrap/check from CLI:

```powershell
python -m universal_security_scanner.cli bootstrap-tools --path "C:\Users\sanketa\Documents\UniversalSecurityScanner" --tools semgrep
python -m universal_security_scanner.cli bootstrap-tools --path "C:\Users\sanketa\Documents\UniversalSecurityScanner" --tools semgrep --target-mode codebase
```

If runtime tools use container-runtime mode, ensure Docker Desktop is installed and running:

```powershell
docker --version
```

## Role Behavior

- `Admin`: full access, including scan start, finding review, tool execution, and provisioning.
- `Security Analyst`: full operational access like Admin for triage/provisioning workflows.
- `Developer`: scan + remediation views; read-only Tool Manager and no provisioning.
- `Auditor`: read-only operational posture (history, audits, exports), no scan start/review/provisioning.

For SSH target scans, pass credentials in URI query params or environment variables:

```powershell
$env:USS_REMOTE_SSH_USER = "scanner"
$env:USS_REMOTE_SSH_PASSWORD = "your-password"
$env:USS_REMOTE_SSH_PORT = "22"
```

## Security Defaults

- `contextIsolation: true`
- `nodeIntegration: false`
- IPC-only renderer/backend bridge
- Fix suggestions and patch previews only (no automatic source rewrite)
