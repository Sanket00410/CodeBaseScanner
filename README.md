# CodeSentinelX

CodeSentinelX is a desktop-first secure code analysis platform for local codebases. It combines parser-backed source analysis, evidence-based validation, fix verification, and executive/developer reporting in one application.

## What It Does

CodeSentinelX scans a local code repository and produces three report views:

- `Vulnerability Report`
- `Existing Security Implementation Report`
- `Original and Suggested Fix Report`

It is designed for codebase analysis only. It does not rely on runtime website/IP probing in the desktop workflow.

## Why It Is Different

CodeSentinelX is intentionally focused on authenticity and developer usefulness.

- Real source evidence:
  findings are tied to actual file and line context
- Parser and flow validation:
  important issue families are validated from source-to-sink context instead of only keyword matching
- Executed local validation:
  findings carry replayable validation commands and captured results
- Temp-workspace fix verification:
  suggested fixes can be rechecked in a temporary workspace, including optional build/test commands
- Dependency authenticity:
  dependency findings distinguish declared, locked, imported, and reachable usage with manifest/lockfile/advisory context
- Grounded AI:
  local Ollama can be used for remediation and prioritization, but AI is kept on top of evidence rather than replacing detection truth
- Desktop reports built for multiple audiences:
  leadership, security teams, and developers can use the same scan output in different ways

## Architecture

If you want the layered system layout and request flow, see [`README_ARCHITECTURE.md`](README_ARCHITECTURE.md).

## Core Capabilities

### Secure Code Scanning

- Python, JavaScript, TypeScript, IaC, dependency, and secret coverage
- Built-in and external analyzer integration
- Deduplication and triage normalization
- Severity, CWE, OWASP, and risk scoring

### Evidence-Backed Validation

- Active validation objects per finding
- Reproducible validation command
- Captured validation output
- Confidence tied to actual proof signals

### Fix Intelligence

- Original code
- suggested fix or remediation guidance
- patch preview
- AI remediation summary
- AI validation steps
- fix confidence labels

### Fix Verification

- post-fix rerun in temp workspace
- optional workspace build verification
- optional workspace test verification
- verified fixed / still vulnerable / manual review required outcomes

### Dependency Authenticity

- manifest detection
- lockfile detection
- advisory ID propagation
- import/use evidence
- reachability-aware prioritization

### Reports

- interactive desktop HTML report preview
- HTML exports
- PDF exports
- JSON exports

## Supported Authenticity Improvements Already Added

- parser-backed flow validation for:
  - Python:
    `SQL Injection`, `Command Injection`, `Path Traversal`, `Insecure Deserialization`, `Unsafe eval`, `SSRF`, `Open Redirect`, `SSTI`
  - JavaScript / TypeScript:
    `XSS`, `Unsafe eval`, `Prototype Pollution`, `SQL Injection`, `Command Injection`, `Path Traversal`
- grounded local AI provider path via Ollama
- build/test verification reporting in desktop exports
- dependency manifest + lockfile + advisory enrichment

## Quick Start On A New Windows Laptop

### Option A: one-command setup

From a PowerShell terminal:

```powershell
git clone https://github.com/Sanket00410/CodeBaseScanner.git
cd CodeBaseScanner
Set-ExecutionPolicy -Scope Process Bypass
.\setup-windows.ps1 -RunValidation
.\run-codesentinelx.ps1
```

### Option B: setup with optional local AI

```powershell
git clone https://github.com/Sanket00410/CodeBaseScanner.git
cd CodeBaseScanner
Set-ExecutionPolicy -Scope Process Bypass
.\setup-windows.ps1 -RunValidation -EnableOllama
.\run-codesentinelx.ps1 -EnableOllama
```

## Setup Script

`setup-windows.ps1` prepares the repo for use on a Windows laptop.

It will:

- create `.venv`
- install Python package dependencies
- install desktop `npm` dependencies inside `codesentinelx_desktop`
- optionally pull an Ollama model
- optionally run validation checks

### Example

```powershell
.\setup-windows.ps1 -RunValidation
```

With optional local Ollama:

```powershell
.\setup-windows.ps1 -EnableOllama -OllamaModel qwen2.5-coder:7b -RunValidation
```

## Run Script

`run-codesentinelx.ps1` starts the desktop application with the scanner root and common environment settings already configured.

### Example

```powershell
.\run-codesentinelx.ps1
```

With Ollama:

```powershell
.\run-codesentinelx.ps1 -EnableOllama -OllamaModel qwen2.5-coder:7b
```

With custom verification commands:

```powershell
.\run-codesentinelx.ps1 `
  -FixVerifyBuildCommand "python -m compileall ." `
  -FixVerifyTestCommand "python -m pytest -q"
```

## Manual Run Flow

If you do not want to use the scripts:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
cd codesentinelx_desktop
npm install
npm run dev
```

## Optional Local AI

CodeSentinelX can use Ollama locally for grounded remediation and prioritization.

Required:

- Ollama installed
- `ollama serve` running
- a local model such as `qwen2.5-coder:7b`

The run script sets these when `-EnableOllama` is used:

- `USS_AI_REMEDIATION_PROVIDER=ollama`
- `USS_AI_OLLAMA_MODEL=<model>`
- `USS_AI_OLLAMA_URL=http://127.0.0.1:11434/api/generate`

## Validation Commands

The setup script can run:

```powershell
python -m pytest -q tests/test_poc_verify.py tests/test_plugins.py tests/test_report_builder_validation.py
cd codesentinelx_desktop
npm run typecheck
```

## Scanner Quality Benchmark Truth Set

CodeSentinelX includes a starter benchmark truth set so the quality gate section can appear on first run.

- Starter file in the repo: `codesentinelx_engine/resources/benchmark_truth_set.json`
- Default runtime file: `C:\\Users\\sanketa\\Documents\\CodeSentinelX_Reports\\export\\.integrity\\benchmark_truth_set.json`
- Optional override: set `USS_QUALITY_BENCHMARK_FILE` to a custom JSON file path

To use your own repo-specific truth set:

1. Copy the starter file into the runtime location:

```powershell
Copy-Item codesentinelx_engine\resources\benchmark_truth_set.json C:\Users\sanketa\Documents\CodeSentinelX_Reports\export\.integrity\benchmark_truth_set.json
```

2. Add benchmark cases for findings you want to measure. Each case should include:
   - `case_id`
   - `expected_present` or `expected_absent`
   - `file_path`
   - `rule_id`
   - `title`
   - `line_number` when relevant

3. Re-run a scan. The report will show precision, recall, F1, false-positive rate, and any benchmark gate blockers.

This benchmark is meant to be honest, not decorative:

- empty or incomplete cases will surface as warnings
- threshold failures will show up in the report gate
- the starter file is intentionally minimal so you can replace it with real truth data for your repo

## Practical Advantages For Teams

### For Developers

- file and line-level findings
- grounded remediation
- fix verification evidence
- less generic report text

### For Security Teams

- stronger false-positive control through evidence and validation
- dependency authenticity proof
- richer taxonomy and reporting
- toolchain and data quality visibility

### For Leadership

- business-facing summary layers
- deduplicated reporting
- verification-aware remediation status
- cleaner narrative for risk and readiness

## Important Notes

- This repo intentionally excludes local scan output folders like `exports/`
- This repo is designed to be portable across laptops
- Desktop runtime is codebase-only
- Local AI is optional; the scanner still works without Ollama

## Main Entry Points

- Desktop app: `codesentinelx_desktop`
- Python engine: `codesentinelx_engine`
- Setup script: `setup-windows.ps1`
- Run script: `run-codesentinelx.ps1`

