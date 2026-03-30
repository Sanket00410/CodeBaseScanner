param(
    [switch]$EnableOllama,
    [string]$OllamaModel = "qwen2.5-coder:7b",
    [int]$ToolWorkers = 4,
    [int]$FileWorkers = 8,
    [string]$ScanPreset = "standard",
    [string]$FixVerifyBuildCommand = "",
    [string]$FixVerifyTestCommand = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$codesentinelx_desktopRoot = Join-Path $RepoRoot "codesentinelx_desktop"
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment not found at $VenvPython. Run .\setup-windows.ps1 first."
}

if (-not (Test-Path (Join-Path $codesentinelx_desktopRoot "package.json"))) {
    throw "codesentinelx_desktop package.json was not found. Repository layout is incomplete."
}

$env:CODESENTINELX_SCANNER_ROOT = $RepoRoot
$env:CODESENTINELX_PYTHON = $VenvPython
$env:USS_TOOL_WORKERS = [string]$ToolWorkers
$env:USS_FILE_SCAN_WORKERS = [string]$FileWorkers
$env:USS_SCAN_CACHE_ENABLED = "1"
$env:USS_SCAN_PRESET = $ScanPreset

if ($FixVerifyBuildCommand) {
    $env:USS_FIX_VERIFY_BUILD_COMMAND = $FixVerifyBuildCommand
}

if ($FixVerifyTestCommand) {
    $env:USS_FIX_VERIFY_TEST_COMMAND = $FixVerifyTestCommand
}

if ($EnableOllama) {
    $env:USS_AI_REMEDIATION_PROVIDER = "ollama"
    $env:USS_AI_OLLAMA_MODEL = $OllamaModel
    $env:USS_AI_OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
    $env:USS_AI_REMEDIATION_MAX_FINDINGS = "8"
    $env:USS_AI_PRIORITIZATION_MAX_FINDINGS = "18"
}

Write-Step "Starting CodeSentinelX desktop app"
Push-Location $codesentinelx_desktopRoot
try {
    npm run dev
}
finally {
    Pop-Location
}

