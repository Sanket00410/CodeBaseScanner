param(
    [switch]$InstallPrerequisites,
    [switch]$EnableOllama,
    [string]$OllamaModel = "qwen2.5-coder:7b",
    [switch]$RunValidation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Install-WithWinget {
    param(
        [string]$WingetId,
        [string]$DisplayName
    )
    if (-not (Test-Command "winget")) {
        throw "winget is not available. Install $DisplayName manually and rerun setup."
    }
    Write-Step "Installing $DisplayName via winget"
    winget install --id $WingetId --exact --accept-package-agreements --accept-source-agreements
}

function Resolve-PythonCommand {
    if (Test-Command "py") {
        return "py -3.11"
    }
    if (Test-Command "python") {
        return "python"
    }
    throw "Python 3.11+ was not found."
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

Write-Step "Preparing CodeSentinelX at $RepoRoot"

if ($InstallPrerequisites) {
    if (-not (Test-Command "git")) {
        Install-WithWinget -WingetId "Git.Git" -DisplayName "Git"
    }
    if (-not (Test-Command "node")) {
        Install-WithWinget -WingetId "OpenJS.NodeJS.LTS" -DisplayName "Node.js LTS"
    }
    if (-not (Test-Command "py") -and -not (Test-Command "python")) {
        Install-WithWinget -WingetId "Python.Python.3.11" -DisplayName "Python 3.11"
    }
    if ($EnableOllama -and -not (Test-Command "ollama")) {
        Install-WithWinget -WingetId "Ollama.Ollama" -DisplayName "Ollama"
    }
}

if (-not (Test-Command "node")) {
    throw "Node.js was not found. Install Node.js LTS or rerun with -InstallPrerequisites."
}

$PythonCommand = Resolve-PythonCommand

Write-Step "Creating Python virtual environment"
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Invoke-Expression "$PythonCommand -m venv .venv"
}

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment creation failed. Expected python at $VenvPython"
}

Write-Step "Upgrading pip"
& $VenvPython -m pip install --upgrade pip

Write-Step "Installing Python package dependencies"
& $VenvPython -m pip install -e ".[dev]"

Write-Step "Installing desktop dependencies"
Push-Location (Join-Path $RepoRoot "SecureScope")
try {
    npm install
}
finally {
    Pop-Location
}

if ($EnableOllama) {
    if (-not (Test-Command "ollama")) {
        throw "Ollama was requested but is not installed. Install Ollama or rerun setup without -EnableOllama."
    }
    Write-Step "Pulling local Ollama model $OllamaModel"
    ollama pull $OllamaModel
}

if ($RunValidation) {
    Write-Step "Running focused Python validation tests"
    & $VenvPython -m pytest -q tests/test_poc_verify.py tests/test_plugins.py tests/test_report_builder_validation.py

    Write-Step "Running SecureScope typecheck"
    Push-Location (Join-Path $RepoRoot "SecureScope")
    try {
        npm run typecheck
    }
    finally {
        Pop-Location
    }
}

Write-Step "Setup complete"
Write-Host "Next command:" -ForegroundColor Green
if ($EnableOllama) {
    Write-Host ".\run-codesentinelx.ps1 -EnableOllama -OllamaModel $OllamaModel" -ForegroundColor Yellow
} else {
    Write-Host ".\run-codesentinelx.ps1" -ForegroundColor Yellow
}
