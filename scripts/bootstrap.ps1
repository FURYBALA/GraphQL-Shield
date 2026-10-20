# ==============================================================================
# GraphQL Shield - One-command bootstrap (Windows / PowerShell 5.1+)
# ==============================================================================
# Creates a local virtual environment, installs the validated dependency set,
# seeds the database, and runs the full test suite.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
#
# Requirements: Python 3.11+ available as `py` or `python`.
# ==============================================================================

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$python = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }

Write-Host "[1/5] Creating virtual environment (.venv)..."
& $python -m venv .venv
if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }

$venvPy = Join-Path $repoRoot ".venv\Scripts\python.exe"

Write-Host "[2/5] Installing pip tooling..."
& $venvPy -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }

Write-Host "[3/5] Installing dependencies (requirements.txt + constraints.txt)..."
& $venvPy -m pip install -r requirements.txt -c constraints.txt
if ($LASTEXITCODE -ne 0) { throw "dependency install failed" }

if (-not (Test-Path (Join-Path $repoRoot ".env"))) {
    Write-Host "[i] .env not found; copying .env.example -> .env"
    Copy-Item (Join-Path $repoRoot ".env.example") (Join-Path $repoRoot ".env")
}

Write-Host "[4/5] Seeding database..."
& $venvPy -m app.seed
if ($LASTEXITCODE -ne 0) { throw "database seed failed" }

Write-Host "[5/5] Running test suite..."
& $venvPy -m pytest tests/ -q
if ($LASTEXITCODE -ne 0) { throw "test suite failed" }

Write-Host ""
Write-Host "Bootstrap complete. Start the server with:"
Write-Host "  .\.venv\Scripts\Activate.ps1; uvicorn app.main:app --reload"
Write-Host "Then open http://localhost:8000/dashboard"
