# Windows equivalent of run.sh. Starts a backend plus the GraphQLShield gateway (:5000); Ctrl+C stops both.
#   .\run.ps1                   ClinicHub demo backend on :5001
#   .\run.ps1 -Target fastapi   the main FastAPI app (repo root) on :8000, protected through /graphql-insecure
# Then open http://127.0.0.1:5000/dashboard
param([ValidateSet("clinichub", "fastapi")][string]$Target = "clinichub")

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

if ($Target -eq "fastapi") {
    $root = Split-Path -Parent $here
    # Restore the seed users/objects in place (unlike app.seed, this keeps shield.db and its audit data)
    Push-Location $root
    & $py -c "from app.database import init_db; from app.seed import restore_seed_rows; init_db(); restore_seed_rows()"
    Pop-Location
    $backend = Start-Process $py -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" `
        -WorkingDirectory $root -PassThru -NoNewWindow
    $env:GS_POLICY = "policy_fastapi.json"
    $env:GS_BACKEND = "http://127.0.0.1:8000"
    if (-not $env:GS_JWT_SECRET) { $env:GS_JWT_SECRET = if ($env:JWT_SECRET) { $env:JWT_SECRET } else { "super_secret_dev_key" } }
} else {
    $backend = Start-Process $py -ArgumentList "-m", "backend.app" -WorkingDirectory $here -PassThru -NoNewWindow
}

try {
    Push-Location $here
    & $py -m gateway.app
} finally {
    Pop-Location
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
}
