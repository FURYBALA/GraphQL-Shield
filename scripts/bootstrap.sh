#!/usr/bin/env bash
# ==============================================================================
# GraphQL Shield - One-command bootstrap (Linux / macOS / Git Bash / WSL)
# ==============================================================================
# Creates a local virtual environment, installs the validated dependency set,
# seeds the database, and runs the full test suite.
#
# Usage (from the repository root):
#   bash scripts/bootstrap.sh
#
# Requirements: Python 3.11+ available as `python3` or `python`.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

echo "[1/5] Creating virtual environment (.venv)..."
"$PYTHON" -m venv .venv

if [ -x ".venv/bin/python" ]; then
    VENV_PY=".venv/bin/python"
else
    VENV_PY=".venv/Scripts/python.exe"
fi

echo "[2/5] Installing pip tooling..."
"$VENV_PY" -m pip install --upgrade pip

echo "[3/5] Installing dependencies (requirements.txt + constraints.txt)..."
"$VENV_PY" -m pip install -r requirements.txt -c constraints.txt

if [ ! -f ".env" ]; then
    echo "[i] .env not found; copying .env.example -> .env"
    cp .env.example .env
fi

echo "[4/5] Seeding database..."
"$VENV_PY" -m app.seed

echo "[5/5] Running test suite..."
"$VENV_PY" -m pytest tests/ -q

echo ""
echo "Bootstrap complete. Start the server with:"
echo "  source .venv/bin/activate; uvicorn app.main:app --reload"
echo "Then open http://localhost:8000/dashboard"
