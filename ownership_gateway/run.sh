#!/usr/bin/env bash
# Starts the vulnerable backend (:5001) and the GraphQLShield gateway (:5000).
# Usage: ./run.sh            then open http://127.0.0.1:5000/dashboard   (Ctrl+C stops both)
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
[ -d .venv ] && PY=.venv/bin/python
$PY -m backend.app & BACK=$!
trap 'kill $BACK 2>/dev/null' EXIT
$PY -m gateway.app
