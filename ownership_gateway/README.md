# GraphQLShield: Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities

GraphQLShield is a reverse-proxy gateway that sits in front of any GraphQL API. It stops
**Broken Object Level Authorization (BOLA)** attacks without changing the backend's code. It reads the
backend's schema, infers *who owns what*, and enforces ownership in two places:

* **Before execution** (pre-flight): for mutations it looks up the owner of every targeted object ID and
  blocks the request if the caller is not the owner. This stops side effects such as edits and deletes.
* **After execution** (response verification): it rewrites each query to also fetch `__typename` plus the
  owner field of every object, then redacts any object the caller does not own. This catches nested traversal,
  search/list leaks, `node(id)`, fragments, aliases and batching.

```
 client ──► GraphQLShield :5000 ─────────────────────────────► backend :5001 (ClinicHub, deliberately vulnerable)
            parse+validate → limits → pre-flight → augment → forward → verify+redact → strip → log
                                                       ▲
                          ownership model ◄── schema introspection (at startup)
```

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt     # add matplotlib for evaluation charts
./run.sh                                      # backend :5001 + gateway :5000
# open http://127.0.0.1:5000/dashboard
```

In a second terminal:

```bash
.venv/bin/python -m pytest -q                 # 87 automated tests: 48 ClinicHub + 39 FastAPI target (no servers needed)
.venv/bin/python -m eval.run_eval             # experiments -> eval/results/results.md (+ charts)
./demo_cli.sh                                 # backup demo using curl
```

Demo users: `alice/alice123`, `bob/bob123`, `carol/carol123` (patients) and `admin/admin123`.
In the attack scenarios, Bob is the attacker.

On Windows, `.\run.ps1` replaces `./run.sh` (or run `python -m backend.app` and `python -m gateway.app` in two terminals).

## Second target: the main FastAPI application

This folder is part of the team repository. The same gateway, unchanged apart from configuration, also protects the
repository's FastAPI/Strawberry app through its unprotected `/graphql-insecure` endpoint. That schema uses `Int` ids,
`ownerId: Int` and `UserType`/`ResourceType` names, and it is inferred without manual rules.

```powershell
.\run.ps1 -Target fastapi                    # FastAPI app :8000 + gateway :5000
$env:GS_POLICY="policy_fastapi.json"; $env:GS_BACKEND="http://127.0.0.1:8000"; python -m eval.run_eval
```

| File | What it is |
|---|---|
| `gateway/policy_fastapi.json` | Target profile: GraphQL/login/reset paths, principal `UserType`, public fields, corpus |
| `attacks/corpus_fastapi.py` | 12 attacks in 8 categories and 10 benign requests (attacker bob, uid 102) |
| `tests/test_fastapi_target.py` | 39 end-to-end tests; starts the FastAPI app on a throw-away database |
| `eval/results_fastapi/` | Results: full gateway 12/12 prevented, 0/10 false positives |

Users for this target: `alice/alice123`, `bob/bob123`, `charlie/charlie123` (admin). The gateway accepts the app's JWTs when
`GS_JWT_SECRET` is set to the app's `JWT_SECRET` (`run.ps1` defaults it to the development secret).

## Project layout

| Path | What it is |
|---|---|
| `backend/app.py` | ClinicHub: a GraphQL API that authenticates users but never checks ownership (the BOLA target) |
| `common/auth.py` | HMAC-signed tokens (a simplified JWT) shared by backend and gateway |
| `gateway/schema_analyzer.py` | **Module 1**: introspection → ownership model (owned types, owner fields, lookup fields, ID-argument mapping, node field) |
| `gateway/enforcer.py` | **Modules 2-4**: validation, depth/alias/batch limits, pre-flight check, query augmentation, response verification, enumeration detector, 5 protection modes |
| `gateway/store.py` | **Module 5**: SQLite event log and alerts |
| `gateway/app.py` | Flask gateway, dashboard and JSON APIs |
| `gateway/templates/dashboard.html` | **Module 6**: dashboard with KPIs, attack lab, query console, ownership model, logs, alerts and results |
| `gateway/policy.json` | Configuration: public fields, overrides, limits, detector thresholds |
| `attacks/corpus.py` | 14 attacks across 10 categories and 14 benign requests, with a canary-based leak oracle |
| `eval/run_eval.py` | Baseline and ablation experiments (effectiveness, false positives, latency) |
| `tests/test_gateway.py` | 48 pytest tests (ClinicHub) |
| `docs/` | Concepts, design, research plan and the review kit |

## Gateway API

| Method & path | Purpose |
|---|---|
| `POST /graphql` | Protected GraphQL endpoint (supports batching) |
| `POST /login` | Passed through to the backend; returns a token |
| `GET /dashboard` | Security dashboard |
| `GET /api/stats`, `/api/logs`, `/api/alerts` | Dashboard data |
| `GET /api/schema-model` | Inferred ownership model |
| `POST /api/mode` | `{"mode": "off" \| "depth" \| "argcheck" \| "response_only" \| "shield"}` |
| `POST /api/attack/<id>` | Runs one attack against the backend directly and through the gateway |
| `POST /api/reset[?logs=1]` | Restores seed data and clears lockouts (and optionally logs) |
| `GET /api/results` | Latest evaluation results |

Full documentation: [docs/01_CONCEPTS.md](docs/01_CONCEPTS.md), [docs/02_DESIGN.md](docs/02_DESIGN.md),
[docs/03_RESEARCH.md](docs/03_RESEARCH.md), [docs/04_REVIEW_KIT.md](docs/04_REVIEW_KIT.md).

> The backend is intentionally insecure. Run it only on localhost, for education and research.
