# GraphQL Shield — Live Demo Runbook (Faculty Demonstration)

Concise, repeatable **five-minute** demonstration of the live GraphQL authorization
research workbench. Everything below was executed and verified on this machine
(Windows, Python 3.14.5) against the real running application.

> **Default landing page is the workbench at `/`.** The legacy KPI dashboard
> remains available at `/dashboard` for the audit / anomaly / benchmark views,
> but it is no longer the primary experience.

---

## 0. Preflight checklist (before the evaluator arrives)

| Check | Command | Expected |
|---|---|---|
| Python present | `python --version` | `Python 3.11+` (validated on 3.14.5) |
| Dependencies installed | `pip install -r requirements.txt -c constraints.txt` | all satisfied |
| Tests green | `python -m pytest tests/ -q` | `299 passed` |
| Audit checks | `python scripts/verify_audit_remediation.py` | `15 passed (<7s)` |
| Port 8000 free | `Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue` | no output |
| Clean database | `python -m app.seed` | `Database successfully seeded.` |

If dependencies are missing, bootstrap in one command:
`powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1`.

**Known-clean data is essential.** Verify before the demo:

```powershell
python -c "import sqlite3;c=sqlite3.connect('shield.db');print([tuple(r) for r in c.execute('SELECT id,name,owner_id FROM objects ORDER BY id')])"
```

Expected: `101 Alice's Secret Note 101` · `102 Bob's Financial Record 102` · `103 Charlie's Admin Log 103` ·
`201 Alice's Projects 101` · `202 Project Alpha Plan 101` · `203 Project Beta Plan 101`.

---

## 1. Startup

Terminal 1 (keep visible — the `[Schema Ownership Inference]` trace prints on boot):

```powershell
python -m app.seed
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open the workbench:

```
http://127.0.0.1:8000/
```

You should see the three-pane **Authorization Research Engine**: Schema explorer (left),
operation editor + **Run Test** (centre), Evidence panel (right), and the
History / Tests / Execution / Gateway vs Fixture / Findings / Audit tabs below.

> The workbench's **base target URL** defaults to `window.location.origin` (`http://127.0.0.1:8000`).
> All actions issue real HTTP requests to that origin.

---

## 2. Five-minute demonstration script

Each step can be driven from the **workbench UI** and/or the equivalent **CLI**.
Log in as Balanilavan (user 101, `balanilavan` / `balan123` or alias `alice` / `alice123`) once:

```powershell
$token = (Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/auth/login" `
  -ContentType "application/json" -Body '{"username":"balanilavan","password":"balan123"}').access_token
```

### Step 1 — Discover the schema (~40s)

**UI:** click **Discover** (top of the Schema pane).
**Expected:** schema tree populated, status line shows `introspection` source and the
operations `health, user, resource` (queries) and `updateResource, transferOwnership` (mutations).
**CLI equivalent:**

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/authorization-engine/discover" `
  -ContentType "application/json" -Body '{"base_url":"http://127.0.0.1:8000"}'
```

### Step 2 — Legitimate owner request (~40s)

**UI:** caller = `balanilavan` (ID 101), query `query { resource(id: 101) { id name ownerId secretKey } }`, click **▶ Run Test**.
**Expected:** gateway `HTTP 200` · decision `ALLOW` · reason `OWNER_MATCH`; Balanilavan's own record returned;
audit row `ALLOW / OWNER_MATCH`.

### Step 3 — Direct BOLA attack (~40s)

**UI:** change the target id to `102` (owned by Chinmayanand), click **▶ Run Test**.
**Expected:** gateway `HTTP 403` · decision `DENY` · reason `OWNERSHIP_MISMATCH` · risk `HIGH`;
the insecure fixture (`/graphql-insecure`) returns Chinmayanand's record with `HTTP 200` — the **Gateway vs Fixture**
comparison shows the protected gateway blocked what the vulnerable endpoint leaked.
**CLI equivalent:**

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/graphql" `
  -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" `
  -Body '{"query":"{ resource(id: 102) { id name } }"}'
# Expect HTTP 403 · OWNERSHIP_MISMATCH · risk HIGH
```

### Step 4 — Nested BOLA attack (~40s)

**UI:** use the **Nested BOLA** preset, click **▶ Run Test**.
**Expected:** gateway `HTTP 403` · decision `DENY` · reason `NESTED_AUTHORIZATION_VIOLATION` · risk `HIGH`;
two audit events (`user` allowed → `user.resource` denied).
**CLI equivalent:**

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/graphql" `
  -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" `
  -Body '{"query":"{ user(id: 101) { username resource(id: 102) { name } } }"}'
# Expect HTTP 403 · NESTED_AUTHORIZATION_VIOLATION · risk HIGH
```

### Step 5 — Mutation BOLA + automatic state restore (~30s)

**UI:** use the **Mutation BOLA** preset (`mutation { updateResource(id: 102, name: "probe") … }`), click **▶ Run Test**.
**Expected:** gateway `HTTP 403` · `DENY` · `OWNERSHIP_MISMATCH`; the evidence panel shows
`before == after` and **state restored** (the workbench snapshots the target object and reverts it).

### Step 6 — Inspect the evidence and audit record (~40s)

In the **Evidence** panel confirm, for the request just executed:

- **Observed HTTP** — the real status, headers and response body.
- **Decision** — the gateway's authorization decision and reason.
- **Canonical AST path** — e.g. `resource` or `user.resource`.
- **Ownership** — the resolved owner of each object (fail-closed pipeline).
- **Audit event** — the persisted row (`decision`, `reason`, `path`, `user_id`, `object_id`).
- **Differential** — gateway vs insecure fixture.

**Verify persist-/retrievability from the DB (ADMIN API):**

```powershell
$admin = (Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/auth/login" `
  -ContentType "application/json" -Body '{"username":"kapilesh","password":"kapilesh123"}').access_token
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/audit-logs" -Headers @{ Authorization = "Bearer $admin" }
```

### Step 7 — Research contribution and limitations (~60s)

> **Contribution.** GraphQL Shield is a schema-aware, pre-execution **AST taint analysis**
> whose findings are **correlated with runtime authorization evidence** in an audit-only,
> backward-compatible mode. On our benchmark it raises exact source-to-sink path attribution
> from **56.2% to 90.5% (95/105)** under strict canonical matching and **100.0%** under semantic target attribution, verifies authorization boundaries for **100% of protected entities**,
> preserves **100% of gateway decisions** (zero divergence), and **suppresses the 81.1%
> false-alarm rate of static-only taint analysis** — without changing any enforcement decision.
> This live workbench makes that pipeline executable end-to-end: *discover → generate → execute
> → inspect evidence → persist audit*.

> **Limitations (stated honestly).** (1) Ownership matching + a global `ADMIN` override only —
> no fine-grained per-field RBAC. (2) AST type inference is field-name based (`resource → Resource`),
> so exotic polymorphic schemas may evade it; the extractor only tracks nested objects that carry
> an explicit `id:` argument, so relationship-only traversal is not attributed. (3) Ownership is
> looked up per-request in SQLite (a production build needs a cache). (4) The 100% benchmark
> precision/recall applies to our modelled, deterministic corpus, not to arbitrary enterprise
> schemas. (5) The AI analyst layer is advisory-only and, on unconfigured credentials, runs on a
> deterministic mock provider.

---

## 3. Automated end-to-end proof (asserts HTTP + decision + persisted audit)

With the server already running against a fresh database:

```powershell
python scripts/e2e_live_proof.py
```

Drives the **real HTTP endpoints** and asserts, per scenario, the response, the deterministic
policy decision, and the persisted audit row. Expected: `11/11 checks passed`.
Transcript: `docs/evidence/e2e_demo.txt`.

The workbench's own API surface is equivalent and fully exerciseable from the UI:
`/api/v1/authorization-engine/{identities,discover,execute,generate,run}`, plus
`/api/v1/differential-testing/*` and `/api/v1/security/*`.

---

## 4. Evaluation commands (evidence for the report)

```powershell
python scripts/verify_audit_remediation.py                  # 15/15 passed (<7s, all 5 audit remediations verified)
python -m pytest tests/ -q                                   # 299 passed (~60s)
python scripts/build_ground_truth_corpus.py                  # 115-case corpus (105 valid)
python scripts/evaluate_taint_corpus.py --corpus data/ground_truth_corpus.json --output docs/EVALUATION_REPORT.json
python scripts/evaluate_phase_7.py --corpus data/ground_truth_corpus.json --output docs/PHASE_7_RESULTS.json
python scripts/evaluate_anomaly.py                           # static 50% -> adaptive 100% detection, 0% FP
python -m scripts.evaluate_performance                       # 100% BOLA detection; ~15-17 ms overhead (machine dependent)
python scripts/generate_inference_report.py                  # schema ownership inference report
```

Consolidated metrics: `docs/RESULTS_SUMMARY.json`. Raw transcripts: `docs/evidence/`.
Latency figures vary by host; the deterministic security and attribution metrics reproduce exactly.

---

## 5. Troubleshooting & recovery

| Symptom | Cause | Fix |
|---|---|---|
| `database is locked` | server running while seeding | stop the server, run `python -m app.seed`, restart |
| `ModuleNotFoundError: app` | wrong cwd | run all commands from the project root |
| Workbench shows the old KPI dashboard | a **stale server** (started before the workbench existed) is on port 8000 | stop it and restart: `Get-NetTCPConnection -LocalPort 8000 -State Listen \| Select OwningProcess` → `Stop-Process -Id <pid> -Force`, then restart |
| `Address already in use` | a previous server is still running | find and stop it (command above), then restart |
| `Connection lost — retrying…` / blank panels | server not running / wrong port | start uvicorn on port 8000 |
| 403 on `/api/v1/security/*` or `/api/v1/audit-logs` | not using the ADMIN token | log in as `kapilesh` / `kapilesh123` (or `sakthivel` / `sakthivel123` / alias `charlie`) |
| Port 8000 blocked by firewall prompt | first run | allow on private networks, or use `--port 8010` and update the base URL in the workbench |
| Object names look altered (e.g. `Alice Valid Update`) | a prior differential/anomaly run (or an old dashboard auto-run) drifted the seed row | stop the server, `python -m app.seed`, restart |

**If the server is unavailable mid-demo:** in Terminal 1 press `Ctrl+C`, then re-run the two
startup commands from Section 1. The workbench is stateless — reload the page; all state comes
from the backend. Re-seed if any object state looks non-canonical.

---

## 6. Reset for a clean run

```powershell
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
python -m app.seed
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
