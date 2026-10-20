# GraphQL Shield: Schema-Aware Security Gateway 🛡️

**Project Title:** GraphQL Shield: Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities  
**Course/Domain:** Computer Communication and Network Security  
**Team:** Agnihotram Chinmayanand, B.V.Balanilavan, Kapilesh.N, Sakthivel  
**Status:** ✅ Complete — core gateway (Phases 1–14), differential-testing engine, adaptive anomaly detection, multi-tenant identity integrity, and full test suite (299 passing)

---

## 📖 1. Architecture Overview
GraphQL Shield is a dedicated security gateway designed to intercept, parse, and enforce zero-trust authorization policies on GraphQL traffic *before* it reaches backend resolvers. 

Traditional GraphQL implementations struggle with **Broken Object Level Authorization (BOLA)** because resolvers are executed natively via depth-first graph traversal, making centralized security hard to enforce. GraphQL Shield abstracts this by using Pre-Execution AST Parsing to map all requested objects and enforcing strict contextual authorization.

**Data Flow:**
1. **Client** sends GraphQL Query + JWT.
2. **FastAPI Middleware** intercepts the request.
3. **JWT Extractor** resolves user identity and roles.
4. **AST Normalizer** traverses the syntax tree, resolving variables and fragment spreads, extracting requested `types` and `IDs`.
5. **Schema-Aware Ownership Resolution** combines the explicit database ownership lookup with the ownership model inferred from the GraphQL schema at startup (see section 6). Types with no explainable ownership relationship fail closed.
6. **Policy Engine** evaluates the contextual request against zero-trust rules.
7. **Risk Engine** computes a deterministic risk score (0-100).
8. **Audit Logger** persists the exact decision context to SQLite.
9. **Enforcement Block**:
    - If `ALLOW` -> execution is handed over to the Strawberry GraphQL Engine.
    - If `DENY` -> execution is halted instantly, returning `HTTP 403 Forbidden` and preventing backend processing.

---

## 📡 2. API Documentation

### **Authentication**
- `POST /api/v1/auth/login`
  - Body: `{"username": "balanilavan", "password": "balan123"}` (or alias `{"username": "alice", "password": "alice123"}`)
  - Returns: `{"access_token": "...", "token_type": "bearer"}`

### **GraphQL Endpoints**
- `POST /graphql`
  - The secured endpoint. All requests must carry an `Authorization: Bearer <token>` header.
- `POST /graphql-insecure`
  - A strictly unprotected replica of the endpoint used *only* for the Phase 11 Latency Benchmarks.

### **Monitoring & Dashboards**
- `GET /dashboard`
  - Serves the live, professional HTML statistics UI.
- `GET /api/v1/dashboard-stats`
  - Public data aggregation endpoint for the dashboard UI.
- `GET /api/v1/audit-logs`
  - Secured audit feed. **Requires `ADMIN` JWT role.** Returns recent security events.
- `GET /api/v1/security/schema-ownership`
  - Schema inference inspection feed. **Requires `ADMIN` JWT role.** Returns the ownership rules the gateway inferred from the GraphQL schema, the rejected/ambiguous relationships, and the priority order used during authorization (see section 7).
- `GET /api/v1/security/anomaly`
  - Adaptive behavioural anomaly feed. **Requires `ADMIN` JWT role.** Returns the per-principal anomaly scores derived from the live audit stream (see section 8).

---

## 🚀 3. Setup Instructions

**Fastest path (one command: creates a virtualenv, installs a validated dependency set, seeds the database, and runs the tests):**

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```
```bash
# Linux / macOS / Git Bash / WSL
bash scripts/bootstrap.sh
```

**Manual path:**

1. **Clone the Repository**
   ```bash
   git clone https://github.com/FURYBALA/GraphQL-Shield.git
   cd GraphQL-Shield
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Mac/Linux:
   source .venv/bin/activate
   ```

3. **Install dependencies (reproducible, constraint-pinned)**
   ```bash
   pip install -r requirements.txt -c constraints.txt
   ```

4. **Create the environment file and initialize the database**
   ```bash
   cp .env.example .env
   python -m app.seed
   ```
   *(This creates `shield.db` and populates `users`, `objects`, and ownership structures).*

5. **Run the Server**
   ```bash
   uvicorn app.main:app --reload
   ```

> Full setup, reproduction steps, and troubleshooting: **[`SETUP.md`](./SETUP.md)**.
> Canonical, machine-readable metrics: **[`docs/RESULTS_SUMMARY.json`](./docs/RESULTS_SUMMARY.json)**.

---

## 🧪 4. Test Instructions

The system features an automated test suite covering authentication, authorization, BOLA (direct, nested, multi-ID, variable and fragment based), the policy engine, risk scoring, audit logging, dashboards, schema-aware ownership inference, multi-tenant boundaries, and a dedicated 15-test audit remediation suite.

Current totals (run `python -m pytest tests/ -q`):

| Metric | Count |
|---|---|
| Test files | 28 |
| Tests collected | 299 |
| Passing | 299 |
| Failing | 0 |
| Audit Remediation checks | 15 / 15 |

To execute the 15-check independent audit verification suite (<7s):
```bash
python scripts/verify_audit_remediation.py
```

To execute the full test suite across all system modules:
```bash
python -m pytest tests/ -v
```

To execute only the schema-aware ownership inference suite:
```bash
python -m pytest tests/test_ownership_inference.py -v
```

To run the Phase 11 Latency Benchmark (Comparing protected vs unprotected overheads):
```bash
python -m scripts.evaluate_performance
```

---

## 🎯 5. Quick Start & Demonstration

To best evaluate this project, we highly recommend a **Live Manual Demonstration** where you interact with the running server using real HTTP requests. This proves that the Gateway is dynamically intercepting traffic in real-time.

**Terminal 1 (The Server):**
```bash
# Seed the database and start the FastAPI security server
python -m app.seed
uvicorn app.main:app --reload
```
*(As you send requests, you will see a detailed, live Security Trace output here showing the exact Ownership, Risk, and Policy Evaluation decisions).*

**Terminal 2 (The Client):**
Follow the **[`LIVE_DEMONSTRATION_GUIDE.md`](./LIVE_DEMONSTRATION_GUIDE.md)** for the exact `curl` commands to authenticate and execute:
1. Legitimate GraphQL Access
2. Direct BOLA Attacks
3. Nested BOLA Attacks
4. Invalid JWT Rejections
5. Schema-Aware Ownership Inference (Demo 5)

**Browser (The Dashboard):**
Navigate to `http://localhost:8000/dashboard` to view the live GUI reflecting your manual attacks.

*(Note: We have also provided `python scripts/run_demo.py` as an automated, deterministic regression utility, but the live manual interaction is the primary evaluation method).*

---

## 🧬 6. Primary Research Contribution: AST Taint Analysis & Dual-Path Attribution

The primary contribution of this work is a **schema-aware, pre-execution AST taint analysis** whose findings are correlated with **runtime authorization evidence**, producing accurate *source-to-sink path attribution* without changing any enforcement decision.

- **Schema-aware AST taint analysis** (`app/security/object_extractor.py` plus the taint model and propagation modules) parses every query before execution, resolves variables and fragment spreads, and traces client-controlled object identifiers to sensitive field sinks.
- **Dual-path attribution** records both the **client response path** (the alias the client sees) and the **canonical schema path** (e.g. `Query.resource`), defeating GraphQL field aliasing that blinds ordinary gateways.
- **Runtime correlation** (see `scripts/evaluate_phase_7.py`, Method 3) pairs each taint finding with the deterministic gateway decision, so static false alarms on legitimately-owned resources are suppressed instead of alerted.

Measured on the independent **115-case benchmark** (105 valid: 52 vulnerable / 53 benign, 10 malformed):

| Method | Precision | Recall | F1 | False-Alarm Rate | Exact Path Attribution | Semantic Attribution |
|---|---|---|---|---|---|---|
| M1 — Gateway alone | 100.0% | 100.0% | 1.000 | 0.0% | 56.2% (59/105) | 65.7% (69/105) |
| M2 — Static taint alone | 54.7% | 100.0% | 0.708 | **81.1%** | **90.5%** (95/105) | **100.0%** (105/105) |
| M3 — Correlated (ours) | 100.0% | 100.0% | 1.000 | 0.0% | **90.5%** (95/105) | **100.0%** (105/105) |

**Headline result:** correlation preserves the gateway's 100% precision/recall while eliminating static analysis's 81.1% false-alarm rate, and raises exact path attribution from 56.2% to 90.5% (95/105) under strict canonical matching and 100.0% (105/105) under semantic target attribution — with **zero** behavioral divergence across all 115 cases. The full academic treatment (formal model, algorithms, ablation, related work) is in [`docs/RESEARCH_PAPER_DRAFT.md`](./docs/RESEARCH_PAPER_DRAFT.md).

Reproduce with `SETUP.md` §5; canonical metrics in `docs/RESULTS_SUMMARY.json`; raw run transcripts in `docs/evidence/`.

---

## 🔬 7. Schema-Aware Ownership Inference

### Why hard-coded ownership rules are limited

The original gateway determined ownership with a hard-coded lookup: *"everything that is not a user is read from the `objects.owner_id` column"*. That works for this demo schema, but it does not scale: every new type, table, or relationship requires a code change inside the security gateway, and the gateway itself cannot explain *why* a given object is owned by a given user. Ownership knowledge lives in the application code instead of in the schema that the API already publishes.

### How the GraphQL schema contains relationship information

GraphQL schemas already describe the shape of ownership:

```graphql
type User {
    id: ID!
    resources: [Resource]      # User -> resources -> Resource
}

type Resource {
    id: ID!
    owner_id: ID!              # Resource.ownerId identifies the owning User
}
```

A field called `owner`, `ownerId`, `userId` or `createdBy` that points at a user-like type, and a collection field that points back at a resource type, are both strong, *readable* signals about who owns what.

### How the gateway analyzes the schema

At application startup (`startup` event in `app/main.py`), `app/security/ownership_inference.py` walks the Strawberry type registry once and converts every object type into an internal model of `(field name, resolved type name)` pairs. Field names are normalized (`ownerId` -> `owner_id`) and type names are normalized (`Resource` == `ResourceType`) so that query-derived names and schema names line up. The result is stored in a read-only singleton (`inference_engine`); **no schema analysis is repeated per request** — request handling only reads the pre-built model.

Each accepted rule is an inspectable record:

| source_type | source_field | target_type | confidence | pattern | reason |
|---|---|---|---|---|---|
| ResourceType | owner_id | UserType | HIGH | OWNER_FIELD | scalar ownership identifier referencing UserType |
| UserType | resources | ResourceType | MEDIUM | COLLECTION | collection of ResourceType |
| UserType | id | UserType | HIGH | SELF_OWNERSHIP | type owns its own record |

### Supported inference patterns (defined, not magical)

This prototype supports a **defined and explainable set of schema patterns**, not automatic ownership inference for every GraphQL API:

- **Pattern A** — `Resource.owner: User` → `Resource.owner → User` (object reference)
- **Pattern B** — `User.resources: [Resource]` → `User.resources → Resource` (collection)
- **Pattern C** — `Resource.ownerId: ID` → `Resource.ownerId → User` (scalar identifier)
- **Pattern D** — nested chains of A/B/C, e.g. `User → resources → Resource → owner`

Matching is driven by a configurable naming list (`owner`, `owner_id`, `user_id`, `created_by`, `author`, ...). Relationships that match a name but cannot be validated — for example a `createdBy: String` label — are **not** accepted; they are recorded as ambiguous in the report.

### Explicit policies always take precedence

The gateway resolves ownership in a fixed priority order, which is also printed by the inspection endpoint:

1. **Explicit configured authorization / ownership rule** (and the authoritative database ownership lookup)
2. **Validated schema-inferred ownership rule** (used to explain and to gate the lookup)
3. **UNKNOWN OWNERSHIP → explicit policy required → DENY**

Inference **never** overrides an explicit rule and **never** invents an owner id: the actual owner of an instance is always read from the explicit database lookup. The inference engine only tells the gateway *which* relationship to expect for a type, and annotates every decision (live terminal trace and the inspection endpoint) with the rule that justified it.

### Fail-closed behavior

If neither an explicit rule nor a validated inferred rule explains a requested object type, the gateway returns `HTTP 403` with `reason: UNKNOWN_OWNERSHIP` and a `HIGH` risk score instead of guessing. Uncertainty never results in access.

### Inspecting the inferred rules

```bash
# Login as the seeded ADMIN (kapilesh / sakthivel)
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"kapilesh\",\"password\":\"kapilesh123\"}"

curl "http://localhost:8000/api/v1/security/schema-ownership" \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

The response contains the actual analysis of the real schema: `types_analyzed`, `analyzed_types`, `relationships_detected`, per-confidence counts, `ambiguous_relationships`, the accepted `rules`, the `rejected` relationships with reasons, and the `priority` list. The same summary is printed to the console at startup under `[Schema Ownership Inference]`.

### Generating the inference report

```bash
python scripts/generate_inference_report.py
```

This re-analyzes the real schema and writes `ownership_inference_report.json` (summary, accepted rules with confidence and reason, rejected/ambiguous relationships, priority order). Current output of the actual schema:

```
GraphQL types analyzed:               3
Ownership relationships detected:      3
High-confidence rules:                 2
Medium-confidence rules:               1
Ambiguous/rejected relationships:      0
```

The numbers are computed at generation time; they are never hard-coded.

### Honest limitations

- The engine recognizes the patterns listed above; exotic ownership models (polymorphic owners, join tables, multi-tenant scoping) are **not** inferred automatically and would fall back to `UNKNOWN_OWNERSHIP` unless an explicit rule is configured.
- Inference validates and explains relationships; it does not replace instance-level ownership data, which still comes from the database.
- Type names are matched with a normalization heuristic (`Resource` == `ResourceType`), so unconventional naming may require an explicit rule.

---

## 8. Adaptive Behavioural Anomaly Detection (Complementary Novelty)

### The gap in per-event scoring

The deterministic `risk_engine.py` scores every authorization decision *in isolation*: an ownership
mismatch is `80 / HIGH`, a clean access is `0 / LOW`. It is stateless across requests, so it cannot tell a
one-off mistake from sustained abuse, and it assigns **risk 0** to a compromised account that stays fully
authorized while rapidly enumerating every record it can reach (mass data access). It also cannot see a
low-and-slow scan that hides between ordinary reads.

### What the novelty adds

`app/security/anomaly_engine.py` adds a complementary, **unsupervised principal-level** layer. It reads
the audit events the gateway has already persisted and derives four behavioural signals per principal:

| Signal | Meaning |
|---|---|
| `deny_ratio` | share of the principal's requests that were denied |
| `target_breadth` | number of distinct object identifiers requested |
| `velocity` | requests per minute within the principal's own activity span |
| `deny_trend` | escalation of the deny ratio between the older and recent half of the history |

Two adaptive mechanisms turn these into a score instead of a fixed table:

1. **Robust peer-relative baseline** — each feature becomes a median/MAD robust z-score against the
   observed principal population, so "normal" moves with the traffic rather than being hard-coded.
2. **Temporal drift** — `deny_trend` compares a principal against its *own* earlier behaviour, catching a
   stable principal that suddenly turns abusive.

Each feature's deviation is `max(peer z-score, value / documented absolute threshold)` — the absolute term
is a floor that keeps the engine usable on the 3-user demo population and during cold start. Per-feature
contributions are combined as a blend of the weighted mean and the **peak** signal, so one unmistakable
indicator is not diluted. The result is a `0–100` score and a `LOW/MEDIUM/HIGH` level plus an explainable
pattern label (`HIGH_VELOCITY_ENUMERATION`, `SUSTAINED_AUTHORIZATION_ABUSE`, `BROAD_TARGET_SCAN`,
`ESCALATING_DENY_PATTERN`).

The layer is **advisory only**: it never grants, denies, or mutates an enforcement decision. It is exposed
at `GET /api/v1/security/anomaly` (ADMIN) and rendered live on the dashboard.

### Measured evaluation vs the baseline

```bash
python scripts/evaluate_anomaly.py
```

The script generates **real traffic through the live gateway** (so every audit row is produced by the real
enforcement middleware) and compares the static per-event baseline (max single-event risk ≥ 60) against the
adaptive engine (score ≥ 60) on the identical audit stream. Actual output:

| Principal | Ground truth | Events | Max static risk | Static flagged | Adaptive score | Adaptive level | Pattern |
|---|---|---|---|---|---|---|---|
| 101 | benign | 3 | 0 | no | 34 | MEDIUM | NO_PATTERN |
| 102 | attack (mass authorized enumeration) | 15 | 0 | **no** | 65 | HIGH | HIGH_VELOCITY_ENUMERATION |
| 103 | benign (admin) | 2 | 0 | no | 25 | LOW | NO_PATTERN |
| 104 | attack (direct BOLA burst) | 6 | 90 | yes | 80 | HIGH | SUSTAINED_AUTHORIZATION_ABUSE |

| Engine | Detection rate | False-positive rate |
|---|---|---|
| Static per-event baseline | 50.0% | 0.0% |
| Adaptive behavioural engine | **100.0%** | **0.0%** |

The static engine flags the direct BOLA burst (risk 90) but **structurally cannot** flag the mass authorized
enumeration (every event is a legitimate `ALLOW` with risk 0). The adaptive engine detects both behaviours
from aggregate signals without flagging either benign principal. Full machine-readable output is written to
`anomaly_evaluation.json`.

### Honest limitations

- The mass-enumeration case is **authorized** activity (no BOLA bypass); it is a behavioural anomaly, not
  an authorization failure. The layer complements — it does not replace — the per-event BOLA enforcement.
- Thresholds (60 = HIGH) and feature weights are configurable and were tuned on the small demo population.
  The benign principal scored 34 (MEDIUM, below the flag threshold); a slower or lower-breadth profile
  scores lower. Larger deployments should re-tune on real traffic.
- The peer-relative term needs at least two active principals to discriminate; below that it falls back to
  absolute behavioural thresholds.
- The dashboard automatically runs the built-in differential-testing suite when it loads. Those are real
  requests through the gateway, so the anomaly panel aggregates them too, and test callers that repeatedly
  provoke denials will legitimately score HIGH. The controlled evaluation above uses an isolated database
  with no harness traffic.

---

## 9. Known Limitations
- **Type Inference:** The AST parser infers Object Types based directly on field names (e.g., `resource` -> `Resource`) rather than utilizing full internal schema reflection. Highly complex polymorphic GraphQL schemas may bypass this.
- **Role-Based Limitations:** The system currently relies strictly on Ownership matching and a global `ADMIN` override. Fine-grained RBAC per-field is not supported in this prototype.
- **Database Overhead:** Ownership lookup queries the SQLite database directly per requested object. In a massive production system, this would require Redis/Memcached caching to maintain low latency.

---

## 🔮 10. Future Work
- **Learned Anomaly Models:** The current adaptive layer is unsupervised and explainable; future work is to
  compare it against trained models (isolation forests, sequence models) once multi-day traffic is available.
- **Rate Limiting Engine:** Add a strict rate-limiting gateway specifically for high-risk IP addresses or users exhibiting medium-risk querying patterns.
- **Full Schema Introspection Validation:** Integrate the Gateway directly with the Strawberry Schema registry to perfectly map all incoming aliases and unions to their exact Database tables without relying on inference.

---

## 11. Real-Time Authorization Research Engine

A live research engine built on top of the existing gateway, ownership
inference, AST analysis, audit logging and exporters. It turns GraphQL Shield
from a static gateway into an end-to-end authorization testing tool:

```
Discover schema  ->  Generate tests  ->  Run real HTTP  ->  Inspect finding
       ->  Reproduce/minimize  ->  Export (SARIF + JUnit)
```

Implementation lives in `app/security/recon/`:

| Module | Responsibility |
| --- | --- |
| `introspection.py` | **Live schema reconnaissance**: introspects the running service (or SDL) and builds a navigation graph of operations, arguments, nested relations, identifiers and authorization boundaries. Nothing is hardcoded. |
| `generator.py` | **Automated test generation** from the discovered schema using the seeded accounts/resources, with per-test provenance (`seeded_fixture` vs `exploratory`) and the expected authorization outcome. |
| `oracle.py` | **Differential oracle (expectation side)**: replays `normalize_query -> resolve_ownership -> PolicyEngine`, the exact pipeline the gateway uses. |
| `executor.py` | **Real HTTP execution** against `/graphql` (protected) and `/graphql-insecure` (deliberately vulnerable local reference backend), with bounded concurrency, cancellation, and object-identity / database-state inspection. |
| `reproducer.py` | **Automatic reproduction & AST minimization** (delta debugging) for confirmed violations; keeps the original query if minimization cannot make progress. |
| `engine_exporters.py` | **Validated SARIF 2.1.0 and JUnit XML** generated only from executed results. |
| `engine.py` / `api.py` | Orchestration (sessions, progress, cancellation) and the workbench REST API. |

### Guarantees

- A vulnerability is **never asserted from an HTTP status alone**. Query leaks
  are confirmed by the returned object's owner; mutation leaks by the resulting
  database state.
- **Fixture leaks are separated from gateway findings.** Leaks observed on the
  labelled vulnerable backend (`/graphql-insecure`) are baseline sensitivity
  signals and never emitted as SARIF findings.
- Discovery is **schema-driven**; supplying a different schema yields different
  discovered paths (verified by test).
- Standard introspection is served by the introspection-capable route because
  the **protected gateway's AST budget deliberately rejects the standard
  introspection query** — this hardening is not weakened.

### Workbench

Start the server and open [http://127.0.0.1:8000/workbench](http://127.0.0.1:8000/workbench)
for the dark research console (6 areas: schema graph, generated tests, live
execution console, gateway-vs-fixture comparison, confirmed findings + evidence,
audit trace + exports).

### Running it

```bash
python -m app.seed
uvicorn app.main:app --reload
# then open /workbench, or drive the API:
#   POST /api/v1/authorization-engine/discover
#   POST /api/v1/authorization-engine/generate
#   POST /api/v1/authorization-engine/run        -> { session_id }
#   GET  /api/v1/authorization-engine/runs/{id}
#   GET  /api/v1/authorization-engine/runs/{id}/export/sarif
#   GET  /api/v1/authorization-engine/runs/{id}/export/junit
```

### Evaluation

```bash
python scripts/evaluate_authorization_engine.py
```

Writes `docs/AUTHORIZATION_ENGINE_EVAL.json` and
`docs/evidence/authorization_engine_eval.txt`. Every number is measured from the
latest run against the documented manual baseline (4 hand-written cases).

### Tests

```bash
python -m pytest tests/test_authorization_engine.py -q
```

13 acceptance tests covering discovery, generation, real execution, legitimate
owner access, gateway denial of cross-owner access, fixture leakage with
evidence, reproduction/minimization, export validity and the API/UI surface.

### Honest limitations

- Evaluation is performed against this application's own schema and seeded data.
  It does **not** prove compatibility with arbitrary production schemas.
- The deliberately vulnerable backend is a local fixture, not a real third-party
  service; leakage there demonstrates resolver behaviour without the gateway.
- Minimization reduces scalar selections; it does not attempt argument synthesis.

