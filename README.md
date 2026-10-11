# GraphQL Shield: Schema-Aware Security Gateway 🛡️

**Project Title:** GraphQL Shield: Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities  
**Course/Domain:** Computer Communication and Network Security  
**Team:** Agnihotram Chinmayanand, B.V.Balanilavan, Kapilesh.N, Sakthivel  
**Status:** ✅ 100% Complete (Phases 1-12)

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
  - Body: `{"username": "alice", "password": "alice123"}`
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
  - Schema inference inspection feed. **Requires `ADMIN` JWT role.** Returns the ownership rules the gateway inferred from the GraphQL schema, the rejected/ambiguous relationships, and the priority order used during authorization (see section 6).

---

## 🚀 3. Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/FURYBALA/GraphQL-Shield.git
   cd GraphQL-Shield
   ```

2. **Setup Virtual Environment**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Mac/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize Database**
   ```bash
   python -m app.seed
   ```
   *(This creates `shield.db` and populates `users`, `objects`, and ownership structures).*

5. **Run the Server**
   ```bash
   uvicorn app.main:app --reload
   ```

---

## 🧪 4. Test Instructions

The system features an automated test suite covering authentication, authorization, BOLA (direct, nested, multi-ID, variable and fragment based), the policy engine, risk scoring, audit logging, dashboards, and schema-aware ownership inference.

Current totals (run `python -m pytest tests/ -q`):

| Metric | Count |
|---|---|
| Tests collected | 86 |
| Passing | 86 |
| Failing | 0 |

- **59** pre-existing tests (unchanged, all still passing)
- **27** new tests for schema-aware ownership inference (`tests/test_ownership_inference.py`), including backward-compatibility checks for Demos 1-4

To execute the full suite across all system modules:
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

## 🔬 6. Schema-Aware Ownership Inference

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
# Login as the seeded ADMIN (charlie)
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"charlie\",\"password\":\"charlie123\"}"

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

## ⚠️ 7. Known Limitations
- **Type Inference:** The AST parser infers Object Types based directly on field names (e.g., `resource` -> `Resource`) rather than utilizing full internal schema reflection. Highly complex polymorphic GraphQL schemas may bypass this.
- **Role-Based Limitations:** The system currently relies strictly on Ownership matching and a global `ADMIN` override. Fine-grained RBAC per-field is not supported in this prototype.
- **Database Overhead:** Ownership lookup queries the SQLite database directly per requested object. In a massive production system, this would require Redis/Memcached caching to maintain low latency.

---

## 🔮 8. Future Work
- **Machine Learning Integration:** Replace the deterministic rule-based Risk Engine with an ML anomaly detection model to catch slow, highly distributed reconnaissance attacks.
- **Rate Limiting Engine:** Add a strict rate-limiting gateway specifically for high-risk IP addresses or users exhibiting medium-risk querying patterns.
- **Full Schema Introspection Validation:** Integrate the Gateway directly with the Strawberry Schema registry to perfectly map all incoming aliases and unions to their exact Database tables without relying on inference.
