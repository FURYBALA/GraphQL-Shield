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
5. **Ownership Engine** queries the database to establish the true object owner.
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

The system features an automated, highly comprehensive test suite (36 tests) covering 21 distinct scenarios (including multi-ID sneaking, variable injection, and fragment spread BOLA).

To execute the test suite:
```bash
python -m pytest tests/test_phase_10_comprehensive.py -v
```
To run the entire suite across all system modules:
```bash
python -m pytest tests/
```

To run the Phase 11 Latency Benchmark (Comparing protected vs unprotected overheads):
```bash
python -m scripts.evaluate_performance
```

---

## 🎯 5. Demo Instructions

To manually demonstrate the core BOLA protection to your professor:

**1. Log in as Alice (User 101):**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
-H "Content-Type: application/json" \
-d '{"username":"alice","password":"alice123"}'
```
*(Copy the `access_token`)*

**2. Legitimate Request (Alice requesting Alice's Resource):**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <ALICE_TOKEN>" \
-H "Content-Type: application/json" \
-d '{"query": "{ resource(id: 101) { name } }"}'
```
*Result: HTTP 200 OK (Returns Data)*

**3. Direct BOLA Attack (Alice attempting to read Bob's Resource 102):**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <ALICE_TOKEN>" \
-H "Content-Type: application/json" \
-d '{"query": "{ resource(id: 102) { name } }"}'
```
*Result: HTTP 403 Forbidden (Blocked by Gateway, High Risk Score)*

**4. View Dashboard:**
Navigate to `http://localhost:8000/dashboard` in your browser to see the live telemetry and audit logs of the attacks you just executed.

---

## ⚠️ 6. Known Limitations
- **Type Inference:** The AST parser infers Object Types based directly on field names (e.g., `resource` -> `Resource`) rather than utilizing full internal schema reflection. Highly complex polymorphic GraphQL schemas may bypass this.
- **Role-Based Limitations:** The system currently relies strictly on Ownership matching and a global `ADMIN` override. Fine-grained RBAC per-field is not supported in this prototype.
- **Database Overhead:** Ownership lookup queries the SQLite database directly per requested object. In a massive production system, this would require Redis/Memcached caching to maintain low latency.

---

## 🔮 7. Future Work
- **Machine Learning Integration:** Replace the deterministic rule-based Risk Engine with an ML anomaly detection model to catch slow, highly distributed reconnaissance attacks.
- **Rate Limiting Engine:** Add a strict rate-limiting gateway specifically for high-risk IP addresses or users exhibiting medium-risk querying patterns.
- **Full Schema Introspection Validation:** Integrate the Gateway directly with the Strawberry Schema registry to perfectly map all incoming aliases and unions to their exact Database tables without relying on inference.
