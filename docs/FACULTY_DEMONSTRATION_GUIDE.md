# Faculty Demonstration Guide: GraphQL Shield

**Project Title:** Correlating AST-Based GraphQL Path Analysis with Runtime Authorization Evidence for Explainable BOLA Auditing  
**Course:** Computer and Communication Network Security (CCNS)  
**Presenter:** Project Team  
**Evaluation Mode:** Live Demonstration & Research Defense  
**Research Question:** *"Does correlating schema-aware, AST-driven GraphQL taint analysis with runtime authorization evidence improve the accuracy of security-path attribution and the auditability of authorization decisions while preserving existing gateway enforcement behavior?"*

---

## 0. Executive Checklist Before Presentation

- [ ] Ensure the server is running on `http://127.0.0.1:8000` (started in Terminal 1).
- [ ] Open a browser tab to the **Live Dashboard**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) (scroll down to the **Real-World Security Scenario Lab**).
- [ ] Open a browser tab to the **OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
- [ ] Open Terminal 2 for executing live client queries and automated scripts.
- [ ] Have the evaluation reports ready: `docs/FINAL_RESEARCH_REPORT.md` and `docs/REAL_WORLD_CASE_STUDIES.md`.

---

## 1. Opening Pitch (2 Minutes: The Real-World Academic Problem)

**What to say to your professor:**
> *"Respected Faculty / Professor,*
>
> *Our project addresses **Broken Object-Level Authorization (BOLA)**, ranked #1 on the OWASP API Security Top 10 (API1:2023). BOLA occurs when an authenticated user manipulates object identifiers to access sensitive resources belonging to another tenant.*
>
> *While BOLA is well-studied in flat REST APIs, it is far more dangerous and difficult to audit in **GraphQL**. In GraphQL, clients can formulate arbitrary, hierarchical queries using **field aliases**, **fragments**, and **nested relationship traversals** (such as `user.resources` or team workspace collections).*
>
> *A prominent real-world example is **Hoppscotch GitHub Advisory GHSA-m5pg-r4jp-qq75** (CVE-pending, fixed in v2026.2.0), where an authenticated user could read any user's private collection simply by supplying an arbitrary `userCollectionID` because the GraphQL resolver lacked object-level ownership checks.*
>
> *Current defenses fall into two flawed extremes:*
> 1. ***Gateway Black-Box Enforcers:*** *They return generic HTTP 403 Forbidden responses without schema coordinates, and they lose track of indirect traversals and client aliases (only 56.2% exact path attribution).*
> 2. ***Purely Static Taint Analysis (e.g., Lambers et al., LMCS 2026):*** *While Lambers et al. proved that AST taint analysis can discover graph API access control flaws, static analysis alone produces an **81.1% false alarm rate** on benign queries because it cannot inspect runtime JWT credentials or database ownership records.*
>
> *Our research contribution is **GraphQL Shield**: an AST-driven, context-sensitive taint propagation engine that correlates with runtime authorization evidence in an **audit-only, backward-compatible mode**. It raises exact path attribution from **56.2% to 89.5%**, verifies authorization boundaries for **100% of protected entities**, preserves 100% of gateway decisions with **zero divergence**, and adds **less than 0.3 milliseconds of latency**.*
>
> *I will now demonstrate our system live across the 7-step sequence: baseline vulnerability, direct BOLA, indirect nested traversal, alias disambiguation, the Hoppscotch real-world case study, explainability verification in our Scenario Lab, and empirical benchmark proof."*

---

## 2. Act 1: The Baseline Vulnerability (Why GraphQL Needs This)

**Objective:** Prove why an unshielded GraphQL API fails against BOLA.

**What to do in Terminal 2:**
```powershell
# 1. Acquire Alice's Token (Tenant 1, User ID 101)
$AliceResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/auth/login" -Method Post -ContentType "application/json" -Body '{"username":"alice","password":"alice123"}'
$AliceToken = $AliceResp.access_token

# 2. Query the INSECURE GraphQL Endpoint (/graphql-insecure) requesting Bob's doc (ID 102)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql-insecure" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { resource(id: 102) { id name } }"}'
```

**What happens on screen:**
- Returns `HTTP 200 OK` with Bob's data: `{"data": {"resource": {"id": 102, "name": "Bob's Financial Plan"}}}`.

**What to tell your professor:**
> *"As you can see, without our gateway, Alice can freely access Bob's private financial data simply by altering the ID argument. The resolver executed the query without tenant isolation."*

---

## 3. Act 2: Direct BOLA Prevention & Live Gateway Trace (Step 1)

**Objective:** Show live enforcement and AST taint detection on the protected gateway endpoint (`/graphql`).

**What to do in Terminal 2:**
```powershell
# Query the PROTECTED Gateway (/graphql) requesting Bob's doc (ID 102)
try {
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { resource(id: 102) { id name } }"}'
} catch {
  $_.ErrorDetails.Message
}
```

**What happens on screen:**
- Returns **`HTTP 403 Forbidden`** with structured detail:
  ```json
  {"decision": "DENY", "user_id": 101, "object_id": 102, "reason": "OWNERSHIP_MISMATCH", "risk_score": 90, "risk_level": "HIGH"}
  ```
- Terminal 1 (Server Log) prints the rich live trace:
  ```text
  [AUTH] User ID: 101, Role: USER
  [OWNERSHIP] Requesting User: 101 | True Owner ID: 102 (EXPLICIT_DB)
  [AUTHORIZATION] Decision: DENY | Reason: OWNERSHIP_MISMATCH | Risk: HIGH (90/100)
  [TAINT ANALYSIS] Mode: audit_only | Candidates: 1 direct | Correlation: TRUE_POSITIVE_BLOCKED
  [ENFORCEMENT] HTTP 403 Forbidden - Request Dropped.
  ```

**What to tell your professor:**
> *"The gateway intercepts the request prior to GraphQL resolver execution. It resolved ownership of Resource 102 from the database, detected that Alice (101) does not match Bob (102), assigned a High Risk score of 90/100, and immediately dropped the request with HTTP 403."*

---

## 4. Act 3: Indirect BOLA & Nested Relational Traversal (Step 2)

**Objective:** Demonstrate defense against indirect collection traversals where the target has no explicit ID argument.

**What to do in Terminal 2:**
```powershell
# Alice queries Bob's user node and traverses into his resources collection
try {
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { user(id: 102) { resources { id name } } }"}'
} catch {
  $_.ErrorDetails.Message
}
```

**What happens on screen:**
- Returns **`HTTP 403 Forbidden`** (`OWNERSHIP_MISMATCH`).
- In server logs:
  - Static Taint Engine identifies relationship context: `UserType.resources` (One-to-Many collection sink `SinkKind.RELATIONSHIP_COLLECTION`).
  - Correlation classification: `TRUE_POSITIVE_BLOCKED`.

---

## 5. Act 4: False-Alarm Prevention & Legitimacy Verification (Step 3)

**Objective:** Prove that legitimate traffic is allowed and explain why static-only taint analysis fails without correlation.

**What to do in Terminal 2:**
```powershell
# Alice requests her OWN document (ID 101)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { resource(id: 101) { id name } }"}'
```

**What happens on screen:**
- Returns **`HTTP 200 OK`**:
  ```json
  {"data": {"resource": {"id": 101, "name": "Alice's Secret Note"}}}
  ```
- Server log prints:
  ```text
  [AUTHORIZATION] Decision: ALLOW | Reason: OWNER_MATCH | Risk: LOW (10/100)
  [TAINT ANALYSIS] Correlation: RUNTIME_PROTECTED_ALLOWED
  ```

**What to tell your professor:**
> *"Here is the scientific importance of correlation: Static taint analysis flagged argument `id` as untrusted input reaching a sensitive sink. Lambers et al. and static-only scanners would report this as a vulnerability candidate — an 81.1% false alarm rate on our benchmark! But our correlation engine evaluates the runtime JWT against the database, sees `OWNER_MATCH`, and marks it `RUNTIME_PROTECTED_ALLOWED`."*

---

## 6. Act 5: Client Alias Disambiguation (Step 4)

**Objective:** Show that field aliases do not blind our AST engine.

**What to do in Terminal 2:**
```powershell
# Alice attempts to access Bob's resource using alias 'stolenDoc'
try {
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { stolenDoc: resource(id: 102) { id name } }"}'
} catch {
  $_.ErrorDetails.Message
}
```

**What to tell your professor:**
> *"An attacker aliases `resource` to `stolenDoc`. A regex or URL gateway only sees `stolenDoc`. Our AST traverser maps the client response path `stolenDoc` back to the underlying canonical schema path `resource` on `ResourceType`, maintaining full path attribution accuracy."*

---

## 7. Act 6: Real-World Case Study A (Hoppscotch IDOR Reproduction — Step 5)

**Objective:** Demonstrate reproduction of GitHub Advisory `GHSA-m5pg-r4jp-qq75` in a controlled, academic test environment.

**What to do in Terminal 2:**
```powershell
# Alice attempts to access Bob's collection (ID 102) via userCollection query
try {
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { userCollection(userCollectionID: 102) { id name } }"}'
} catch {
  $_.ErrorDetails.Message
}
```

**What happens on screen:**
- Returns **`HTTP 403 Forbidden`** with reason `OWNERSHIP_MISMATCH`.
- Gateway extracts `object_id = 102`, maps to database owner `102` (Bob), and halts execution before any resolver data leakage can occur.

**What to tell your professor:**
> *"In Hoppscotch prior to v2026.2.0, this exact pattern allowed unauthorized collection harvesting across users. In our gateway, the pre-execution policy engine enforces strict tenant isolation while the AST taint engine captures the exact schema sink and flags a true positive."*

---

## 8. Act 7: The Interactive Scenario Lab & Dashboard Audit (Step 6)

**Objective:** Show the faculty the live interactive dashboard and real-time audit intelligence.

**What to do:**
1. Switch to your browser tab at **`http://localhost:8000/dashboard`**.
2. Scroll to the new **Real-World Security Scenario Lab** section.
3. Click through the 4 scenario tabs:
   - **Hoppscotch Collection IDOR (`GHSA-m5pg-r4jp-qq75`)**: Shows Alice $\to$ Bob's collection 102, HTTP 403 Forbidden, `TRUE_POSITIVE_BLOCKED`, and boundary evidence verified (`caller_bound=True`, `target_bound=True`, `ownership_checked=True`).
   - **Aliased Nested Traversal**: Shows client alias `targetUser.userDocs` disambiguated to canonical path `user.resources`.
   - **SaaS Multi-Tenant Isolation**: Shows tenant isolation across enterprise document repositories.
   - **Legitimate Owner Access**: Shows Alice accessing her own document 101, HTTP 200 OK, and `RUNTIME_PROTECTED_ALLOWED` preventing false alarm.
4. Show the live JSON scenario API in Terminal 2:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/security/scenario-lab" -Method Get | ConvertTo-Json -Depth 3
```

---

## 9. Act 8: Automated Live Showcase & Benchmark Proof (Step 7)

**Objective:** Give the faculty mathematical certainty that all claims are reproducible and rigorously evaluated.

### Part A: Run the Live Showcase Script (7-Step Sequence)
```powershell
python scripts/demo_live_showcase.py
```
*This executes all 7 steps automatically with colored status banners, live HTTP calls, AST taint inspections, and programmatic assertions.*

### Part B: Run the 167-Test Automated Suite
```powershell
python -m pytest -q
```
*Output: `167 passed in ~5 seconds` across 21 test files (including 13 dedicated real-world scenario tests).*

### Part C: Run the 115-Case Benchmark Evaluation
```powershell
python scripts/evaluate_phase_7.py
```
*Output: Displays the 6-dimension evaluation matrix across 105 valid cases and 10 syntax edge cases.*

---

## 10. Faculty Q&A Survival Guide (Defending Against Tough Questions)

### Q1: *"Did your taint analysis detect more attacks than the baseline gateway?"*
> **Answer:**  
> *"No, Professor, and that is a critical point of scientific integrity in our research report. Both the gateway and our correlated model achieved 100.0% recall on the 52 attack cases in our benchmark. Our research contribution is not claiming increased binary blocking, but solving the **attribution and explainability failure** of existing gateways: our model improves exact path attribution from **56.2% to 89.5%**, uncovers nested collections and field aliases, and verifies boundary proofs for 100% of protected entities."*

### Q2: *"How does your work compare to Lambers et al. (LMCS 2026)?"*
> **Answer:**  
> *"Lambers et al. presented pioneering work on static taint tracking for Graph APIs to detect broken access control candidates. However, Lambers et al. operates purely statically. In our empirical evaluation, applying static taint alone produces an **81.1% false alarm rate** on benign operations because static code cannot verify runtime JWT identity or database ownership records. Our contribution is the **correlation framework**: combining AST taint analysis with runtime authorization evidence to eliminate false alarms (0.0% false alarm rate) and provide explainable audit proofs."*

### Q3: *"Did you test against the live Hoppscotch production server?"*
> **Answer:**  
> *"No, out of strict academic ethics and scientific reproducibility, we did not execute unauthorized probes against third-party production infrastructure. Instead, we constructed a faithful, controlled local reproduction of the `GHSA-m5pg-r4jp-qq75` vulnerability pattern (`userCollection` IDOR) using identical schema entities, argument bindings, and authorization contracts, validating our findings through automated unit tests (`tests/test_real_world_scenarios.py`)."*

### Q4: *"Why did you integrate taint analysis in audit-only mode instead of inline blocking?"*
> **Answer:**  
> *"Because static taint analysis alone has an 81.1% false alarm rate. If we enforced blocking directly on taint findings, legitimate users would be locked out of their own data. Operating in audit-only mode guarantees **zero divergence** from existing gateway decisions (115/115 cases preserved) while enriching audit logs with deep schema coordinates and boundary proofs."*

### Q5: *"What is the performance overhead of adding AST taint analysis?"*
> **Answer:**  
> *"We profiled the engine across benchmark iterations: cold-start latency is **0.377 ms**, and warmed median latency is **0.295 ms** (P95 is **0.434 ms**). Because the entire gateway request lifecycle takes ~20–25 ms including database I/O, AST analysis adds less than 1.5% overhead."*

---

## 11. Summary Evaluation Matrix

| Evaluation Dimension | Gateway Alone (M1) | Static Taint Alone (M2) | Correlated Defense (M3) |
| :--- | :---: | :---: | :---: |
| **Detection Recall** | 100.0% (52/52) | 100.0% (52/52) | **100.0% (52/52)** |
| **Detection Precision** | 100.0% (52/52) | 54.7% (52/95) | **100.0% (52/52)** |
| **False Alarm Rate** | 0.0% (0/53) | 81.1% (43/53) | **0.0% (0/53)** |
| **Exact Path Attribution** | 56.2% (59/105) | 89.5% (94/105) | **89.5% (94/105)** |
| **Boundary Criteria Verified** | 0.0% (0/105) | 0.0% (0/105) | **90.5% (95/105)** *(100% of protected entities)* |
| **Illustrative Rubric Score** | 3.33 / 8.0 (41.6%) | 5.75 / 8.0 (71.9%) | **7.83 / 8.0 (97.9%)** |
| **Added Latency Overhead** | 0.00 ms (Baseline) | 0.295 ms (Median) | **0.295 ms (Median)** |
| **Behavioral Compatibility** | 100.0% (Baseline) | N/A (Static) | **100.0% (115/115 Zero Divergence)** |
| **Automated Test Suite** | — | — | **167/167 Passing Tests (21 Suites)** |
