# Faculty Demonstration Guide: GraphQL Shield

**Project Title:** Schema-Aware GraphQL BOLA Security Gateway with Context-Sensitive Taint Analysis  
**Course:** Computer and Communication Network Security (CCNS)  
**Presenter:** Project Team  
**Evaluation Mode:** Live Demonstration & Defense  

---

## 0. Executive Checklist Before Presentation

- [ ] Ensure the server is running on `http://127.0.0.1:8000` (started in Terminal 1).
- [ ] Open a browser tab to the **Live Dashboard**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard).
- [ ] Open a browser tab to the **OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
- [ ] Open a Terminal window for running client queries and scripts.
- [ ] Have the evaluation report ready: `docs/FINAL_RESEARCH_REPORT.md`.

---

## 1. Opening Pitch (2 Minutes: Setting the Academic Problem)

**What to say to your professor:**
> *"Respected Faculty / Professor,*
>
> *Our project addresses **Broken Object-Level Authorization (BOLA)**, the #1 vulnerability on the OWASP API Security Top 10 (API1:2023). BOLA occurs when an authenticated user manipulates an object identifier to access resources belonging to another tenant.*
>
> *While BOLA is well-studied in flat REST APIs, it is significantly more dangerous and complex in **GraphQL**. In GraphQL, clients can formulate arbitrary, nested query documents using **field aliases**, **fragment spreads**, and **relational collection traversals** (like `user.resources`).*
>
> *Existing gateway solutions suffer from a major limitation: **they are black-box enforcers**. When they block an attack, they return a generic HTTP 403 Forbidden with zero schema coordinates, and they frequently lose track of indirect traversals and client aliases. Conversely, purely static taint analysis suffers from an **81.1% false alarm rate** because static code cannot inspect runtime JWT identities or database records.*
>
> *Our research contribution is **GraphQL Shield**: an AST-driven, context-sensitive static taint propagation engine that correlates with runtime authorization evidence in an **audit-only, non-disruptive mode**. It raises exact path attribution from **56.2% to 89.5%**, verifies authorization boundaries for **100% of protected entities**, preserves 100% of gateway decisions with **zero divergence**, and adds **less than 0.3 milliseconds of latency**.*
>
> *I will now demonstrate our system live across 5 acts: the baseline vulnerability, direct BOLA, indirect nested BOLA, explainability intelligence, and empirical verification."*

---

## 2. Act 1: The Baseline Vulnerability (Why GraphQL Needs This)

**Objective:** Prove to your faculty why an unshielded GraphQL API fails.

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
> *"As you can see, without our gateway, Alice can freely access Bob's private financial data simply by altering the ID argument. The GraphQL resolver executed the query without tenant isolation."*

---

## 3. Act 2: Direct BOLA Prevention & Live Gateway Trace

**Objective:** Show live enforcement on the protected gateway endpoint (`/graphql`).

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
- Returns **`HTTP 403 Forbidden`** with detail:
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
> *"The gateway intercepts the request prior to GraphQL resolver execution. It resolved ownership of Resource 102 from the database, detected that Alice (101) does not match Bob (102), computed a High Risk score of 90/100, and immediately dropped the request with HTTP 403."*

---

## 4. Act 3: Indirect BOLA & Nested Relational Traversal

**Objective:** Demonstrate that the system defends against advanced attacks using client aliases and nested collection relationships.

**What to do in Terminal 2:**
```powershell
# Alice queries Bob's user node and traverses into his resources collection using client aliases
try {
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/graphql" -Method Post -Headers @{ Authorization = "Bearer $AliceToken" } -ContentType "application/json" -Body '{"query": "query { targetUser: user(id: 102) { userDocs: resources { id name } } }"}'
} catch {
  $_.ErrorDetails.Message
}
```

**What happens on screen:**
- Returns **`HTTP 403 Forbidden`** (`OWNERSHIP_MISMATCH`).
- In server logs:
  - Static Taint Engine identifies 2 findings:
    - Root: `user` (aliased as `targetUser`)
    - Nested collection: `user.resources` (aliased as `targetUser.userDocs`)
  - Identifies relationship context: `UserType.resources` (One-to-Many collection).

**What to tell your professor:**
> *"This is an Indirect BOLA attempt. An attacker tries to evade simple root checks by aliasing fields (`targetUser`, `userDocs`) and traversing relational collections. A standard regex gateway would look for `resource(id:)` and miss this query entirely. Our AST parser normalizes aliases, extracts the underlying schema relationship `user.resources`, and prevents unauthorized traversal."*

---

## 5. Act 4: False-Alarm Prevention & Audit Intelligence

**Objective:** Prove that the gateway allows legitimate traffic and that correlation prevents false positives.

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
> *"Here is the scientific value of our correlation engine: Static taint analysis flagged argument `id` as untrusted input reaching a sensitive sink. If we relied purely on static taint, this would be an annoying False Alarm (Static taint has an 81.1% false alarm rate). But our correlation engine dynamically checks runtime authorization, sees that Alice owns Resource 101 (`OWNER_MATCH`), and marks it `RUNTIME_PROTECTED_ALLOWED`, preventing a false block."*

---

## 6. Act 5: Real-Time Security Dashboard & Audit Endpoints

**What to do:**
1. Switch to your browser tab at **`http://localhost:8000/dashboard`**.
2. Refresh the page to show:
   - **Total Requests Tracked**
   - **Allowed Requests**
   - **Blocked Requests**
   - **BOLA Attacks Caught**
   - **High Risk Incidents**
   - **Live Audit Event Log Table** showing the exact timestamps, user IDs, decisions, and risk levels from your demo queries.

3. In Terminal 2, show the Admin Taint Audit Inspection endpoint:
```powershell
$AdminResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/auth/login" -Method Post -ContentType "application/json" -Body '{"username":"charlie","password":"charlie123"}'
$AdminToken = $AdminResp.access_token

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/security/taint-audit" -Method Get -Headers @{ Authorization = "Bearer $AdminToken" } | ConvertTo-Json -Depth 4
```

---

## 7. Act 6: Automated End-to-End Showcase & Benchmark Proof

**Objective:** Give the faculty mathematical and test-proven certainty that the system is fully reproducible and evaluated.

### Part A: Run the Live Showcase Script
```powershell
python scripts/demo_live_showcase.py
```
*This executes all 4 scenarios automatically with beautiful ASCII tables and timings.*

### Part B: Run the 154-Test Suite
```powershell
python -m pytest -q
```
*Output: `154 passed in ~5 seconds` across 20 test files.*

### Part C: Run the 115-Case Benchmark Evaluation
```powershell
python scripts/evaluate_phase_7.py
```
*Output: Displays the 6-dimension evaluation matrix across 105 valid cases and 10 syntax edge cases.*

---

## 8. Faculty Q&A Survival Guide (How to Answer Tough Questions)

### Q1: *"Did your taint analysis detect more attacks than the baseline gateway?"*
> **Answer:**  
> *"No, Professor, and that is a critical point of scientific honesty in our report. Both the gateway and our correlated model achieved 100.0% recall on the 52 attack cases in our benchmark. Our research contribution is not claiming increased binary blocking, but solving the **attribution and explainability failure** of existing gateways: our model improves exact path attribution from **56.2% to 89.5%**, uncovers nested collections and field aliases, and verifies boundary proofs for 100% of protected entities."*

### Q2: *"Why did you use audit-only mode instead of actively blocking with taint analysis?"*
> **Answer:**  
> *"Purely static taint analysis has an **81.1% false alarm rate** on benign queries because it lacks runtime knowledge of caller identity and database ownership records. If we blocked directly on static taint, legitimate tenant queries would be dropped. Operating in audit-only mode allows us to capture full AST security intelligence without risking production disruption or breaking backward compatibility."*

### Q3: *"How does the system handle nested collections like `user.resources` where child objects don't have explicit ID arguments?"*
> **Answer:**  
> *"Our Phase 2 Typed Security Graph models relationship cardinality and collection sinks (`SinkKind.RELATIONSHIP_COLLECTION`). When the AST traverser encounters `user(id: 102) { resources }`, it propagates the taint tag from the parent object argument into the child selection context and evaluates nested authorization rules."*

### Q4: *"What is the performance overhead of adding AST taint analysis?"*
> **Answer:**  
> *"We profiled the engine across multiple benchmark iterations: cold-start latency is **0.377 ms**, and the warmed median latency is **0.295 ms** (P95 is **0.434 ms**). Because the entire GraphQL gateway takes ~20–25 ms including database I/O, our AST analysis adds less than 1.5% overhead."*

---

## 9. Summary Table to Present to Faculty

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
