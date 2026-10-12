# CCNS Project: 5-Minute Defense Demonstration & Faculty Viva Playbook

**Project Title:** Evidence-Grounded AI Explanations for GraphQL BOLA Auditing: Correlating AST-Derived Paths with Runtime Authorization Evidence  
**Audience:** Faculty Examiners, Reviewers, and Application Security Engineers  
**Target Duration:** 5 Minutes Live Demonstration + Defense Viva Q&A  

---

## 1. Five-Minute Live Demonstration Script

### Setup & Prerequisite Check (T-30 Seconds)
Open a terminal in the project directory:
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open browser to: `http://127.0.0.1:8000/dashboard`

---

### Minute 1: The Problem & The Architecture (0:00 – 1:00)
- **Show the Architecture:** Point to the Dashboard header.
  - *"Modern GraphQL APIs allow flexible client-driven data fetching, but this introduces Broken Object-Level Authorization (BOLA). Standalone static analyzers lack tenant session context and suffer high false alarms. Traditional API gateways drop unauthorized requests with HTTP 403 but log opaque errors without AST path attribution."*
  - *"Our system unifies pre-execution AST taint analysis with deterministic runtime policy correlation and an out-of-band, evidence-grounded AI explanation layer."*
- **Highlight Zero-Authority Guarantee:**
  - *"Notice that the gateway (`PolicyEngine`) maintains exclusive authority. The AI layer is strictly advisory, runs out-of-band, and cannot alter database state or grant access."*
- **Highlight Demo Authentication Hardening:**
  - *"Notice that the frontend JavaScript contains zero hardcoded credentials. It obtains an ephemeral session via `/api/v1/auth/demo-session`, which is loopback-restricted, proxy-audited, and disabled in production."*

---

### Minute 2: Direct BOLA & Field Alias Cloaking (1:00 – 2:00)
- **Select Scenario `REAL-HOPP-001` (Hoppscotch IDOR Reproduction):**
  - Point to the query: `query { resource(id: 102) { id name } }`.
  - Explain: *"Alice (User 101) requests Bob's private collection (Resource 102). The gateway resolves ownership (`Resource:102` owned by `User:102`), detects the tenancy mismatch, and drops the request with HTTP 403 `OWNERSHIP_MISMATCH`."*
  - Point to the correlation: `TRUE_POSITIVE_BLOCKED`.
- **Select Scenario `REAL-NEST-001` (Alias Cloaking & Nested Traversal):**
  - Point to the query: `query { targetUser: user(id: 101) { userDocs: resources(id: 102) { id } } }`.
  - Explain: *"An attacker uses client aliases (`targetUser`, `userDocs`) to cloak sensitive field sinks. Standard gateways log only the alias string `userDocs`, blinding auditors. Our dual path canonicalization unmasks the alias to the canonical schema coordinate `Query.user.resources`."*

---

### Minute 3: The False-Alarm Elimination Proof (2:00 – 3:00)
- **Select Scenario `REAL-HOPP-002` or `REAL-SAAS-003` (Benign Authorized Access):**
  - Query: `query { resource(id: 101) { id name } }` by Alice (User 101).
  - Point to Taint Analysis box: *"Static taint analysis flags this as a `DIRECT_BOLA_CANDIDATE` because a client-controlled ID flows into a sensitive sink. On our benchmark, static analysis alone flags 43 of 53 benign queries—an unsustainable 81.1% false-alarm rate."*
  - Point to Correlation box: *"Our correlation engine checks runtime policy evidence. Because Alice is the legitimate owner (`OWNER_MATCH`), the system classifies this as `RUNTIME_PROTECTED_ALLOWED` with zero policy divergence. Runtime correlation suppresses 100% of these static false alarms."*

---

### Minute 4: The 6-Stage Evidence Sequence & Grounded AI Analyst (3:00 – 4:00)
- **Demonstrate the 6-Stage Evidence Pipeline:**
  - Walk across the visual pipeline:
    `Step 1: AST Normalization ➔ Step 2: Inferred Ownership ➔ Step 3: AST Taint ➔ Step 4: Security Graph ➔ Step 5: Deterministic Decision ➔ Step 6: Audit Event`.
- **Click `Generate Evidence-Grounded AI Explanation`:**
  - Watch the synthesis:
    - Point to **Cited Evidence Items ($E_1 \dots E_{11}$)**: Notice that every sentence cites structured program evidence (e.g., `[E2]`, `[E6]`, `[E7]`, `[E8]`).
    - Point to **Grounding Badge**: `100% Grounded (Score: 100%)`.
    - Point to **Actionable Remediation**: Concrete resolver patch scoped to tenant context.
  - Explain: *"The AI Analyst receives a sanitized, token-scrubbed Evidence Package. If the AI hallucinates a non-existent citation or contradicts the gateway's decision, the post-generation Grounding Engine catches and rejects it."*

---

### Minute 5: Automated Verification & Empirical Rigor (4:00 – 5:00)
- **Switch to terminal and run the test suite:**
  ```powershell
  python -m pytest tests/test_demo_security.py -v
  ```
  Show 9 passed tests covering loopback authentication, production guardrails, and proxy spoofing defense.
- **Run the evaluation harness:**
  ```powershell
  python scripts/evaluate_phase_7.py
  ```
  Highlight the verified empirical figures:
  - Detection: 100% Precision, 100% Recall, 0.0% False-Alarm Rate (matching gateway).
  - Path Attribution: 89.5% Exact Matches vs 56.2% for gateway alone.
  - Zero Divergence: 115/115 cases preserved.
- **Conclude:**
  - *"In summary, GraphQL Shield demonstrates that correlating AST taint analysis with runtime authorization proofs eliminates static false alarms, unmasks aliased field paths, and produces verifiable audit explanations—without adding unconstrained AI authority to the access control path."*

---

## 2. Faculty Viva: Rehearsal of the 8 Difficult Defense Questions

### Question 1:
> *"Your paper reports that Gateway Alone achieves 100% precision and 100% recall, and Correlated Defense also achieves 100% precision and 100% recall. If the binary detection accuracy is identical, what is the actual contribution of runtime correlation?"*

**Answer:**  
*"That is a critical distinction that we formalize in Section 7.1. Runtime correlation does not alter or inflate the binary decision—the deterministic `PolicyEngine` already makes the authoritative access decision.  
The actual contributions are twofold:  
First, **it operationalizes static AST taint analysis by eliminating its 81.1% false-alarm rate**. A static analyzer alone flags 43 out of 53 benign owner requests as attacks because it lacks session context. Correlation suppresses 100% of these false alarms.  
Second, **it overcomes the attribution blindness of gateway logging**. Standard gateways log only top-level aliases and achieve only 56.2% exact path attribution. Our correlated AST engine elevates exact path attribution to 89.5%, unmasking client aliases to canonical schema coordinates (`Query.resource`) for security forensics.  
In short: the gateway provides binary enforcement; AST taint provides path attribution; and correlation binds them together with zero behavioral divergence."*

---

### Question 2:
> *"Isn't your 100% detection rate simply an artifact of evaluating on your own constructed benchmark?"*

**Answer:**  
*"Yes, and we explicitly highlight this limitation in the Abstract, Section 6.1, and Section 9. Our 100% precision and recall metrics apply specifically to the 105 valid benchmark cases and 12 synthetic real-world scenarios where schemas, object types, and ownership bindings were modeled.  
These figures prove formal correctness of the correlation logic under the specified corpus, but they do not claim universal generalization across arbitrary enterprise schemas with unmodeled custom ABAC policies, complex multi-tenant groups, or third-party legacy databases. That is a deliberate scope boundary of this research prototype."*

---

### Question 3:
> *"Can an external attacker bypass your demo-session authentication endpoint by spoofing an `X-Forwarded-For: 127.0.0.1` header?"*

**Answer:**  
*"No. The endpoint employs defense-in-depth:  
1. **Direct Peer IP Validation:** It verifies the TCP socket address (`request.client.host`). If an external client connects directly over the internet, their peer IP is an external address (e.g., `198.51.100.25`), so the request is immediately dropped with HTTP 403 regardless of what headers they send.  
2. **Reverse Proxy Header Audit:** If the server is behind a local reverse proxy (where direct peer is `127.0.0.1`), the endpoint inspects `X-Forwarded-For`, `X-Real-IP`, and RFC 7239 `Forwarded` headers. If *any* non-loopback IP address appears anywhere in the proxy chain, the request is rejected.  
3. **Configuration & Environment Guards:** The endpoint is disabled if `ENABLE_DEMO_SESSION=False` and strictly prohibited whenever `ENVIRONMENT == 'production'`. All 9 security regression tests in `tests/test_demo_security.py` verify these constraints."*

---

### Question 4:
> *"You measured 8.44 ms of gateway overhead. In earlier reports you claimed asynchronous queuing would make overhead strictly below 0.5 ms. Can you actually prove that?"*

**Answer:**  
*"No, and we revised Section 7.5 to correct that unsupported extrapolation.  
What we empirically proved is the **component breakdown**:  
- In-memory AST taint propagation: **0.206 ms**  
- AST object normalization: **0.115 ms**  
- In-memory algorithms combined: **0.321 ms (3.8% of overhead)**  
- SQLite database queries (`SELECT`): **1.612 ms**  
- Synchronous SQLite disk write & commit (`INSERT`): **5.194 ms (61.5% of overhead)**  
While moving audit logging to an asynchronous queue eliminates synchronous disk I/O from the request path, production queueing introduces serialization, memory allocation, broker latency, and backpressure. Therefore, we explicitly state in the paper that sub-millisecond gateway overhead is an architectural design expectation and target for future work, rather than an empirically demonstrated production result."*

---

### Question 5:
> *"Your results table shows 100% citation precision and 100% decision consistency for AI explanations, but your real-LLM experiment was halted. Isn't that misleading?"*

**Answer:**  
*"We made sure it is not misleading by explicitly documenting the boundary in Section 7.3 and Section 7.4.  
The 100% metrics in Table 3 evaluate **the programmatic software contract of the Grounding Engine and data sanitization pipeline** using deterministic mock fixtures (`MockAIProvider` and `FlawedMockAIProvider`). These tests prove that when an explanation violates invariants—such as citing non-existent facts ($E_{99}$) or claiming ALLOW when the gateway returned DENY—our validator reliably catches and rejects the defect.  
When credentials were absent for live LLMs, we deliberately halted the experiment and pre-registered the protocol in `docs/AI_REAL_LLM_EVALUATION_PROTOCOL.json` rather than disguising mock data as live model outputs. We explicitly note in the paper that semantic explanation quality and jailbreak resistance on live LLMs remain open research questions."*

---

### Question 6:
> *"What prevents an attacker from injecting prompt injection payloads into a GraphQL query (e.g., in a comment or field alias) to trick the AI into approving access?"*

**Answer:**  
*"Three layers of defense prevent this:  
1. **Zero Enforcement Authority:** The AI layer runs strictly out-of-band for audit assistance. Even if an attacker achieved a complete semantic jailbreak in the AI output, the gateway has already dropped the HTTP request with 403 Forbidden. The AI has zero capability to alter access control.  
2. **Structural AST Quarantine:** The GraphQL query is parsed into an AST. Comments and raw strings are isolated, sensitive variables are sanitized, and the model receives structured key-value evidence items ($E_1 \dots E_{11}$) rather than an open execution prompt.  
3. **Grounding Engine Invariant Checker:** Even if the model generates text claiming the query was legitimate, Invariant 2 checks $\text{Decision}(\text{AI}) \equiv \text{Decision}(\text{Gateway})$. Any contradiction triggers an immediate Grounding Violation alert."*

---

### Question 7:
> *"Why evaluate at an external gateway rather than implementing field-level authorization inside GraphQL resolvers (e.g., Strawberry extensions or GraphQL Shield)?"*

**Answer:**  
*"Both approaches have architectural merits, but gateway-level authorization offers distinct security advantages:  
1. **Pre-Execution DoS & Blast Radius Mitigation:** Gateway inspection inspects and rejects unauthorized operations before resolver dispatch, preventing resource-intensive database queries or cascading graph traversals.  
2. **Language & Framework Independence:** A gateway operates across heterogeneous microservices regardless of whether backend resolvers are written in Python, Node.js, Go, or Java.  
3. **Centralized Auditing & Graph Attribution:** In microservice federations, individual resolvers have visibility only into their local type slice. A perimeter gateway parses the entire query AST, unmasks global aliases, and logs a unified audit record across the entire operation."*

---

### Question 8:
> *"What accounts for the 11 partial matches in your exact path attribution metric?"*

**Answer:**  
*"The 89.5% exact path attribution rate reflects 94 exact matches, 11 partial matches, 0 incorrect paths, and 0 missing paths across the 105 valid cases:  
- **10 Multi-Target Queries (`CORPUS-027`–`030`, `CORPUS-036`, etc.):** The benchmark ground truth specified a comma-separated composite target (e.g., `'resource, user'`). Our AST extractor extracted individual hierarchical path elements (e.g., `['user', 'user.resource']`). Because the path matched the primary entity prefix but differed in formatting from the composite string, the evaluation metric scored it as `PARTIAL`.  
- **1 Introspection Query (`CORPUS-084`):** The ground truth expected schema coordinate `'__type'`, whereas our AST visitor extracted the runtime coordinate `'__typename'`.  
In all 11 cases, the primary schema entity was correctly identified; there were zero false classifications."*
