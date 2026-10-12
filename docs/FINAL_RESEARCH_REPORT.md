# Correlating AST-Based GraphQL Path Analysis with Runtime Authorization Evidence for Explainable BOLA Auditing

**Project Title:** Correlating AST-Based GraphQL Path Analysis with Runtime Authorization Evidence for Explainable BOLA Auditing  
**Academic Course:** Computer and Communication Network Security (CCNS)  
**Evaluation Baseline:** 115 Ground-Truth Benchmark Cases (105 Valid Security Cases, 10 Lexical/Syntax Boundary Cases) + 12 Real-World Scenarios  
**Test Suite Verification:** 167 Passed Unit & Regression Tests (100% Pass Rate across 21 Test Modules)  
**Evaluated Target:** GraphQL Shield (FastAPI Security Gateway + Strawberry GraphQL)  

---

## Executive Summary

Broken Object-Level Authorization (BOLA), designated as the #1 threat in the OWASP API Security Top 10 (API1:2023), represents one of the most pervasive vulnerabilities in modern distributed architectures. In GraphQL APIs, BOLA poses unique detection and attribution challenges: clients construct arbitrary, deeply nested selection sets combining field aliases, fragment spreads, and cross-type relational collections. Existing gateway defenses evaluate authorization primarily through coarse-grained pre-execution regex or shallow argument inspection. While an existing gateway may successfully drop unauthorized requests, its security explanations remain opaque (emitting isolated HTTP 403 status codes without schema path coordinates), and it frequently loses visibility over nested collection traversals (e.g., `user.resources`) and client-side field aliases.

Conversely, purely static taint analysis in an inline gateway setting lacks runtime caller credentials (JWT claims) or live database tenant ownership records without execution. On our benchmark, evaluating an isolated static-taint baseline (Method 2) yielded an **81.1% false alarm rate (flagging 43 of 53 benign cases)** because every tainted input reaching a sensitive sink is treated as a vulnerability candidate.

This research paper introduces **GraphQL Shield**, a hybrid architecture that pairs an AST-driven, context-sensitive static taint propagation engine with runtime authorization policy evidence. Operating in an **audit-only, non-disruptive configuration**, GraphQL Shield correlates static taint findings with dynamic policy execution.

### Key Empirical Findings:
1. **Binary Detection Recall (Honest Novelty Assessment):**  
   Both the baseline gateway and the correlated model achieve **100.0% recall (52/52)** and **100.0% precision (52/52)** on the 105 valid security benchmark cases. **Correlated analysis does not improve binary blocking recall over the gateway alone on this evaluated corpus.** Claims of superior attack blocking are scientifically unwarranted and rejected.
2. **Exact Path Attribution Accuracy:**  
   Context-sensitive AST taint analysis elevates exact schema path attribution from **56.2% (59/105)** under the gateway alone to **89.5% (94/105)** under correlated analysis, eliminating client alias confusion and correctly attributing indirect traversals across nested collections.
3. **Program-Verified Boundary Transparency:**  
   The gateway alone exposes 0 structured boundary criteria (0.0%). The static analyzer represents 100.0% of criteria in its model but verifies 0.0% in the program. Correlated defense represents 100.0% of boundary criteria and dynamically verifies all 4 criteria in the program for **95 / 95 (100.0%) of protected domain object cases** (90.5% across all 105 valid cases; the remaining 10 cases are public/introspection queries requiring no authorization check).
4. **Behavioral Compatibility on Evaluated Corpus:**  
   Across all 115 benchmark cases, audit-only taint analysis achieves **100.0% behavioral preservation (115/115)**, with zero HTTP status code divergence and zero mutation of response bodies. This is documented as an empirical result on the evaluated corpus, not a universal guarantee for all future arbitrary schemas.
5. **Runtime Latency Overhead:**  
   The warmed median latency overhead of the taint engine is **0.295 ms** (P95 = **0.434 ms**), introducing sub-millisecond overhead suitable for inline gateway logging.
6. **Real-World Incident Grounding:**  
   The approach is validated through a controlled local reproduction of **GitHub Security Advisory GHSA-m5pg-r4jp-qq75 / CVE-2026-28217** (Hoppscotch GraphQL `userCollection` IDOR), demonstrating automated attribution, alias normalization, and false-alarm prevention.

---

## 1. Problem Statement & Research Gap

### 1.1 The Challenge of BOLA in GraphQL
In traditional RESTful APIs, resources are mapped to rigid hierarchical URIs (e.g., `GET /users/102/documents/501`). Access control filters can inspect path parameters with lightweight pattern matching. In contrast, GraphQL provides a single execution endpoint (typically `/graphql`) where the client defines the selection set shape. This flexibility introduces four critical security challenges:

1. **Arbitrary Graph Traversal Depth:** Clients can query relations several layers deep (e.g., `user -> team -> project -> documents`).
2. **Client-Controlled Aliasing:** Clients can rename response keys (e.g., `stolenDoc: resource(id: 102)`), decoupling the HTTP response structure from the underlying schema field names.
3. **Fragment Indirection:** Named fragment definitions disperse field selections across the document.
4. **Relational Collection Bypasses:** Top-level fields may be guarded, but nested collection fields (e.g., `User.resources`) frequently omit resolver-level authorization checks.

### 1.2 Related Work & Literature Positioning
In recent academic literature, **Lambers et al. (Logical Methods in Computer Science, Volume 22, Issue 1, March 2026)** presented pioneering theoretical work on *"Taint Analysis for Graph APIs Focusing on Broken Access Control"*. Lambers et al. formalized static and dynamic taint analysis using graph transformation rules and Critical Pair Analysis (CPA) to discover broken access control candidates in graph APIs, demonstrating their approach on a portion of the GitHub GraphQL API alongside dynamic test generation.

Our research is situated within this problem space but addresses a distinct operational setting:
- **Operational Domain:** Lambers et al. explored static analysis using graph transformation rules and test generation. Our work investigates an **inline API gateway mediation layer** operating in front of a live GraphQL engine.
- **The Static False Alarm Limitation:** In our investigation, evaluating an isolated static-taint baseline (Method 2) on our 115-case benchmark produced an **81.1% false alarm rate (43/53 on benign cases)**. This figure belongs specifically to our project's static-taint baseline, illustrating that static analysis alone cannot inspect runtime caller credentials (JWT claims) or live database ownership records.
- **No Direct Empirical Comparison:** We do **not** claim a direct empirical benchmark comparison with the Lambers et al. prototype itself (which was developed for Critical Pair Analysis on graph transformation rules). Rather, we cite Lambers et al. as the theoretical foundation establishing that untrusted graph inputs propagate toward sensitive sinks.
- **Our Distinct Contribution:** We focus on **runtime policy correlation**: binding AST-driven taint paths to dynamic runtime authorization policy evidence in an audit-only mode to eliminate false alarms, improve path attribution, and provide program-verified boundary evidence without changing gateway decisions.

---

## 2. Research Question & Core Objectives

> **Primary Research Question:**  
> *Does correlating schema-aware, AST-driven GraphQL taint analysis with runtime authorization evidence improve the accuracy of security-path attribution and the auditability of authorization decisions while preserving existing gateway enforcement behavior?*

### Specific Research Objectives:
1. **Context-Sensitive AST Attribution:** Disambiguate client-supplied aliases from canonical schema coordinates and track indirect traversals across nested collections.
2. **Authorization Boundary Modeling:** Formally define and track 4 boundary criteria (`principal_bound`, `target_bound`, `mandatory_on_path`, `covers_operation`) and distinguish criteria represented in a report from criteria verified in the program.
3. **Runtime Correlation:** Map static vulnerability candidates to dynamic policy decisions, categorizing results into `TRUE_POSITIVE_BLOCKED`, `RUNTIME_PROTECTED_ALLOWED`, `BENIGN_AUTHORIZED`, or `POLICY_DENIED_UNCORRELATED`.
4. **Empirical Evaluation & Non-Disruption:** Demonstrate that audit-only operation achieves 100% behavioral compatibility with zero gateway decision divergence on the evaluated benchmark and sub-millisecond overhead.
5. **Real-World Incident Validation:** Model the vulnerability pattern from a documented public security advisory (Hoppscotch GHSA-m5pg-r4jp-qq75 / CVE-2026-28217) in a controlled academic reproduction.

---

## 3. Threat Model

### 3.1 Attacker Capabilities
- **Authenticated Principal:** The threat actor possesses valid JWT authentication credentials granting standard `user` privileges.
- **Untrusted Input Control:** The attacker controls query strings, variable mappings, field arguments, operation names, and client aliases.
- **Objective (OWASP API1:2023 - BOLA):** Access, traverse, or enumerate data belonging to another tenant or higher-privileged role (e.g., Alice attempting to access Bob's private collection or Charlie's administrative documents).

### 3.2 Evaluated Attack Vectors
1. **Direct BOLA:** Direct root query invocation with foreign object IDs (e.g., `query { resource(id: 102) { name } }`).
2. **Variable Default Injections:** Omitting variable payloads and relying on AST variable default values (`query ($id: Int = 102) { resource(id: $id) { name } }`).
3. **Alias Masking:** Renaming sensitive fields to evade string-based filters (`query { stolenDoc: resource(id: 102) { name } }`).
4. **Fragment Spreading:** Indirection through named and inline fragment spreads.
5. **Indirect / Nested Collection Traversals:** Accessing foreign resources through unconstrained relational fields (`query { user(id: 102) { resources { id name } } }` or `query { user(id: 101) { resource(id: 102) { id } } }`).

### 3.3 Out of Scope
- SQL / NoSQL injection (mitigated via parameterized queries).
- Broken authentication / cryptographic token forgery (mitigated via asymmetric JWT signature checks).
- Denial of Service / recursive depth exhaustion (mitigated via maximum traversal depth bounds).

---

## 4. Architecture & System Design

```
+--------------------------------------------------------------------------------------------------+
|                                    INCOMING GRAPHQL HTTP REQUEST                                 |
|                               (Method: POST, Headers: JWT, Body: AST)                            |
+--------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
                     +---------------------------------------------------------+
                     |         GATEWAY PRE-EXECUTION SECURITY MIDDLEWARE       |
                     +---------------------------------------------------------+
                                  |                                 |
            (Dynamic Context)     |                                 |   (Static AST Inspection)
                                  v                                 v
      +----------------------------------------+   +---------------------------------------+
      |         RUNTIME AUTHORIZATION          |   |      AST CONTEXT-SENSITIVE TAINT      |
      |         - JWT Caller Extraction        |   |      - Phase 2 Security Graph         |
      |         - DB Ownership Resolution      |   |      - Source / Sink Identification   |
      |         - PolicyEngine Evaluation      |   |      - Contextual Propagation         |
      |         (Decision: ALLOW / DENY)       |   |      (Findings & Boundary Evidence)   |
      +----------------------------------------+   +---------------------------------------+
                                  \                                 /
                                   \                               /
                                    v                             v
                     +---------------------------------------------------------+
                     |           PHASE 5/7 TAINT CORRELATION ENGINE            |
                     |           - Maps AST findings to Runtime decisions      |
                     |           - Distinguishes Candidates vs True Positives  |
                     |           - Exposes Verified Boundary Proofs            |
                     +---------------------------------------------------------+
                                                  |
                                                  v
                     +---------------------------------------------------------+
                     |             GATEWAY AUDIT LOG & ENFORCEMENT             |
                     |             - HTTP 200 / 403 Decision (Preserved)       |
                     |             - Structured Audit Record (Correlated)      |
                     +---------------------------------------------------------+
```

### 4.1 System Components
1. **Typed GraphQL Security Graph (`app/security/security_graph.py`):**  
   Constructed directly from the Strawberry schema. Nodes represent types (`TypeNode`), fields (`FieldNode`), and arguments (`ArgumentNode`), capturing cardinality, nullability, ownership semantics, and return kinds.
2. **Taint & Boundary Model (`app/security/taint_model.py`):**  
   - `TaintSource`: Arguments tagged with `UNTRUSTED_IDENTIFIER` or `UNTRUSTED_PARAMETER`.
   - `PropagationContext`: Tracks parent type, field, cardinality, collection status, and depth.
   - `SensitiveSink`: Object or collection nodes classified by sensitivity level.
   - `BoundaryEvidence`: Structured record capturing 4 boundary criteria and explicit uncertainties.
3. **AST Propagation Engine (`app/security/taint_engine.py`):**  
   Walks the GraphQL document AST, normalizes fragments, coerces variable defaults, and records dual path coordinates (`schema_path` vs `response_path`).
4. **Correlation Engine (`app/security/taint_correlation.py`):**  
   Binds static AST findings to runtime PolicyEngine outcomes, establishing verifiable boundary proofs.

---

## 5. Taint Propagation & Correlation Algorithm

```
Algorithm 1: Context-Sensitive GraphQL AST Taint Propagation & Correlation
Input : Query Document Q, Variables Map V, Authenticated Principal P
Output: HTTP Decision D, Correlated Audit Record R

1:  AST <- ParseGraphQLDocument(Q)
2:  if AST is Invalid then
3:      return HTTP 400 Malformed, Record(status=MALFORMED)
4:  
5:  // Step 1: Variable Coercion & Source Identification
6:  EffectiveVars <- CoerceASTVariableDefaults(AST, V)
7:  Sources <- IdentifyTaintSources(AST, EffectiveVars)
8:  
9:  // Step 2: AST Selection-Set Traversal
10: State <- InitTraversalState(max_depth = 15)
11: Steps, Findings <- TraverseSelections(AST.Operation, Root="Query", State)
12: 
13: // Step 3: Runtime Policy Evaluation (Gateway Baseline)
14: Objects <- ExtractDomainObjects(AST, EffectiveVars)
15: RuntimeDecisions <- []
16: for Obj in Objects do
17:     Owner <- ResolveOwnership(Obj.Type, Obj.ID)
18:     Decision <- PolicyEngine.Evaluate(Principal=P, Target=Obj, Owner=Owner)
19:     RuntimeDecisions.Append(Decision)
20: end for
21: GatewayDecision <- AggregateDecisions(RuntimeDecisions) // ALLOW or DENY
22: 
23: // Step 4: Correlation & Boundary Verification (Audit-Only)
24: Correlations <- []
25: for Decision in RuntimeDecisions do
26:     MatchingFinding <- MatchFinding(Decision.Path, Findings)
27:     Status <- ClassifyCorrelation(Decision, MatchingFinding)
28:     VerifiedCriteria <- VerifyBoundary(Decision, Principal=P, Target=Decision.Obj)
29:     Correlations.Append(Correlate(Decision, MatchingFinding, Status, VerifiedCriteria))
30: end for
31: 
32: // Step 5: Audit-Only Preservation
33: EmitStructuredAuditLog(Correlations, Findings, GatewayDecision)
34: return GatewayDecision // Zero Divergence
```

---

## 6. Real-World Case Study: Hoppscotch-Inspired Local Reproduction of the Vulnerability Pattern (GHSA-m5pg-r4jp-qq75 / CVE-2026-28217)

### 6.1 Vulnerability Overview (Official Incident Facts)
On February 26, 2026, GitHub Security Advisory **GHSA-m5pg-r4jp-qq75 (CVE-2026-28217)** was published, reporting an Insecure Direct Object Reference in the self-hosted `hoppscotch-backend` Docker package (versions $\le 2026.1.1$, patched in $2026.2.0$, CVSS 3.1: 6.5 Moderate, reported by `bugbunny-research`). The vulnerability resided in the `userCollection` query:
```graphql
query GetCollection($userCollectionID: ID!) {
  userCollection(userCollectionID: $userCollectionID) {
    id
    title
    data
    userID
  }
}
```
The query resolver accepted `userCollectionID` and fetched the collection from the database without verifying that the authenticated user owned the collection (`packages/hoppscotch-backend/src/user-collection/user-collection.resolver.ts`, line 134). This allowed any authenticated user to retrieve another user's private collections, exposing stored HTTP requests, authentication headers, API keys, and bearer tokens.

### 6.2 Controlled Local Reproduction in GraphQL Shield
To evaluate gateway defense against this vulnerability pattern safely and ethically without touching third-party infrastructure, we modeled the access pattern in our local academic test harness:
- **Simulated Attacker:** Alice (`user_id = 101`, `role = 'user'`)
- **Collection Owner:** Bob (`user_id = 102`, `role = 'user'`)
- **Target Resource:** Collection Resource ID `102` (`Bob's Financial Record`)
- **Attack Query:**
  ```graphql
  query GetCollection($colId: Int!) {
    resource(id: $colId) { id name objectType }
  }
  ```
  with variables `{"colId": 102}`.

> [!NOTE]
> The live Hoppscotch production application was not tested. Rather, the vulnerability pattern (unauthenticated ID parameter lookup on an entity requiring tenant isolation) was reproduced in our controlled local schema.

### 6.3 Local Execution & Verification Trace
1. **Gateway Interception:** Pre-execution object extraction identifies target `(type='Resource', id=102)`. SQLite lookup confirms `owner_id = 102`. PolicyEngine detects `OWNERSHIP_MISMATCH` and drops the request with **`HTTP 403 Forbidden`**.
2. **AST Taint Propagation:** Maps argument `$colId` as taint source reaching sensitive sink `ResourceType`. Schema path attributed: `resource`.
3. **Correlation:** Produces status **`TRUE_POSITIVE_BLOCKED`** with verified boundary criteria.
4. **Legitimate Owner Contrast:** When Bob requests ID `102`, the gateway permits access with **`HTTP 200 OK`**, and correlation logs **`RUNTIME_PROTECTED_ALLOWED`**, preventing a false block.

---

## 7. Empirical Evaluation Methodology & Datasets

### 7.1 Dataset 1: Baseline Ground-Truth Corpus (115 Cases)
The baseline benchmark (`data/ground_truth_corpus.json`) contains 115 version-controlled test cases:
- **52 Ground-Truth BOLA Positive Cases:** Direct attacks (22), variable default injections (1), alias obfuscations (10), fragment indirection (5), and nested collection traversals (14).
- **53 Ground-Truth Benign Negative Cases:** Legitimate owner queries (20), admin privileged queries (15), nested owner collections (8), and public health/introspection queries (10).
- **10 Lexical/Syntax Edge Cases:** Empty queries, malformed syntax, and type violations (evaluated separately from security detection denominators).
- **Valid Security Denominator:** **105 cases** (52 Positive, 53 Negative).

### 7.2 Dataset 2: Real-World Scenarios Dataset (12 Scenarios)
A dedicated dataset (`data/real_world_scenarios.json`) evaluated independently via `scripts/evaluate_real_world_scenarios.py`:
- Hoppscotch collection IDOR pattern (unauthorized, authorized, admin override).
- Team workspace nested collection traversals with client aliases.
- Multi-tenant SaaS document isolation (cross-tenant access, variable default coercion).
- Authentication layer boundaries (unauthenticated, malformed JWT).

---

## 8. Comparative Results Across 6 Research Dimensions

### Dimension 1: Security Detection Performance (105 Valid Cases)
| Metric | Method 1: Gateway Alone | Method 2: Static Alone | Method 3: Correlated Defense |
| :--- | :---: | :---: | :---: |
| **True Positives (TP)** | 52 | 52 | 52 |
| **False Positives (FP)** | 0 | 43 | 0 |
| **True Negatives (TN)** | 53 | 10 | 53 |
| **False Negatives (FN)** | 0 | 0 | 0 |
| **Precision** | **100.0%** (52/52) | **54.7%** (52/95) | **100.0%** (52/52) |
| **Recall (Sensitivity)** | **100.0%** (52/52) | **100.0%** (52/52) | **100.0%** (52/52) |
| **F1-Score** | **1.000** | **0.708** | **1.000** |
| **False Alarm Rate (FAR)**| **0.0%** (0/53)* | **81.1%** (43/53)* | **0.0%** (0/53)* |

*\*Note: The False Alarm Rate is computed strictly over the 53 evaluated benign test cases in our benchmark corpus. The 81.1% false alarm rate belongs to our own isolated static baseline (Method 2) on 43 of 53 benign cases.*

#### Honest Assessment of Detection Recall:
> [!IMPORTANT]
> Correlated Defense does **not** increase binary detection recall over Gateway Alone on this corpus. Both block 52/52 attacks. Our static-taint baseline alone produces an 81.1% false alarm rate on benign queries because it cannot know whether the runtime caller owns the target resource without executing the database check. The genuine research value of the AST taint analyzer lies in **explanation, path attribution, and boundary transparency**, not in raw binary blocking.

---

### Dimension 2: Path Attribution Accuracy (105 Valid Cases)
| Attribution Metric | Method 1: Gateway Alone | Method 2: Static Alone | Method 3: Correlated Defense |
| :--- | :---: | :---: | :---: |
| **Exact Path Matches** | 59 (56.2%) | 94 (89.5%) | **94 (89.5%)** |
| **Partial Matches** | 34 (32.4%) | 11 (10.5%) | **11 (10.5%)** |
| **Incorrect Paths (Alias Confused)** | 2 (1.9%) | 0 (0.0%) | **0 (0.0%)** |
| **Missing Paths** | 10 (9.5%) | 0 (0.0%) | **0 (0.0%)** |
| **Exact Match Rate** | **56.2%** | **89.5%** | **89.5%** |
| **Attribution Coverage** | **88.6%** | **100.0%** | **100.0%** |

*Gateway Alone frequently fails on relationship paths (reporting only root `user` instead of `user.resources`) and misattributes client aliases as schema fields. The AST engine correctly correlates AST coordinates with schema nodes.*

---

### Dimension 3: Boundary Evidence Transparency (105 Valid Cases)
| Boundary Criterion | Method 1: Gateway Alone | Method 2: Static Alone | Method 3: Correlated Defense |
| :--- | :---: | :---: | :---: |
| **Criteria Represented in Report** | **0.0%** (0/105) | **100.0%** (105/105) | **100.0%** (105/105) |
| **Criteria Verified in Program** | **0.0%** (0/105) | **0.0%** (0/105) | **90.5%** (95/105)* |
| **Principal Binding Tracked** | 0 / 105 | 105 / 105 | 95 / 105 |
| **Target Binding Tracked** | 0 / 105 | 105 / 105 | 95 / 105 |
| **Mandatory Path Tracked** | 0 / 105 | 105 / 105 | 95 / 105 |
| **Operation Coverage Tracked** | 0 / 105 | 105 / 105 | 95 / 105 |
| **Explicit Uncertainties Stated** | **0.0%** (0/105) | **100.0%** (105/105) | **100.0%** (105/105) |

*\*Note: 95/105 cases target protected domain entities. On all 95 protected cases requiring authorization, Correlated Defense dynamically verifies 100.0% (95/95) of boundary criteria in the program from actual runtime policy evidence. The remaining 10 valid cases are public/introspection queries that require no authorization check.*

---

### Dimension 4: Illustrative Architectural Rubric Scores (12 Representative Archetypes)
*(Evaluates architectural capability completeness across 4 objective criteria; does not claim independent double-blind human review).*
- **Method 1 (Gateway Alone):** Mean = **3.33 / 8** (41.6%)
- **Method 2 (Static Taint Alone):** Mean = **5.75 / 8** (71.9%)
- **Method 3 (Correlated Defense):** Mean = **7.83 / 8** (97.9%)

---

### Dimension 5: Latency Overhead Profiling
- **Cold-Start Taint Analysis:** 0.381 ms
- **Warmed Median Latency:** 0.293 ms
- **Warmed 95th Percentile (P95):** 0.443 ms
- **Gateway End-to-End Latency:** ~20–25 ms (dominated by SQLite I/O and password hashing)
- **Overhead Assessment:** Static AST analysis adds < 1.5% to total request latency.

---

### Dimension 6: Behavioral Compatibility on Evaluated Corpus
- **Valid Security Cases Decision Preservation:** **100.0%** (105 / 105)
- **Zero-Divergence Audit Preservation:** **100.0%** (115 / 115)
- **HTTP Response Divergence:** **0 cases** (Zero status code changes, zero payload mutations across evaluated benchmark).
- *Scope Note:* Reported as an empirical result on the evaluated benchmark corpus, not a universal guarantee for arbitrary unseen future schemas.

---

## 9. Limitations & Threats to Validity

1. **Synthetic Corpus Scope:** While the 115-case benchmark and 12 real-world scenarios cover diverse GraphQL constructs, they are executed against a controlled schema. Large enterprise schemas with dynamic federation (Apollo Federation) or schema stitching may introduce additional schema graph parsing overhead.
2. **Mutation Operations:** The current implementation actively intercepts GraphQL `query` operations. Mutation authorization (e.g., `updateResource`, `deleteCollection`) is supported structurally in the AST parser but not active in the gateway enforcement layer.
3. **Double-Blind Human Subject Usability:** Rubric scores reflect structural architectural capabilities rather than external developer usability grading.

---

## 10. Reproducibility Instructions

### Environment
- Python 3.12+ (tested on Python 3.14 Windows)
- Dependencies: `fastapi`, `strawberry-graphql`, `pydantic`, `pytest`, `httpx`, `pyjwt`

### Execution Commands
```powershell
# 1. Run Complete Test Suite (167 passing tests)
python -m pytest tests/ -v

# 2. Run Phase 7 Comparative Evaluation Script (115 benchmark cases)
python scripts/evaluate_phase_7.py

# 3. Run Independent Real-World Dataset Evaluation (12 scenarios)
python scripts/evaluate_real_world_scenarios.py

# 4. Run Live 7-Step Interactive Showcase Demonstration
python scripts/demo_live_showcase.py
```

---

## 11. References

1. **Academic Literature on Graph API Taint Analysis:**  
   Leen Lambers, Lucas Sakizloglou, Taisiya Khakharova, Fernando Orejas, *"Taint Analysis for Graph APIs Focusing on Broken Access Control,"* Logical Methods in Computer Science (LMCS), Volume 22, Issue 1, March 10, 2026.  
   DOI: [10.46298/lmcs-22(1:18)2026](https://doi.org/10.46298/lmcs-22(1:18)2026). URL: [https://lmcs.episciences.org/17696](https://lmcs.episciences.org/17696).

2. **Hoppscotch Security Advisory:**  
   GitHub Security Lab & Hoppscotch Team, *"IDOR in GraphQL userCollection Query Exposes Other Users' Private Collections,"* GHSA-m5pg-r4jp-qq75 / CVE-2026-28217, February 26, 2026.  
   URL: [https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-m5pg-r4jp-qq75](https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-m5pg-r4jp-qq75).

3. **OWASP API Security Top 10:**  
   OWASP Foundation, *"API1:2023 — Broken Object-Level Authorization,"* 2023.  
   URL: [https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

4. **MITRE CWE:**  
   MITRE Corporation, *"CWE-639: Authorization Bypass Through User-Controlled Key,"* 2024.  
   URL: [https://cwe.mitre.org/data/definitions/639.html](https://cwe.mitre.org/data/definitions/639.html).
