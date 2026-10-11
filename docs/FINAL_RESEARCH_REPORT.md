# Final Research Report: Authorization-Aware Context-Sensitive Taint Analysis for GraphQL BOLA

**Project Title:** GraphQL Shield: Context-Sensitive AST-Driven Taint Analysis and Authorization-Boundary Correlation for Broken Object-Level Authorization (BOLA)  
**Academic Course/Context:** CCNS Project (Computer and Network Security)  
**Current Evaluation Baseline:** 115 Ground-Truth Benchmark Cases (105 Valid Security Cases, 10 Lexical/Syntax Boundary Cases)  
**Test Suite Verification:** 154 Passed Unit & Regression Tests (100% Pass Rate across 20 Test Modules)  
**Git Head Reference:** Commit `c534e77` (Local Working Tree Clean)

---

## Executive Summary

Broken Object-Level Authorization (BOLA), designated as the #1 threat in the OWASP API Security Top 10 (API1:2023), represents one of the most pervasive vulnerabilities in modern distributed architectures. In GraphQL APIs, BOLA poses unique detection and attribution challenges: clients construct arbitrary, deeply nested selection sets combining aliases, fragment spreads, and cross-type relational collections. Existing gateway defenses evaluate authorization primarily through coarse-grained, pre-execution regex or shallow argument inspection. While an existing gateway may successfully drop unauthorized requests, its security explanations remain opaque (emitting isolated HTTP 403 status codes without schema path coordinates), and it frequently loses visibility over nested collection traversals (e.g., `user.resources`) and client-side field aliases. Conversely, purely static taint analysis suffers from catastrophic false positive rates (81.1% on this benchmark) because it lacks access to dynamic caller credentials (JWT claims) and live database tenant ownership records.

This research project introduces **GraphQL Shield**, a hybrid architecture that pairs an AST-driven, context-sensitive static taint propagation engine with runtime authorization policy evidence. Operating in an **audit-only, non-disruptive configuration**, GraphQL Shield correlates static taint findings with dynamic policy execution. 

### Key Findings & Empirical Results:
1. **Binary Detection Recall (Honest Novelty Assessment):**  
   Both the baseline gateway and the correlated model achieve **100.0% recall (52/52)** and **100.0% precision (52/52)** on the 105 valid security benchmark cases. **Correlated analysis does not improve binary blocking recall over the gateway alone on this evaluated corpus.** Claims of superior attack blocking are scientifically unwarranted and rejected.
2. **Exact Path Attribution Accuracy:**  
   Context-sensitive AST taint analysis elevates exact schema path attribution from **56.2% (59/105)** under the gateway alone to **89.5% (94/105)** under correlated analysis, eliminating alias confusion and correctly attributing indirect traversals across nested collections.
3. **Program-Verified Boundary Transparency:**  
   The gateway alone exposes 0 structured boundary criteria (0.0%). The static analyzer represents 100.0% of criteria in its model but verifies 0.0% in the program. Correlated defense represents 100.0% of boundary criteria and dynamically verifies all 4 criteria in the program for **95 / 95 (100.0%) of protected domain object cases** (90.5% across all 105 valid cases; the remaining 10 cases are public/introspection queries requiring no authorization check).
4. **Behavioral Compatibility & Zero Divergence:**  
   Across all 115 benchmark cases, audit-only taint analysis achieves **100.0% behavioral preservation (115/115)**, with zero HTTP status code divergence and zero mutation of response bodies.
5. **Runtime Latency Overhead:**  
   The warmed median latency overhead of the taint engine is **0.295 ms** (P95 = **0.434 ms**), introducing sub-millisecond overhead suitable for inline gateway logging.

---

## 1. Research Question

> **Primary Research Question:**  
> *Does context-sensitive AST-driven taint analysis, when correlated with dynamic authorization policy evidence in an audit-only mode, provide superior source-to-sink path attribution and verifiable authorization-boundary explanations compared to a standalone pre-execution gateway, without altering baseline authorization decisions or incurring prohibitive latency?*

This research formally investigates the hypothesis that the principal failure of existing API gateways is not necessarily binary detection of known single-tenant lookups, but rather **explanatory failure**—the inability to attribute nested relationships, disambiguate client field aliases, trace parameter defaults, and expose verified boundary proofs.

---

## 2. Threat Model

### 2.1 Attacker Profile & Capabilities
- **Authenticated Threat Actor:** The attacker possesses valid authentication credentials (e.g., valid JWT signed by the system's identity provider) granting them standard `user` privileges.
- **Untrusted Input Manipulation:** The attacker controls GraphQL query documents, variable dictionaries, field arguments, operation names, and client aliases.
- **Goal (OWASP API1:2023 - BOLA):** Access, traverse, or enumerate data belonging to another tenant or higher-privileged role (e.g., Alice attempting to access Bob's private notes or Charlie's administrative resources).

### 2.2 Attack Vectors Evaluated
1. **Direct BOLA:** Direct invocation of root queries with foreign object identifiers (e.g., `query { resource(id: 102) { name } }`).
2. **Variable Injection & Defaults:** Supplying foreign IDs via variables or relying on AST variable default values (e.g., `query ($id: Int = 102) { resource(id: $id) { name } }`).
3. **Alias Obfuscation:** Masking sensitive root fields with arbitrary client aliases (e.g., `query { stolenDoc: resource(id: 102) { name } }`).
4. **Fragment Spreading:** Indirection through named fragments and inline fragment spreads to hide argument flows.
5. **Indirect / Nested Collection Traversals:** Accessing foreign resources through unconstrained relational fields on legitimate or foreign objects (e.g., `query { user(id: 102) { resources { id name } } }` or `query { user(id: 101) { resource(id: 102) { id } } }`).

### 2.3 Out of Scope
- SQL injection / NoSQL injection (mitigated via parameterized ORM).
- Broken authentication / forged JWTs (mitigated via asymmetric JWT signature validation).
- Denial of Service / deeply recursive query DOS (mitigated via maximum traversal depth limiting).

---

## 3. Architecture & System Design

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

### 3.1 Core Components
1. **Phase 2 Typed Security Graph (`app/security/security_graph.py`):**  
   Constructs a typed structural graph directly from the Strawberry schema. Nodes represent types (`TypeNode`), fields (`FieldNode`), and arguments (`ArgumentNode`), capturing cardinality, nullability, ownership semantics, and return kinds.
2. **Phase 3 Taint & Boundary Model (`app/security/taint_model.py`):**  
   Defines formal abstractions:
   - `TaintSource`: Client-supplied arguments and variables tagged with `UNTRUSTED_IDENTIFIER` or `UNTRUSTED_PARAMETER`.
   - `PropagationContext`: Traversal context capturing parent type, field, cardinality, collection status, and depth.
   - `SensitiveSink`: Object or collection nodes classified by sensitivity level.
   - `BoundaryEvidence`: Four-criterion authorization boundary record (`principal_bound`, `target_bound`, `mandatory_on_path`, `covers_operation`).
3. **Phase 4 AST Propagation Engine (`app/security/taint_engine.py`):**  
   Recursively walks the GraphQL document AST. Resolves fragment spreads, coerced variable defaults, and alias mappings while tracking dual path coordinates (`schema_path` and `response_path`).
4. **Phase 5/7 Correlation Engine (`app/security/taint_correlation.py`):**  
   Integrates static findings with runtime policy evaluations, assigning formal correlation classifications: `TRUE_POSITIVE_BLOCKED`, `RUNTIME_PROTECTED_ALLOWED`, `BENIGN_AUTHORIZED`, or `POLICY_DENIED_UNCORRELATED`.

---

## 4. Taint Propagation & Boundary Verification Algorithm

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

## 5. Empirical Evaluation Methodology

### 5.1 Corpus Design & Stratification
The evaluation was conducted on a version-controlled, independently labeled corpus of 115 test cases (`data/ground_truth_corpus.json`):
- **52 Ground-Truth BOLA Positive Cases:** Direct attacks (22), variable default injections (1), alias obfuscations (10), fragment indirection (5), and nested collection traversals (14).
- **53 Ground-Truth Benign Negative Cases:** Legitimate owner queries (20), admin privileged queries (15), nested owner collections (8), and public health/introspection queries (10).
- **10 Lexical/Syntax Edge Cases:** Empty query strings, unbalanced braces, invalid field names, and type violations. These fail at the AST parser and are appropriately excluded from security detection denominators.
- **Valid Security Denominator:** **105 cases** (52 Positive, 53 Negative).

### 5.2 Evaluated Methods
- **Method 1 (M1: Gateway Alone):** Pre-execution object extractor and PolicyEngine; emits HTTP status code and unstructured log string.
- **Method 2 (M2: Static Taint Alone):** AST propagation engine operating purely on schema graph and document AST without runtime caller or database context.
- **Method 3 (M3: Correlated Defense):** Integrated architecture pairing AST taint findings with runtime PolicyEngine decisions in audit-only mode.

---

## 6. Comprehensive Comparative Results

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
| **False Alarm Rate (FAR)**| **0.0%** (0/53) | **81.1%** (43/53) | **0.0%** (0/53) |

#### Honest Scientific Assessment on Detection:
> [!IMPORTANT]
> Correlated Defense does **not** increase the binary detection recall over Gateway Alone on this corpus. Both block 52/52 attacks. Static taint alone produces an unacceptable 81.1% false alarm rate because it cannot know whether the runtime caller owns the target resource without executing the database check. The genuine research value of the AST taint analyzer lies in **explanation, path attribution, and boundary transparency**, not in raw binary blocking.

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

### Dimension 4: Illustrative Rubric Scores (12 Representative Archetypes)
*(Note: Evaluates architectural capability completeness across 4 criteria; does not claim independent human subject review).*
- **Method 1 (Gateway Alone):** Mean = **3.33 / 8** (41.6%)
- **Method 2 (Static Taint Alone):** Mean = **5.75 / 8** (71.9%)
- **Method 3 (Correlated Defense):** Mean = **7.83 / 8** (97.9%)

---

### Dimension 5: Latency Overhead Profiling
- **Cold-Start Taint Analysis:** 0.377 ms
- **Warmed Median Latency:** 0.295 ms
- **Warmed 95th Percentile (P95):** 0.434 ms
- **Total Gateway Execution (Warmed):** ~20–25 ms (dominated by SQLite I/O and password hashing)
- **Overhead Assessment:** Static AST analysis adds < 1.5% to total request handling time.

---

### Dimension 6: Behavioral Compatibility
- **Valid Security Cases Decision Preservation:** **100.0%** (105 / 105)
- **Zero-Divergence Audit Preservation:** **100.0%** (115 / 115)
- **HTTP Response Divergence:** **0 cases** (Zero status code changes, zero payload mutations).

---

## 7. Limitations & Threats to Validity

1. **Synthetic Corpus Scope:** While the 115-case corpus covers diverse GraphQL constructs, it is synthetically generated against a controlled schema. Production GraphQL deployments with federation or dynamic directives may introduce additional complexities.
2. **Double-Blind Human Subject Study:** Explanation rubric scores reflect structural capability models, not external developer usability studies.
3. **Audit-Only Dependency:** In audit-only mode, the system relies on the gateway's PolicyEngine for enforcement. If the gateway's policy rule is absent, the system flags the issue in logs but does not block the request.

---

## 8. Reproducibility Instructions

### Environment Requirements
- Python 3.12+ (tested on Python 3.14.0 Windows)
- Dependencies: `fastapi`, `strawberry-graphql`, `pydantic`, `pytest`, `httpx`, `pyjwt`

### Commands
```powershell
# 1. Run Complete Test Suite (154 passing tests)
python -m pytest tests/ -q

# 2. Run Phase 7 Comparative Evaluation Script
python scripts/evaluate_phase_7.py

# 3. Run Live Interactive Demonstration Script
python scripts/demo_live_showcase.py
```
All outputs are self-contained and reproduce with 100% determinism.
