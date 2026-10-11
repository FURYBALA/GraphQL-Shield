# Phase 6: Ground-Truth Dataset and Rigorous Evaluation Methodology

## 1. Executive Summary

Phase 6 establishes a reproducible, scientifically rigorous, and independently labeled evaluation benchmark to measure **Direct and Indirect GraphQL Broken Object Level Authorization (BOLA)** detection across three distinct architectural paradigms:
1. **Method 1: Existing Gateway Alone** (Dynamic runtime ownership enforcement without taint analysis).
2. **Method 2: Static Taint Analysis Alone** (AST-driven context-sensitive taint propagation without runtime authentication context).
3. **Method 3: Correlated Defense** (Context-sensitive AST taint analysis correlated with dynamic runtime gateway policies).

The evaluation is conducted on an independently labeled benchmark corpus of **115 test cases** spanning direct attacks, nested collection traversals, aliases, variables, named fragments, inline fragments, multi-root queries, public fields, admin overrides, boundary values, and syntax errors.

---

## 2. Threat Model and Labeling Methodology

### 2.1. Threat Model
- **Adversary Capability:** An authenticated adversary (`user_id = 101` or `102`) issues arbitrary, valid or malformed GraphQL queries over HTTP POST `/graphql`. The attacker may introduce arbitrary GraphQL syntactic constructs (aliases, nested spreads, variables with default values, multiple root fields) to bypass edge inspection.
- **Security Objective:** Ensure that principals can only access objects they legitimately own (or have explicit administrative rights to access), whether accessed directly via root fields (e.g. `Query.resource(id)`) or indirectly through graph navigation (e.g. `Query.user(id).resources` or `Query.resource(id).children`).

### 2.2. Independent Ground-Truth Definition
Ground-truth security labels are established strictly according to the **formal access control specification**, completely decoupled from the predictions of any static analyzer or gateway tool:

- **`VULNERABLE`:** A request where the authenticated principal attempts to access, traverse, or probe an object or collection not owned by that principal (e.g., Alice requesting Bob's document `102`, or Alice querying Bob's `user(id: 102).resources`).
- **`BENIGN`:** An authorized request where the principal is the legitimate owner (`user_id == owner_id`), holds an administrative override role (`role == 'admin'`), or accesses an unrestricted public field (`Query.health`, schema introspection).
- **`MALFORMED`:** Syntactically invalid GraphQL documents that violate the GraphQL specification (e.g., unclosed delimiters, unknown schema fields, missing arguments).

**Critical Principle:** No case is labeled vulnerable merely because the static analyzer flags it. Legitimate owner queries parameterized by input arguments (e.g., Alice requesting her own document `101`) are classified as `BENIGN` in the ground truth, even though static taint analysis identifies client input flowing to a sensitive sink.

---

## 3. Benchmark Dataset Composition

The dataset is version-controlled at `data/ground_truth_corpus.json` and comprises **115 distinct test cases**:

| Scenario Category | Count | Ground-Truth Distribution | Syntactic Characteristics |
| :--- | :---: | :--- | :--- |
| **Direct BOLA (Unauthorized)** | 22 | 22 Vulnerable | Single-hop root lookups on victim documents, user profiles, folders, and admin logs. Includes aliases, variables, fragments, and unowned ID probes. |
| **Indirect BOLA (Unauthorized)** | 22 | 22 Vulnerable | Nested collection traversals (`User.resources`), nested parameterized fields (`User.resource(id)`), folder hierarchies (`Resource.children`), and nested alias/fragment spreads. |
| **Legitimate Owner Access** | 25 | 25 Benign | Direct lookups, collections, nested relationships, and multi-field queries on owned resources (`101`, `201`, `202`, `203`) by Alice or Bob. |
| **Admin Privileged Access** | 10 | 10 Benign | Administrative inspection by Charlie (`103`) across Alice and Bob objects, verifying authorized cross-tenant overrides. |
| **Public & Introspection** | 10 | 10 Benign | Unparameterized public health pings, root `__typename`, schema introspection, and type queries. |
| **Multi-Root Field Selections** | 10 | 5 Vulnerable, 5 Benign | Queries containing dual or triple root selections (e.g., bundling legitimate own objects with unauthorized victim objects or health checks). |
| **Syntax Errors & Malformed Queries** | 10 | 10 Malformed | Unclosed braces, undefined fields, invalid string literals, missing mandatory arguments, wrong scalar types, and empty bodies. |
| **Edge Cases & Boundary Conditions** | 6 | 3 Vulnerable, 3 Benign | Boundary IDs (`0`, `-1`), deep multi-hop hierarchies, multi-fragment reuse, and multi-variable binding. |
| **Total** | **115** | **52 Vulnerable, 53 Benign, 10 Malformed** | Comprehensive coverage across all GraphQL syntactic and operational dimensions. |

---

## 4. Multi-Method Comparative Evaluation

### 4.1. Unit of Evaluation
The unit of evaluation is **one complete GraphQL operation request** evaluated under a specific authenticated principal.

### 4.2. Comparative Results Summary

| Metric | Method 1: Gateway Alone (Runtime Baseline) | Method 2: Static Taint Alone (AST Analyzer) | Method 3: Correlated Defense (Taint + Gateway) |
| :--- | :---: | :---: | :---: |
| **Evaluated Valid Cases** | 105 | 105 | 105 |
| **True Positives (TP)** | 51 | 52 | 51 |
| **False Positives (FP)** | 0 | 43 | 0 |
| **True Negatives (TN)** | 53 | 10 | 53 |
| **False Negatives (FN)** | 1 | 0 | 1 |
| **Precision** | **100.0%** | **54.7%** | **100.0%** |
| **Recall** | **98.1%** | **100.0%** | **98.1%** |
| **F1-Score** | **0.990** | **0.708** | **0.990** |
| **Overall Accuracy** | **99.1%** | **59.1%** | **99.1%** |
| **Legitimate Denial Rate (FP Rate)** | **0.0%** | **81.1%** | **0.0%** |
| **Direct BOLA Detection Recall** | **96.5%** (28/29) | **100.0%** (29/29) | **96.5%** (28/29) |
| **Indirect BOLA Detection Recall** | **100.0%** (23/23) | **100.0%** (23/23) | **100.0%** (23/23) |

---

## 5. Scientific Analysis of Comparative Findings

### 5.1. Method 2 (Static Taint Alone): The "Semantic Blindness" Problem
- **Strengths:** Achieved **100.0% Recall** across both direct and indirect BOLA cases, successfully identifying all 52 attack scenarios including variable-driven attacks, complex fragment spreads, and nested collection navigations.
- **Weakness:** Suffered from **43 False Positives**, resulting in a precision of only **54.7%** and a prohibitive **81.1% legitimate denial rate**.
- **Root Cause:** Pure static analysis operates strictly on the GraphQL query document. Without authenticated JWT runtime context, static taint propagation cannot determine *who* is issuing the request (Alice vs. Bob). It correctly identifies that an untrusted argument flows into a sensitive sink, but cannot determine whether the caller is the legitimate owner.

### 5.2. Method 1 (Gateway Alone): The "AST Default Value" Blind Spot
- **Strengths:** Achieved **100.0% Precision** and zero false alarms on legitimate owner requests.
- **Weakness:** Missed **1 vulnerability** (`CORPUS-018`: *Variable with default value direct BOLA*), yielding 98.1% recall.
- **Root Cause:** The runtime object extractor (`app/security/object_extractor.py`) inspected incoming variable key-value pairs from the HTTP JSON body (`variables.get(var_name)`). When an attacker relied on a variable default value declared in the query header (`query GetDoc($target: Int = 102)` with empty variables `{}`), the runtime extractor found no bound variable, resulting in an authorization bypass.
- **Insight:** Static AST taint analysis caught this attack because it parses `VariableDefinitionNode.default_value`, highlighting the necessity of AST-aware analysis.

### 5.3. Method 3 (Correlated Defense): The Optimal Production Balance
- By correlating static taint candidates with dynamic runtime boundary evaluations:
  - Eliminates all 43 false positives exhibited by static analysis (`RUNTIME_PROTECTED_ALLOWED` distinguishes authorized owners).
  - Maintains **100.0% Precision**, **0.0% False Alarm Rate**, and **0.990 F1-Score**.
  - Provides explainable audit evidence logging for security operations.

---

## 6. Execution Latency Profiling

Latency profiling was performed over 3 repeated iterations across all 115 corpus queries on Windows (Python 3.14):

| Latency Metric | Timing (ms) | Notes |
| :--- | :---: | :--- |
| **Cold-Start Latency (1st Query)** | **0.362 ms** | One-time compilation of schema graph $G = (V, E)$ cached in memory. |
| **Warmed-Up Median Latency** | **0.293 ms** | Sub-millisecond AST propagation per query. |
| **Warmed-Up Mean Latency** | **0.308 ms** | Consistent execution time across varied queries. |
| **Warmed-Up P95 Latency** | **0.419 ms** | 95% of queries analyze in under 0.42 ms. |
| **Warmed-Up Minimum / Maximum** | **0.047 ms / 4.613 ms** | Min on unparameterized health; max on deep multi-fragment spreads. |

---

## 7. Performance by GraphQL Syntax Category

| Syntax Category | Valid Cases | Gateway Recall | Static Recall | Correlated Recall | Static FP | Correlated FP |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `BASIC` | 39 | 100.0% | 100.0% | 100.0% | 18 | 0 |
| `ALIAS` | 7 | 100.0% | 100.0% | 100.0% | 3 | 0 |
| `VARIABLE` | 10 | 80.0% | 100.0% | 80.0% | 5 | 0 |
| `FRAGMENT` | 6 | 100.0% | 100.0% | 100.0% | 3 | 0 |
| `INLINE_FRAGMENT`| 3 | 100.0% | 100.0% | 100.0% | 1 | 0 |
| `MULTI_ROOT` | 10 | 100.0% | 100.0% | 100.0% | 5 | 0 |
| `RELATIONSHIP` | 2 | 100.0% | 100.0% | 100.0% | 1 | 0 |
| `NESTED_PARAM` | 6 | 100.0% | 100.0% | 100.0% | 2 | 0 |
| `PUBLIC` | 6 | N/A (Benign) | N/A (Benign) | N/A (Benign) | 0 | 0 |
| `INTROSPECTION` | 4 | N/A (Benign) | N/A (Benign) | N/A (Benign) | 0 | 0 |
| `BOUNDARY_ID` | 2 | 100.0% | 100.0% | 100.0% | 0 | 0 |
| `DEEP_TRAVERSAL` | 2 | 100.0% | 100.0% | 100.0% | 1 | 0 |

---

## 8. Reproducibility Instructions

### 8.1. Rebuilding Ground-Truth Corpus
```bash
python scripts/build_ground_truth_corpus.py
```

### 8.2. Executing Full Multi-Method Evaluation
```bash
python scripts/evaluate_taint_corpus.py --corpus data/ground_truth_corpus.json --output docs/EVALUATION_REPORT.json
```

### 8.3. Running Evaluation Test Suite
```bash
python -m pytest tests/test_evaluation_framework.py -v
```

---

## 9. Limitations & Research Scope

1. **Schema Scope:** The evaluated dataset is constructed around the current Strawberry GraphQL schema (`User`, `Resource`, `HealthCheck`) and its relational SQLite database backend. While structurally diverse, performance on multi-megabyte enterprise schemas with hundreds of types may exhibit different graph traversal scaling characteristics.
2. **Synthetic Identities:** Test cases utilize synthetic user identities (`alice: 101`, `bob: 102`, `charlie: 103`) in isolated databases. No production or personal data was utilized.
3. **AST Parser Boundary:** The static analyzer assumes valid GraphQL AST input. Malformed queries fast-fail to GraphQL execution errors rather than security decisions.
