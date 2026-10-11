# Phase 6 & 6.1: Ground-Truth Dataset, Independent Evaluation Audit, and Defect Investigation

## 1. Executive Summary

This document establishes the independent audit, evaluation methodology, and comparative benchmarking framework for **Direct and Indirect GraphQL Broken Object Level Authorization (BOLA)** vulnerabilities in the GraphQL Shield gateway.

### 1.1. Core Audit Findings
1. **Benchmark Corpus Scope:** A standardized, version-controlled dataset of **115 test cases** was constructed and validated at `data/ground_truth_corpus.json`.
2. **Label Independence:** Security ground truth (`VULNERABLE`, `BENIGN`, `MALFORMED`) was assigned independently based on formal access-control policies (ownership and role rules), not from tool predictions.
3. **Investigation of `CORPUS-018` Defect:** The audit confirmed a genuine authorization bypass defect in `app/security/object_extractor.py`: when GraphQL operations declared variable default values in the query header (e.g., `query GetDoc($target: Int = 102)` with empty variables `{}`), the extractor failed to inspect AST `VariableDefinitionNode.default_value`, returning empty objects and allowing Alice to access Bob's document (HTTP 200).
4. **Targeted Fix & Verification:** The defect was reproduced with a dedicated regression suite (`tests/test_variable_defaults_regression.py`), safely resolved by merging AST default values into effective variables, and verified across all 147 test cases with zero regressions.
5. **Rigorous Method Clarification:** We explicitly clarify the semantic distinction between **Request Authorization Enforcement** (Methods 1 & 3) and **Static Vulnerability Detection** (Method 2).
6. **Honest Novelty Assessment:** With the extractor defect resolved, Correlated Defense and Gateway Alone both achieve **100.0% binary request recall** on this corpus. The research value of Correlated Defense lies in **explainable source-to-sink path attribution**, **formal boundary modeling**, and **structured auditability**, not in higher binary block rates on this schema.

---

## 2. Threat Model and Independent Ground-Truth Formulation

### 2.1. Threat Model
- **Adversary Capability:** Authenticated users (`alice: 101`, `bob: 102`) submit arbitrary GraphQL queries over HTTP POST `/graphql`. The attacker attempts to view objects belonging to other users or administrators by manipulating object IDs, traversing navigation fields, utilizing aliases, declaring variable defaults, or spreading fragments.
- **Security Axiom:** An object access request is authorized if and only if:
  $$\text{Authorized}(u, o) \iff (u.\text{id} == o.\text{owner\_id}) \lor (u.\text{role} == \text{'admin'}) \lor (\text{IsPublic}(o))$$

### 2.2. Ground-Truth Categorization
- **`VULNERABLE` (52 cases):** An unauthorized request where the authenticated principal lacks ownership or administrative privilege over the requested entity or collection.
- **`BENIGN` (53 cases):** An authorized request where the principal is the legitimate owner, an administrator with override rights, or queries a public unrestricted field (`health`, introspection).
- **`MALFORMED` (10 cases):** Syntactically invalid GraphQL documents that violate the GraphQL specification.

---

## 3. Dataset Distribution (115 Cases)

```
=================================================================
  GROUND-TRUTH BENCHMARK CORPUS COMPOSITION
=================================================================
Total Test Cases Generated : 115
  Vulnerable (Attack Cases): 52
    - Direct BOLA Attacks  : 29
    - Indirect BOLA Attacks: 23
  Benign (Authorized Cases): 53
    - Legitimate Owners    : 25
    - Admin Overrides      : 10
    - Public / Schema      : 10
    - Multi-Root Legitimate:  8
  Malformed (Syntax Errors): 10
=================================================================
```

---

## 4. Method Clarification: What Does Each Method Predict?

| Evaluation Method | Input Analyzed | Output / Prediction Meaning | Target Ground-Truth Metric |
| :--- | :--- | :--- | :--- |
| **Method 1: Gateway Alone** (Runtime Baseline) | Extracted objects from query + runtime JWT user + SQLite database state. | **Runtime Authorization Decision:** Predicts `VULNERABLE` if the gateway issues an HTTP 403 `DENY`; `BENIGN` if it issues HTTP 200 `ALLOW`. | Request-Level Authorization Enforcement. |
| **Method 2: Static Taint Alone** (AST Propagation Engine) | Query AST document + variable names/types (zero runtime identity). | **Static Vulnerability Candidate:** Predicts `VULNERABLE` if untrusted input flows into a sensitive sink without verifiable boundary; `BENIGN` if no flow. | Static Threat Detection / Candidate Screening. |
| **Method 3: Correlated Defense** (Taint + Gateway Boundary) | Query AST + Taint Propagation + Runtime Boundary Evaluation. | **Correlated Authorization Block:** Predicts `VULNERABLE` if a static candidate is confirmed blocked by runtime boundary (`TRUE_POSITIVE_BLOCKED`); `BENIGN` if verified authorized (`RUNTIME_PROTECTED_ALLOWED`). | Explainable Request-Level Defense. |

---

## 5. Investigation and Resolution of `CORPUS-018`

### 5.1. Defect Description
In `CORPUS-018`:
```graphql
query GetDoc($target: Int = 102) {
  resource(id: $target) {
    name
  }
}
```
HTTP Payload: `{"query": "...", "variables": {}}`.

### 5.2. Root Cause Analysis
1. The GraphQL specification (Section 5.8.3) defines that when a variable is omitted from the request variables dictionary, execution falls back to the declared `default_value` in `VariableDefinitionNode`.
2. Strawberry GraphQL faithfully followed this specification: when `$target` was omitted, it resolved `id = 102` (Bob's financial record).
3. However, `app/security/object_extractor.py` only inspected `variables.get("target")`. Because the HTTP JSON dictionary was empty, `variables.get("target")` returned `None`.
4. As a result, `normalize_query` returned `{"operation": "query", "objects": []}`, causing the gateway to skip authorization checks and allow Alice to view Bob's data (HTTP 200).

### 5.3. Corrective Implementation
In `app/security/object_extractor.py`:
```python
# Resolve effective variable values: explicit variables override AST default values
effective_vars = dict(variables) if variables else {}
if definition.variable_definitions:
    for var_def in definition.variable_definitions:
        var_name = var_def.variable.name.value
        if var_name not in effective_vars and var_def.default_value is not None:
            if isinstance(var_def.default_value, (IntValueNode, StringValueNode)):
                effective_vars[var_name] = var_def.default_value.value
```

### 5.4. Regression Verification
A dedicated test suite was implemented in `tests/test_variable_defaults_regression.py` (4 tests), verifying:
1. `normalize_query` correctly resolves default values when variables map is empty.
2. Explicit variables correctly override default values when supplied.
3. Gateway drops Alice's unauthorized request with HTTP 403.
4. Gateway allows Alice's request when accessing her own document default with HTTP 200.

---

## 6. Multi-Method Comparative Performance Results

### 6.1. Post-Resolution Performance Table (105 Valid Security Cases)

| Metric | Method 1: Gateway Alone | Method 2: Static Taint Alone | Method 3: Correlated Defense |
| :--- | :---: | :---: | :---: |
| **Evaluated Security Cases** | 105 | 105 | 105 |
| **True Positives (TP)** | 52 | 52 | 52 |
| **False Positives (FP)** | 0 | 43 | 0 |
| **True Negatives (TN)** | 53 | 10 | 53 |
| **False Negatives (FN)** | 0 | 0 | 0 |
| **Precision** | **100.0%** (52/52) | **54.7%** (52/95) | **100.0%** (52/52) |
| **Recall** | **100.0%** (52/52) | **100.0%** (52/52) | **100.0%** (52/52) |
| **F1-Score** | **1.000** | **0.708** | **1.000** |
| **Overall Accuracy** | **100.0%** (105/105) | **59.1%** (62/105) | **100.0%** (105/105) |
| **Legitimate Denial Rate (FP Rate)** | **0.0%** (0/53) | **81.1%** (43/53) | **0.0%** (0/53) |
| **Direct BOLA Detection Recall** | **100.0%** (29/29) | **100.0%** (29/29) | **100.0%** (29/29) |
| **Indirect BOLA Detection Recall** | **100.0%** (23/23) | **100.0%** (23/23) | **100.0%** (23/23) |

### 6.2. Mathematical Verification of Confusion Matrix
- Ground Truth Positives ($P = 52$):
  - Method 1: $\text{TP} = 52, \text{FN} = 0 \implies \text{Recall} = 52/52 = 1.000$.
  - Method 2: $\text{TP} = 52, \text{FN} = 0 \implies \text{Recall} = 52/52 = 1.000$.
  - Method 3: $\text{TP} = 52, \text{FN} = 0 \implies \text{Recall} = 52/52 = 1.000$.
- Ground Truth Negatives ($N = 53$):
  - Method 1: $\text{TN} = 53, \text{FP} = 0 \implies \text{Precision} = 52/(52+0) = 1.000$.
  - Method 2: $\text{TN} = 10, \text{FP} = 43 \implies \text{Precision} = 52/(52+43) = 0.5474$.
  - Method 3: $\text{TN} = 53, \text{FP} = 0 \implies \text{Precision} = 52/(52+0) = 1.000$.

---

## 7. Honest Novelty & Research Value Assessment

With the extractor defect resolved, **Correlated Defense does NOT improve binary recall or precision over the Gateway Alone** on this test corpus. Both achieve 100.0% precision and 100.0% recall on the 115 benchmark cases.

### Genuine Verified Benefits of Correlated Defense:
1. **Explainable Path Attribution:** The Gateway Alone only logs a scalar rejection (`object_id=102, reason=OWNERSHIP_MISMATCH`). Correlated Defense produces a complete AST path trace (`Query.user(id).resources -> sink:ResourceType`) documenting exactly where taint entered, what variables or aliases were used, and why the boundary was breached.
2. **Authorization Boundary Modeling:** Correlated Defense classifies boundaries by evidence (`principal_bound`, `target_bound`, `mandatory_on_path`, `covers_operation`), distinguishing authorized owner access (`RUNTIME_PROTECTED_ALLOWED`) from benign non-sensitive operations (`BENIGN_AUTHORIZED`).
3. **Proactive Security Graph Visibility:** Enables static pre-execution analysis of prospective query patterns before database queries are initiated, providing valuable auditing for Security Operations Centers (SOC).

---

## 8. Latency Profiling

Across 3 repeated profiling runs on all 115 test cases (Windows, Python 3.14):
- **Cold-Start (Initial Query):** **0.362 ms** (Security graph initialization cached in memory).
- **Warmed-Up Median Latency:** **0.275 ms**.
- **Warmed-Up Mean Latency:** **0.294 ms**.
- **Warmed-Up P95 Latency:** **0.404 ms**.
- **Warmed-Up Range:** **0.046 ms** (public health query) to **4.272 ms** (complex multi-fragment query).

---

## 9. Reproduction Instructions

```bash
# 1. Run all regression tests
python -m pytest tests/test_variable_defaults_regression.py -v

# 2. Run evaluation framework tests
python -m pytest tests/test_evaluation_framework.py -v

# 3. Execute full multi-method evaluation and update JSON report
python scripts/evaluate_taint_corpus.py --corpus data/ground_truth_corpus.json --output docs/EVALUATION_REPORT.json

# 4. Run full repository test suite (147 tests)
python -m pytest tests/
```
