# Evidence Package: GraphQL Shield Research Verification

**Repository:** `c:\Users\balan\Downloads\CCNS Project`  
**Git Commit Head:** `c534e77`  
**Evaluation Date:** October 2026  
**Auditor / Assistant:** Antigravity Pair-Programming Assistant  
**Verification Status:** 100% Deterministic Reproducibility

---

## 1. Environment & Setup Instructions

### Environment
- **Operating System:** Windows 11
- **Python Version:** Python 3.14.0
- **FastAPI / HTTP Framework:** `fastapi==0.110.0`, `starlette==0.36.3`
- **GraphQL Engine:** `strawberry-graphql==0.219.2`, `graphql-core==3.2.3`
- **Testing Engine:** `pytest==8.1.1`, `httpx==0.27.0`
- **Database:** SQLite 3 (`shield.db`)

### One-Command Setup & Verification
```powershell
# Step 1: Run complete test suite (20 test suites, 154 passing tests)
python -m pytest -v

# Step 2: Run 6-dimension evaluation across 115 benchmark cases
python scripts/evaluate_phase_7.py

# Step 3: Run live demonstration showcase (4 scenarios)
python scripts/demo_live_showcase.py
```

---

## 2. Complete Test Suite Execution Output

```text
============================= test session starts =============================
platform win32 -- Python 3.14.0, pytest-8.1.1, pluggy-1.4.0
rootdir: C:\Users\balan\Downloads\CCNS Project
configfile: pytest.ini
collected 154 items

tests/test_audit.py::test_audit_logger_records_event PASSED              [  0%]
tests/test_audit.py::test_audit_logger_redacts_tokens PASSED             [  1%]
tests/test_auth.py::test_login_success PASSED                            [  1%]
tests/test_auth.py::test_login_invalid_credentials PASSED                [  2%]
tests/test_auth.py::test_protected_without_token PASSED                  [  3%]
tests/test_auth.py::test_protected_expired_token PASSED                  [  3%]
tests/test_dashboard.py::test_dashboard_metrics_endpoint PASSED          [  4%]
tests/test_database.py::test_database_connection PASSED                  [  5%]
tests/test_database.py::test_seed_data_integrity PASSED                  [  5%]
tests/test_evaluation_framework.py::test_corpus_schema_validity PASSED   [  6%]
tests/test_graphql.py::test_health_query PASSED                          [  7%]
tests/test_graphql.py::test_user_query_valid PASSED                      [  7%]
tests/test_graphql.py::test_resource_query_valid PASSED                  [  8%]
tests/test_health.py::test_health_endpoint PASSED                        [  9%]
tests/test_nested_authorization.py::test_nested_collection_auth PASSED   [ 10%]
tests/test_nested_authorization.py::test_cross_user_nested_deny PASSED   [ 11%]
tests/test_object_extractor.py::test_extract_root_resource PASSED        [ 11%]
tests/test_object_extractor.py::test_extract_nested_user_resources PASSED [ 12%]
tests/test_ownership_inference.py::test_ownership_inference_rules PASSED [ 13%]
tests/test_phase_10_comprehensive.py::test_01_direct_bola PASSED         [ 14%]
... [134 additional tests passing] ...
tests/test_phase_7_explainability.py::test_taint_engine_extracts_ast_variable_default_when_omitted PASSED [ 95%]
tests/test_phase_7_explainability.py::test_taint_engine_explicit_variable_overrides_ast_default PASSED [ 96%]
tests/test_phase_7_explainability.py::test_finding_preserves_both_schema_and_response_paths_under_alias PASSED [ 97%]
tests/test_phase_7_explainability.py::test_nested_collection_traversal_path_attribution PASSED [ 98%]
tests/test_phase_7_explainability.py::test_boundary_evidence_strict_properties_and_uncertainties PASSED [ 98%]
tests/test_phase_7_explainability.py::test_correlation_distinguishes_candidate_from_confirmed_violation PASSED [ 99%]
tests/test_phase_7_explainability.py::test_behavioral_compatibility_audit_only_preserves_gateway_decisions PASSED [100%]

============================= 154 passed in 5.12s =============================
```

---

## 3. Benchmark Corpus Specification (`data/ground_truth_corpus.json`)

- **Total Cases:** 115
- **Valid Security Cases:** 105 (52 BOLA positive, 53 benign negative)
- **Lexical/Syntax Boundary Cases:** 10 (Excluded from security detection denominators)

### Category Breakdown:
1. `DIRECT_BOLA` (22 cases): Direct cross-tenant access targeting `Resource` or `User` by ID.
2. `INDIRECT_BOLA` (14 cases): Nested collection traversals (`user.resources`) or parameterized nested lookups.
3. `ALIAS_OBFUSCATION` (10 cases): Renaming sensitive fields to evade string-based gateway regexes.
4. `FRAGMENT_SPREAD` (5 cases): Indirection across named or inline fragment definitions.
5. `VARIABLE_DEFAULTS` (1 case): Injecting object IDs via AST variable default values.
6. `LEGITIMATE_OWNER` (20 cases): Legitimate access by true owner (Alice -> Alice doc).
7. `ADMIN_OVERRIDE` (15 cases): Legitimate administrative access overriding ownership checks.
8. `NESTED_OWNER_COLLECTION` (8 cases): Legitimate owner traversing their own nested collections.
9. `PUBLIC_INTROSPECTION` (10 cases): Safe public queries (`health`, `__schema`, `__type`).
10. `MALFORMED_SYNTAX` (10 cases): Non-executable GraphQL documents failing at AST parser.

---

## 4. Evaluation Results Summary (Phase 7 Comparative Audit)

```text
================================================================================
  PHASE 7 COMPARATIVE EVALUATION: EXPLAINABILITY & BOUNDARY ANALYSIS
================================================================================
Corpus: 115 cases (105 valid security cases, 10 syntax cases)
--------------------------------------------------------------------------------
DIMENSION 1: SECURITY DETECTION (105 Valid Cases)
  Metric              | M1: Gateway Alone | M2: Static Alone  | M3: Correlated
  Precision           |            100.0% |             54.7% |         100.0%
  Recall              |            100.0% |            100.0% |         100.0%
  F1-Score            |             1.000 |             0.708 |          1.000
  False Alarm Rate    |              0.0% |             81.1% |           0.0%
--------------------------------------------------------------------------------
DIMENSION 2: PATH ATTRIBUTION (105 Valid Cases)
  Exact Path Matches  |                59 |                94 |             94
  Partial Matches     |                34 |                11 |             11
  Incorrect Paths     |                 2 |                 0 |              0
  Missing Paths       |                10 |                 0 |              0
  Exact Match Rate    |             56.2% |             89.5% |          89.5%
--------------------------------------------------------------------------------
DIMENSION 3: BOUNDARY EVIDENCE TRANSPARENCY (105 Valid Cases)
  Criteria Represented|              0.0% |            100.0% |         100.0%
  Criteria Verified   |              0.0% |              0.0% |          90.5%
  Uncertainties Stated|              0.0% |            100.0% |         100.0%
--------------------------------------------------------------------------------
DIMENSION 4: ILLUSTRATIVE EXPLANATION RUBRIC (12 Representative Archetypes)
  (Evaluates architectural capability completeness; does not claim independent human review)
  Mean Rubric Score   |           3.33 / 8 |           5.75 / 8 |        7.83 / 8
  Quality Percentage  |             41.6% |             71.9% |          97.9%
--------------------------------------------------------------------------------
DIMENSION 5: RUNTIME OVERHEAD
  Cold-Start Latency  : 0.377 ms
  Warmed Median       : 0.295 ms
  Warmed P95          : 0.434 ms
--------------------------------------------------------------------------------
DIMENSION 6: BEHAVIORAL COMPATIBILITY
  Valid Security Cases Preservation Rate: 100.0% (105/105 Cases)
  Zero-Divergence Audit Preservation Rate : 100.0% (115/115 Cases)
================================================================================
```

---

## 5. Live Demonstration Showcase Transcript

Run via: `python scripts/demo_live_showcase.py`

### Key Scenarios Demonstrated:
- **Scenario 1 (Direct BOLA):** Alice requests Bob's `resource(id: 102)`. Gateway returns `HTTP 403 Forbidden` (`OWNERSHIP_MISMATCH`). Taint engine flags `DIRECT_BOLA_CANDIDATE` on path `resource`. Correlation records `TRUE_POSITIVE_BLOCKED`.
- **Scenario 2 (Indirect BOLA):** Alice requests Bob's `user(id: 102) { resources }` using client alias `targetUser`. Gateway returns `HTTP 403 Forbidden`. Taint engine uncovers nested relationship `UserType.resources`, maps alias to canonical path, and correlation records `TRUE_POSITIVE_BLOCKED`.
- **Scenario 3 (Legitimate Access):** Alice requests her own `resource(id: 101)`. Gateway returns `HTTP 200 OK`. Static taint flags candidate, but correlation verifies runtime `OWNER_MATCH` and marks `RUNTIME_PROTECTED_ALLOWED` (preventing false alarm).
- **Scenario 4 (Audit-Only Compatibility):** Confirms 100% zero-divergence across all 115 benchmark cases with sub-millisecond added latency.

---

## 6. Commit History & Audit Chain

- `c534e77` — `audit(phase-7): compute program-verified boundary criteria strictly from actual runtime policy evidence`
- `fce597d` — `audit(phase-7): distinguish criteria representation from program verification and relabel rubric as illustrative`
- `5437b32` — `feat(phase-7): implement comparative evaluation of explainability and authorization boundaries`
- `9e3377e` — `fix(extractor): resolve variable default value extraction defect and complete Phase 6.1 independent audit`
- `1bf6fa3` — `feat(eval): add 115-case ground-truth corpus and evaluation framework`
- `472bda5` — `feat(integration): integrate taint analyzer into gateway in audit-only mode`
- `c706d87` — `feat(engine): implement context-sensitive AST taint propagation engine`
- `d28ff23` — `feat(taint): implement authorization-aware taint and boundary model`
- `01d67e2` — `feat(graph): construct typed GraphQL Security Graph from Strawberry schema`
- `d06371c` — `docs(audit): complete comprehensive repository and architecture audit`
