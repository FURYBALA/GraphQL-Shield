# GraphQL Taint and Authorization Boundary Model Specification

**Phase:** Phase 3 — Taint and Authorization-Boundary Modeling  
**Module:** `app/security/taint_model.py`  
**Research Objective:** Authorization-Aware Context-Sensitive Taint Analysis for Direct and Indirect GraphQL BOLA  

---

## 1. Executive Overview

This specification establishes the formal semantic foundations of the **Authorization-Aware Context-Sensitive Taint Analysis Model**. It builds directly upon the GraphQL Security Graph $G = (V, E)$ constructed in Phase 2.

### Critical Safety & Scientific Distinction
> [!IMPORTANT]
> **Candidate Finding vs. Confirmed Exploit:**  
> The taint model discovers and classifies **candidate exposure paths** and records structural evidence. The existence of a relationship, traversal hop, or unparameterized collection **must never be reported as a confirmed vulnerability** without concrete dynamic verification. All findings document their **explicit assumptions and uncertainties**.

---

## 2. Core Analysis Concepts

```
┌─────────────────┐         ┌────────────────────────┐         ┌─────────────────────────┐
│  Taint Source   │ ──────> │  Propagation Context   │ ──────> │     Sensitive Sink      │
│ (Variables/Args)│         │ (Path, Type, Edge, Hop)│         │ (Domain Object/Collect.)│
└─────────────────┘         └───────────┬────────────┘         └─────────────────────────┘
                                        │
                                        ▼
                            ┌────────────────────────┐
                            │ Authorization Boundary │
                            │ (Evidence Evaluation)  │
                            └───────────┬────────────┘
                                        │
                                        ▼
                            ┌────────────────────────┐
                            │    Analysis Finding    │
                            │ (Direct/Indirect/Safe) │
                            └────────────────────────┘
```

### 2.1 Taint Sources (`TaintSource`)
Client-controlled parameters that can identify, select, or influence access to protected domain entities.

- **`TaintSourceKind`:**
  - `FIELD_ARGUMENT`: Arguments defined directly on GraphQL query fields (e.g., `resource(id: 101)`).
  - `VARIABLE`: Values passed via the operation variables JSON envelope (`$resId: Int!`).
- **`TaintTag`:**
  - `UNTRUSTED_IDENTIFIER`: Arguments whose name or type matches entity identifier heuristics (`id`, `*_id`, `pk`, `uuid`).
  - `UNTRUSTED_PARAMETER`: General query arguments influencing filtering or pagination.

### 2.2 Propagation Contexts (`PropagationContext`)
A strictly context-sensitive path tracker ensuring that the same GraphQL type or field reached through different paths is evaluated in its distinct execution and relationship context.

- **Context Attributes:**
  - `operation`: Root operation (`query`, `mutation`).
  - `field_path`: Dotted traversal path (e.g., `resource`, `user.resources`, `user.resource`).
  - `parent_type`: Enclosing GraphQL type name (e.g., `Query`, `UserType`).
  - `field_name`: Invoked field name (e.g., `resources`).
  - `target_type`: Unwrapped return type name (e.g., `ResourceType`).
  - `argument_name`: Explicit argument driving the lookup (or `None`).
  - `cardinality`: `ONE_TO_ONE` vs `ONE_TO_MANY`.
  - `step_depth`: Distance from root operation (`0` for direct lookup, `1` for first nested hop, etc.).
  - `carried_taint_tags`: Set of taint tags flowing into this step.

### 2.3 Authorization Boundaries (`AuthorizationBoundary` & `BoundaryEvidence`)
Access control mechanisms evaluated to determine whether the authenticated caller has permission for a specific target object or relationship.

#### Boundary Classifications
1. **`VERIFIED_BOUNDARY`:**
   - Concrete, verifiable evidence proves that the check:
     - Uses the authenticated principal identity (`principal_bound = True`).
     - Applies directly to the target object instance or relationship edge (`target_bound = True`).
     - Is mandatory on the relevant execution path (`mandatory_on_path = True`).
     - Covers the requested operation (`covers_operation = True`).
2. **`UNVERIFIED_BOUNDARY`:**
   - A check is claimed or suspected (e.g., naming hint or gateway interception candidate), but lacks static proof of target entity binding, tenant isolation, or path coverage.
3. **`NO_BOUNDARY_IDENTIFIED`:**
   - No access-control check or tenancy filter is detected on the navigation step.

#### Boundary Scopes
- `OBJECT_LEVEL`: Protects a specific instance of a domain entity.
- `RELATIONSHIP_LEVEL`: Protects the navigation association between parent and child.
- `FIELD_LEVEL`: Protects an individual sensitive attribute.
- `GLOBAL_ROLE`: Enforces caller global role requirements (e.g., `ADMIN_OVERRIDE`).

### 2.4 Sensitive Sinks (`SensitiveSink`)
Protected data endpoints where unauthorized access leaks confidential information.

- **`SinkKind`:**
  - `PROTECTED_OBJECT_LOOKUP`: Direct lookup of a domain object by ID.
  - `RELATIONSHIP_COLLECTION`: Traversal returning an unconstrained collection of owned resources.
  - `NESTED_OBJECT_ACCESS`: Reading a specific nested object through parent relationship.
  - `SENSITIVE_ATTRIBUTE`: Accessing sensitive data fields (e.g., credentials, financial figures).
- **`SensitivityLevel`:** `HIGH`, `MEDIUM`, `LOW`.

---

## 3. Direct vs. Indirect BOLA Path Semantics

The model establishes explicit semantic rules to distinguish direct from indirect candidates:

| Candidate Classification | Path Depth | Taint Source Input | Boundary Evidence | Risk |
|---|---|---|---|---|
| **`DIRECT_BOLA_CANDIDATE`** | `step_depth == 0` | Untrusted ID argument on root field | `UNVERIFIED_BOUNDARY` or `NO_BOUNDARY_IDENTIFIED` | **HIGH** |
| **`INDIRECT_BOLA_CANDIDATE`** | `step_depth > 0` | Nested argument OR unconstrained collection traversal | `UNVERIFIED_BOUNDARY` or `NO_BOUNDARY_IDENTIFIED` | **HIGH / MEDIUM** |
| **`VERIFIED_PROTECTED_PATH`** | Any | Any | `VERIFIED_BOUNDARY` (`is_verified == True`) | **LOW** |
| **`SAFE_UNPROTECTED_PATH`** | Any | None | Exempt infrastructure node (e.g., `health`) | **LOW** |

### 3.1 Non-Inheritance Rule for Parent Authorization
> [!CAUTION]
> **Parent authorization does not imply child authorization.**  
> If an authenticated caller is verified to own parent entity $A$ (e.g., `user(id: 101)`), the model **never** assumes that traversing a relationship to child collection $B$ (`user.resources`) is authorized. If the relationship edge lacks verified relationship-level boundary evidence, the child step is classified as an **`INDIRECT_BOLA_CANDIDATE`**.

---

## 4. Context-Sensitive Traversal & Cycle Safety

In schemas containing cyclic relationships (e.g., `User -> Post -> User`):
- **Path Distinguishability:** The root user `ctx:query:user` (`step_depth = 0`, `parent_type = Query`) is modeled separately from the author user `ctx:query:user.posts.author` (`step_depth = 2`, `parent_type = Post`).
- **Cycle Prevention:** During path exploration, branch-local visited type sets prevent recursive re-entry of active branches, guaranteeing that cyclic models terminate deterministically.

---

## 5. Concrete Active Schema Example

Applied to the active GraphQL Shield schema:

### 1. Direct Lookup: `Query.resource(id: Int!) -> ResourceType`
- **Source:** `source:Query.resource.id` (`UNTRUSTED_IDENTIFIER`).
- **Context:** `ctx:query:resource` (`step_depth = 0`, `ONE_TO_ONE`).
- **Sink:** `sink:ResourceType` (`PROTECTED_OBJECT_LOOKUP`).
- **Static Status:** Classified as `DIRECT_BOLA_CANDIDATE` under pure static analysis (since instance ownership depends on runtime database checks). When paired with the active gateway pre-execution check at runtime, it resolves to `VERIFIED_PROTECTED_PATH`.

### 2. Indirect Traversal: `Query.user(id: Int!) -> UserType -> resources -> ResourceType`
- **Step 1 (`user`):**
  - Direct candidate for `UserType`.
  - Boundary: Gateway verifies caller `user_id == 101`.
- **Step 2 (`user.resources`):**
  - Context: `ctx:query:user.resources` (`step_depth = 1`, `ONE_TO_MANY`, `is_collection = True`).
  - Argument: None (unparameterized collection).
  - Sink: `sink:UserType.resources` (`RELATIONSHIP_COLLECTION`).
  - Boundary: `NO_BOUNDARY_IDENTIFIED` at relationship level.
  - Finding: **`INDIRECT_BOLA_CANDIDATE`** (Risk: `HIGH`).
  - Uncertainty: *"Parent user authorization does not prove child collection tenant isolation at gateway level."*

### 3. Parameterized Nested Traversal: `Query.user(id: Int!) -> UserType -> resource(id: Int!) -> ResourceType`
- **Step 2 (`user.resource`):**
  - Context: `ctx:query:user.resource` (`step_depth = 1`, `ONE_TO_ONE`, `argument_name = id`).
  - Source: `source:UserType.resource.id` (`UNTRUSTED_IDENTIFIER`).
  - Sink: `sink:ResourceType` (`PROTECTED_OBJECT_LOOKUP`).
  - Runtime Gateway: Enforces `NESTED_AUTHORIZATION_VIOLATION` if `resource.id != caller.id`.
  - Finding: `INDIRECT_BOLA_CANDIDATE` (Static) $\to$ `VERIFIED_PROTECTED_PATH` (with Gateway Policy Evidence).

---

## 6. Programmatic API

```python
from app.security.security_graph import get_security_graph
from app.security.taint_model import TaintAnalysisModel

graph = get_security_graph()
model = TaintAnalysisModel(graph)

# Summary of sources and sinks
print(model.summary())

# Analyze an execution path
findings = model.analyze_path([
    ("user", "UserType"),
    ("resources", "ResourceType"),
])

for finding in findings:
    print(finding.candidate_kind, finding.risk_assessment)
    print(finding.explanation)
    print("Uncertainties:", finding.assumptions_and_uncertainties)
```

---

## 7. Known Assumptions & Limitations

1. **Pre-Execution vs. Resolver Visibility:** The static taint model evaluates schema topology and gateway interception rules. It does not inspect raw resolver SQL strings or ORM query filters unless explicit boundary evidence adapters are provided.
2. **Conservative Candidate Reporting:** Paths lacking static proof are classified as candidates rather than vulnerabilities, preventing false-positive exploit claims.
3. **Field-Level Sensitivity Default:** All domain entity objects (`UserType`, `ResourceType`) and their entity collections are treated as high-sensitivity sinks by default unless explicitly configured otherwise.
