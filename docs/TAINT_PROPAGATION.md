# AST-Driven Context-Sensitive Taint Propagation Engine Specification

**Phase:** Phase 4 — AST-Driven Context-Sensitive Taint Propagation Engine  
**Module:** `app/security/taint_engine.py`  
**CLI Tool:** `scripts/analyze_query_taint.py`  
**Research Target:** Authorization-Aware Context-Sensitive Taint Analysis for Direct and Indirect GraphQL BOLA  

---

## 1. Engine Architecture & Algorithm

The **Taint Propagation Engine** analyzes incoming GraphQL queries against the Phase 2 Security Graph $G = (V, E)$ and Phase 3 Taint Model. It tracks how untrusted client inputs propagate through GraphQL query selection trees and evaluates whether authorization boundaries adequately protect sensitive data sinks.

```
                      ┌────────────────────────────────────────┐
                      │   Incoming GraphQL Query + Variables   │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │   graphql-core AST Parsing & Normalizer │
                      │   - Named & Anonymous Operations       │
                      │   - Variables & Literals               │
                      │   - Aliases & Fragments                │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │ Context-Sensitive AST Walker           │
                      │ For each selection:                    │
                      │  1. Resolve canonical schema field     │
                      │  2. Resolve client response path       │
                      │  3. Map argument -> TaintSource        │
                      │  4. Propagate taint tags along edge    │
                      │  5. Check target -> SensitiveSink      │
                      │  6. Evaluate Boundary Evidence         │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │  Query Analysis Report                 │
                      │  - Direct BOLA Candidates              │
                      │  - Indirect BOLA Candidates            │
                      │  - Verified Protected Paths            │
                      │  - Safe Unprotected Paths              │
                      │  - Explicit Assumptions & Uncertainties│
                      └────────────────────────────────────────┘
```

---

## 2. Traversal & Propagation Rules

### Rule 1: Structural Return-Type Resolution
- For every `FieldNode` visited, the engine resolves the target type using `SecurityGraph.resolve_field_return_type(parent_type, field_name)`.
- It completely eliminates naming heuristics (`field_name.capitalize()`), using authoritative schema types (`ResourceType`, `UserType`).

### Rule 2: Dual Path Tracking (Schema Path vs. Response Path)
- **`schema_path`:** Canonical dot-separated schema field path (e.g. `user.resources`).
- **`response_path`:** Preserves client response field aliases (e.g. `myUser.myResources`).
- Taint analysis and policy matching always bind to `schema_path`, preventing alias evasion attacks.

### Rule 3: Input Taint Binding
- Variables and literals passed to arguments are inspected.
- An input is tagged with `UNTRUSTED_IDENTIFIER` **only** if the target argument matches candidate identifier heuristics (`id`, `*_id`, `pk`). Non-identifier variables are tagged as `UNTRUSTED_PARAMETER` and do not generate false BOLA candidates.

### Rule 4: Non-Inheritance of Parent Authorization
- Authorization on a parent entity ($A$) does **not** grant authorization to child entity collection ($B$).
- If a query traverses from `user(id: 101)` to `resources`, the child collection step is evaluated independently. If no relationship boundary guards the child collection, it is recorded as an `INDIRECT_BOLA_CANDIDATE`.

### Rule 5: Cycle Safety & Recursion Bounding
- Branch-local visited type sets track type recursion (`User -> Post -> User`).
- Traversal depth is strictly capped at `max_traversal_depth` (default 8). If cyclic types are visited, they are analyzed with distinct depth contexts (`step_depth = 0` vs `step_depth = 2`), preventing infinite recursion.

---

## 3. Supported GraphQL Syntactic Features

| Syntax Feature | Handling Mechanism |
|---|---|
| **Named / Anonymous Operations** | `OperationDefinitionNode.name.value` extracted; operation type mapped to root type (`Query` / `Mutation`). |
| **Variables & Values** | `VariableNode` resolved against runtime `variables` dictionary; literal nodes unwrapped to Python primitives. |
| **Field Aliases** | `FieldNode.alias.value` tracked in `response_path`; canonical field name tracked in `schema_path`. |
| **Named Fragment Spreads** | Two-pass collection of `FragmentDefinitionNode`; inlined recursively with a fragment stack preventing circular fragment loops. |
| **Inline Fragments** | `InlineFragmentNode.type_condition` resolves target concrete types; selection sets evaluated in concrete type context. |
| **Multi-Root Selections** | Multi-root selections (`{ r1: resource(id: 101), r2: resource(id: 102) }`) analyzed as independent parallel propagation branches. |
| **Public / Non-Sensitive Fields** | Infrastructure queries (`health { status }`) mapped to `SAFE_UNPROTECTED_PATH` without producing spurious BOLA warnings. |

---

## 4. Complexity & Performance Considerations

- **AST Parsing Overhead:** $O(N)$ where $N$ is the number of tokens in the query string.
- **Traversal Complexity:** $O(F)$ where $F$ is the number of field selections in the query document. Lookups in `SecurityGraph` and `TaintAnalysisModel` use $O(1)$ hash maps.
- **Memory Footprint:** Ephemeral memory during AST traversal; produces lightweight JSON-serializable dataclasses without external caching or database overhead.

---

## 5. Concrete Analysis Examples

### Example 1: Direct BOLA Candidate with Variables & Aliases
```graphql
query GetResource($resId: Int!) {
  myResource: resource(id: $resId) {
    name
  }
}
```
**Analysis Finding:**
- `Candidate Kind`: `DIRECT_BOLA_CANDIDATE`
- `Schema Path`: `resource`
- `Response Path`: `myResource`
- `Taint Source`: `$resId` $\to$ `Query.resource.id` (`UNTRUSTED_IDENTIFIER`)
- `Sink`: `sink:ResourceType` (`PROTECTED_OBJECT_LOOKUP`)
- `Boundary`: `UNVERIFIED_BOUNDARY` (static analysis requires runtime ownership verification)
- `Risk`: `HIGH`

### Example 2: Indirect BOLA Candidate via Unconstrained Collection
```graphql
query GetUserNotes {
  user(id: 101) {
    username
    resources {
      id
      name
    }
  }
}
```
**Analysis Findings:**
1. Step 1 (`user`): `DIRECT_BOLA_CANDIDATE` for `UserType`.
2. Step 2 (`user.resources`): `INDIRECT_BOLA_CANDIDATE` for `ResourceType` collection.
   - `Boundary`: `NO_BOUNDARY_IDENTIFIED` at relationship level.
   - `Uncertainty`: *"Collection navigation has no field-level identifier argument; parent object authorization does not prove child collection ownership."*

### Example 3: Public Infrastructure Query
```graphql
query CheckHealth {
  health {
    status
    message
  }
}
```
**Analysis Finding:**
- `Candidate Kind`: `SAFE_UNPROTECTED_PATH`
- `Risk`: `LOW`
- Zero false-positive BOLA candidates produced.

---

## 6. Programmatic & CLI Interfaces

### Programmatic Python API
```python
from app.security.taint_engine import analyze_query_taint

report = analyze_query_taint(
    query="query { user(id: 101) { resources { name } } }",
    variables={},
)

print(report.summary())
for finding in report.direct_bola_candidates:
    print("Direct Candidate:", finding.propagation_context.field_path)
for finding in report.indirect_bola_candidates:
    print("Indirect Candidate:", finding.propagation_context.field_path)
```

### CLI Analysis Tool
```powershell
python scripts/analyze_query_taint.py --query "query { resource(id: 102) { name } }"
```
Or with custom variables and JSON report export:
```powershell
python scripts/analyze_query_taint.py --file path/to/query.graphql --variables '{"id": 102}' --output report.json
```

---

## 7. Operational Status in Phase 4

- **Offline / Non-Blocking Analysis:** In Phase 4, the analyzer runs as an independent inspection and diagnostic engine. It does **not** alter live HTTP 200/403 decisions or intercept production traffic yet.
- **Safety Invariant:** Live gateway behavior and test suites remain 100% backward-compatible, ready for runtime enforcement integration in Phase 5.
