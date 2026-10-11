# GraphQL Shield: Repository Audit and Baseline Specification

**Phase:** Phase 1 — Repository Audit and Safe Baseline  
**Date:** October 11, 2026  
**Auditor:** Antigravity Agentic Security Engine  
**Project:** GraphQL Shield: Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities  
**Target Long-Term Extension:** Authorization-Aware Context-Sensitive Taint Analysis for Direct and Indirect GraphQL BOLA  

---

## 1. Executive Summary

This document establishes the verified baseline of the **GraphQL Shield** project. Every finding in this audit has been verified directly against source code files, live database state, test suites, and running application processes.

### Key Audit Findings at a Glance
- **Automated Test Suite Status:** **86 passed, 0 failed, 0 skipped** (4.19 seconds runtime, Python 3.14.5).
- **Git State:** Clean baseline checkpoint created at commit `3f86608` on branch `master`. No uncommitted or dangling working tree changes. No unauthorized pushes made.
- **Runtime State:** Verified live via non-destructive HTTP calls to `/health`, `/api/v1/auth/login`, `/graphql`, `/api/v1/dashboard-stats`, and `/api/v1/security/schema-ownership`. All returned expected status codes.
- **Architecture Readiness:** A pre-execution BOLA security gateway with AST query extraction, deterministic risk scoring, database-backed ownership verification, and schema-aware ownership inference is functional.
- **Research Gap:** Currently, BOLA detection relies purely on pre-execution AST argument extraction (`id: ...`) and static ownership lookup. True **context-sensitive taint analysis**, **indirect BOLA propagation**, **authorization security graphs**, and **automated test generation** are absent and represent the future research phases.

---

## 2. Verified System Architecture and Request Flow

The system operates as an edge/gateway layer positioned immediately in front of the Strawberry GraphQL execution engine within a single FastAPI application.

```
Client Request (HTTP POST /graphql + Bearer JWT + Query Body)
      │
      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ FastAPI Router (Route: /graphql)                                       │
│ Dependencies: [bola_enforcement_middleware]                            │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
      ┌──────────────────────────────┴──────────────────────────────┐
      │                                                             │
      ▼                                                             ▼
┌──────────────────────────────┐              ┌──────────────────────────────────┐
│ Step 1: JWT Authentication    │              │ Step 2: Body & AST Ingestion     │
│ (app/core/dependencies.py)   │              │ (app/security/enforcement.py)    │
│ - Validates Bearer token     │              │ - Extracts JSON query & vars     │
│ - 401 on Expired/Invalid     │              │ - Non-POST or empty -> bypass    │
│ - Returns {user_id, role}    │              └─────────────────┬────────────────┘
└──────────────┬───────────────┘                                │
               │                                                │
               └──────────────────────┬─────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Step 3: Query Normalization & Object Extraction                        │
│ (app/security/graphql_parser.py & app/security/object_extractor.py)   │
│ - graphql.parse(query) -> AST                                          │
│ - Resolves OperationDefinition & FragmentDefinition                    │
│ - Recursive AST walk inspecting FieldNode.arguments                    │
│ - Extracts literals & variables ($var) where argument name == "id"     │
│ - Infers ObjectType (field_name.capitalize()) & path (e.g. user.resource)│
│ - Produces normalized object list: [{type, id, path}]                  │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Step 4: Schema-Aware Ownership Inference & DB Resolution               │
│ (app/security/ownership.py & app/security/ownership_inference.py)     │
│ - Resolves type-level rule from cached schema inference model          │
│   (Priority: Explicit Configured > Schema Inferred > Fail Closed)      │
│ - If type is unmodeled -> status: UNKNOWN_OWNERSHIP (owner_id = None)  │
│ - If modeled -> queries SQLite (users or objects table) for owner_id   │
│ - Produces OwnershipResolution(status, source, rule, owner_id)         │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Step 5: Authorization Context Assembly & Policy Engine                 │
│ (app/security/authorization.py)                                        │
│ - Assembles AuthorizationContext(user_id, role, path, owner_id, etc.)  │
│ - Evaluates zero-trust rule sequence:                                  │
│   1. Invalid Context -> DENY (INVALID_CONTEXT)                         │
│   2. UNKNOWN_OWNERSHIP -> DENY (UNKNOWN_OWNERSHIP) [Fail Closed]       │
│   3. owner_id is None -> DENY (OBJECT_NOT_FOUND)                       │
│   4. role == ADMIN -> ALLOW (ADMIN_OVERRIDE)                           │
│   5. user_id == owner_id -> ALLOW (OWNER_MATCH)                        │
│   6. "." in path -> DENY (NESTED_AUTHORIZATION_VIOLATION)               │
│   7. Default -> DENY (OWNERSHIP_MISMATCH)                              │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Step 6: Deterministic Risk Assessment & Audit Logging                  │
│ (app/security/risk_engine.py & app/security/audit.py)                  │
│ - Computes risk score (0-100):                                         │
│   +80 for Mismatch/Nested Violation/Unknown Ownership                  │
│   +20 for Nested Access ("." in path)                                  │
│   +10 for Repeated Denies (audit_logs query in last 10m)               │
│ - Persists event to SQLite audit_logs table                            │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Step 7: Gateway Enforcement Action                                     │
│ - If decision == DENY:                                                 │
│     * Terminal logs live security trace                                │
│     * Raises HTTPException(status_code=403, detail={...})              │
│     * EXECUTION STOPS (Strawberry resolvers NEVER invoked)             │
│ - If decision == ALLOW:                                                │
│     * Passes control to Strawberry GraphQLRouter                       │
│     * Resolvers execute database queries against SQLite                │
│     * Returns HTTP 200 with {"data": {...}}                            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Implementation Inventory

| Component | File Path | Implementation Status | Verification Evidence |
|---|---|---|---|
| **Database Schema & Pooling** | `app/database.py` | Genuine & Complete | Tables `users`, `objects`, `audit_logs` created with foreign keys. Tested in `tests/test_database.py`. |
| **Deterministic Seed Logic** | `app/seed.py` | Genuine & Complete | Seeds Users 101 (Alice), 102 (Bob), 103 (Charlie, Admin); Resources 101, 102, 103, Folders 201, 202, 203. |
| **JWT Token Generation & Verification** | `app/core/security.py` | Genuine & Complete | PyJWT HMAC-SHA256 tokens with user_id, role, and expiration. Tested in `tests/test_auth.py`. |
| **FastAPI Auth Dependencies** | `app/core/dependencies.py` | Genuine & Complete | `HTTPBearer` extracts and verifies JWT; raises HTTP 401 for expired/invalid tokens. |
| **GraphQL Schema & Resolvers** | `app/graphql/types.py`, `app/graphql/queries.py`, `app/graphql/schema.py` | Genuine & Complete | Strawberry GraphQL types (`UserType`, `ResourceType`, `HealthCheckType`). Supports nested `user.resource(id)`. |
| **AST Parser** | `app/security/graphql_parser.py` | Genuine & Complete | Wraps `graphql-core` `parse()`. Handles syntax errors gracefully by returning `None`. |
| **AST Normalizer & Object Extractor** | `app/security/object_extractor.py` | Genuine (with limitations) | Extracts operations, variable values, named fragments, arguments named `id`. Inferred type uses `capitalize()`. |
| **Schema Ownership Inference** | `app/security/ownership_inference.py` | Genuine & Complete | Analyzes Strawberry types at startup. Detects `OWNER_FIELD`, `COLLECTION`, `SELF_OWNERSHIP`. 27 test cases in `tests/test_ownership_inference.py`. |
| **Ownership Resolution** | `app/security/ownership.py` | Genuine & Complete | Priority pipeline: Explicit Configured > Schema Inferred > Fail Closed. Database lookups for `User` and `Resource`. |
| **Policy Engine** | `app/security/authorization.py` | Genuine & Complete | Rule-based evaluation order. Tested in `tests/test_policy_engine.py`. |
| **Risk Scoring Engine** | `app/security/risk_engine.py` | Genuine & Complete | Deterministic 0-100 scoring based on mismatch (+80), path depth (+20), and SQLite recent denies (+10). |
| **Audit Logger** | `app/security/audit.py` | Genuine & Complete | Inserts structured audit rows into SQLite. Handles foreign key edge cases. |
| **Enforcement Middleware** | `app/security/enforcement.py` | Genuine & Complete | FastAPI dependency on `/graphql`. Intercepts request before Strawberry router; raises HTTP 403 on DENY. |
| **Admin Audit Feed API** | `app/main.py` (`/api/v1/audit-logs`) | Genuine & Complete | Requires `role == ADMIN`; returns recent 50 audit entries. |
| **Schema Ownership Inspection API** | `app/main.py` (`/api/v1/security/schema-ownership`) | Genuine & Complete | Requires `role == ADMIN`; returns JSON report of inferred relationships. |
| **Security Dashboard UI** | `app/static/dashboard.html`, `app/main.py` (`/dashboard`, `/api/v1/dashboard-stats`) | Genuine & Complete | Pure HTML/JS dashboard polling `/api/v1/dashboard-stats` every 2 seconds. |
| **Live Interactive Demo Script** | `scripts/live_demo.py` | Genuine & Complete | Interactive CLI menu sending real HTTP requests to the running server. |
| **Automated Regression Demo** | `scripts/run_demo.py` | Genuine & Complete | Deterministic CLI script stepping through Demos 1-4 with enter pauses. |
| **Performance Evaluation Script** | `scripts/evaluate_performance.py` | Genuine & Complete | Fires 2,000 requests against protected `/graphql` vs unprotected `/graphql-insecure`. |

---

## 4. Verification of Specific Security Claims

Each requirement specified in Phase 1 Task 4 was evaluated against the implementation:

### 1. Legitimate Object Access
- **Claim:** Authenticated user requesting their own object is permitted with HTTP 200 and data is returned by Strawberry.
- **Verification:** **VERIFIED.**
- **Code Path:** `user_id == owner_id` triggers Policy 5 `ALLOW (OWNER_MATCH)`. Middleware exits cleanly without exception. Strawberry executes resolver.
- **Test:** `tests/test_phase_10_comprehensive.py::test_05_user_accessing_own_object` and `verify_script.py` step 1.

### 2. Direct Cross-User BOLA
- **Claim:** Authenticated user modifying `id` to reference another user's object is blocked with HTTP 403 before backend execution.
- **Verification:** **VERIFIED.**
- **Code Path:** User 101 requesting Resource 102. `resolve_ownership` returns `owner_id = 102`. `101 != 102` triggers Policy 7 `DENY (OWNERSHIP_MISMATCH)`. `enforcement.py` raises `HTTPException(status_code=403)`. Strawberry is never executed.
- **Test:** `tests/test_phase_10_comprehensive.py::test_06_user_accessing_another_users_object` and `test_09_direct_object_id_manipulation`.

### 3. Nested / Indirect BOLA
- **Claim:** User requesting their own parent object while nesting another user's child object is detected and blocked.
- **Verification:** **PARTIALLY VERIFIED (Strict Limitations Apply).**
- **Code Path:** When Alice (101) submits:
  ```graphql
  query {
    user(id: 101) {
      username
      resource(id: 102) { name }
    }
  }
  ```
  `object_extractor.py` extracts both `user#101` (path `user`) and `resource#102` (path `user.resource`). When evaluating `resource#102`, `101 != 102` and `"." in path` triggers Policy 6 `DENY (NESTED_AUTHORIZATION_VIOLATION)`.
- **Limitation / Defect:** This **only** works because the nested field `resource(id: 102)` explicitly declares an `(id: ...)` argument. If the query traverses a relationship without field arguments (e.g., `user(id: 101) { resources { id name } }`), no nested object is extracted by `object_extractor.py` because `resources` has no `id:` argument. True indirect BOLA (data tainted by parent or retrieved dynamically via relationship resolvers) cannot be tracked.

### 4. Invalid JWT
- **Claim:** Missing, invalid, or expired JWT tokens fail authentication prior to GraphQL execution.
- **Verification:** **VERIFIED.**
- **Code Path:** `get_current_user` executes before `bola_enforcement_middleware`. Missing token -> 403 (HTTPBearer default); invalid/expired token -> 401.
- **Test:** `tests/test_phase_10_comprehensive.py::test_01_valid_jwt` through `test_04_expired_jwt`.

### 5. GraphQL Variables, Aliases, Fragments, and Multiple Selections
- **Variables:** **VERIFIED.** `object_extractor.py` checks `isinstance(arg.value, VariableNode)` and resolves variable names against the request `variables` map.
- **Aliases:** **PARTIALLY VERIFIED.** `FieldNode.name.value` is extracted rather than `node.alias.value`. The target field name is correctly identified, but path tracking records schema field names rather than alias names.
- **Fragments:** **PARTIALLY VERIFIED.** Named fragment spreads (`...FragmentName`) are resolved via a two-pass AST visitor. Inline fragments (`... on TypeName`) are ignored.
- **Multiple Selections:** **VERIFIED.** If a query selects multiple objects (`r1: resource(id: 101), r2: resource(id: 102)`), both are analyzed. Any single DENY immediately raises HTTP 403, blocking the entire request batch.

### 6. Blocking Before Protected Backend Execution
- **Claim:** Unauthorized requests never invoke Strawberry resolvers.
- **Verification:** **VERIFIED.**
- **Code Path:** Enforcement occurs in a FastAPI route dependency. Raising `HTTPException(403)` aborts HTTP request processing at the Starlette routing layer. In `tests/test_phase_10_comprehensive.py::test_18_unauthorized_request_does_not_reach_backend`, the response contains `{"detail": ...}` instead of GraphQL `{"data": ..., "errors": ...}`.

### 7. Audit-Log Persistence
- **Claim:** Both ALLOW and DENY decisions are persisted to SQLite `audit_logs` table.
- **Verification:** **VERIFIED.**
- **Code Path:** `log_decision(...)` is called prior to raising `HTTPException(403)`. Integrity errors on non-existent reconnaissance probe IDs are handled cleanly by temporarily disabling foreign key enforcement for the audit row.
- **Test:** `tests/test_phase_10_comprehensive.py::test_20_denied_request_creates_audit_event` and `test_21_allowed_request_creates_audit_event`.

---

## 5. Test Suite Execution Results

The automated test suite was executed in the active Windows Python 3.14.5 environment:

```powershell
python -m pytest tests/ -v
```

### Exact Results
- **Total Tests Collected:** 86
- **Passed:** 86
- **Failed:** 0
- **Skipped:** 0
- **Warnings:** 171 (Pydantic V2 BaseSettings deprecation, FastAPI `on_event("startup")` deprecation, `datetime.utcnow()` deprecation, and Starlette coroutine inspection warnings)
- **Duration:** 4.19 seconds

### Breakdown by Test Module

| Test Module | Test Count | Scope |
|---|---|---|
| `tests/test_audit.py` | 3 | Audit log creation on ALLOW/DENY; Admin endpoint permissions |
| `tests/test_auth.py` | 6 | Login success/failure, protected route token validation |
| `tests/test_dashboard.py` | 2 | Dashboard HTML serving, dashboard statistics JSON aggregation |
| `tests/test_database.py` | 2 | Table schema creation, foreign key constraints, seed ownership |
| `tests/test_graphql.py` | 3 | Direct User query, direct Resource query, nested folder/children query |
| `tests/test_health.py` | 2 | REST `/health` and GraphQL `health` query |
| `tests/test_nested_authorization.py` | 2 | Nested BOLA block (`user(id: 101) { resource(id: 102) }`) and legitimate nested allow |
| `tests/test_object_extractor.py` | 6 | Direct queries, variable queries, nested queries, fragment queries, invalid queries |
| `tests/test_ownership_inference.py` | 27 | Schema analysis patterns (A, B, C, D), fail-closed behavior, explicit override, caching |
| `tests/test_phase_10_comprehensive.py` | 21 | Full 21-scenario academic test matrix covering auth, authz, BOLA, GraphQL, enforcement, audit |
| `tests/test_policy_engine.py` | 5 | Owner access, non-owner access, admin override, nested resource access, invalid context |
| `tests/test_risk_engine.py` | 3 | Low risk legitimate, high risk BOLA, medium/high risk nested suspicious |
| `tests/test_security_gateway.py` | 4 | Gateway middleware integration tests |
| **Total** | **86** | **All passing** |

---

## 6. Current Technical Limitations & Security Weaknesses

While the current gateway functions reliably for the demonstrated scenarios, several fundamental technical limitations and architectural assumptions must be resolved for advanced research:

### 1. Heuristic Type Extraction via `field_name.capitalize()`
In `app/security/object_extractor.py`:
```python
inferred_type = field_name.capitalize()
```
- **Flaw:** If a GraphQL schema field name differs from the capitalized model name (e.g. `userProfile(id: 101)` -> type `Userprofile`, or `currentProject(id: 202)` -> type `Currentproject`), the gateway attempts to query database table `Currentproject`, fails to find a rule, and either fails closed or misidentifies ownership.
- **Requirement:** Object types must be derived from the **GraphQL schema type system** via schema-aware return-type resolution, not string capitalization.

### 2. Exclusive Dependency on `(id: ...)` Field Arguments
- **Flaw:** The object extractor only identifies objects if the AST `FieldNode` contains an argument named `id`.
- **Vulnerability:** Consider a query such as:
  ```graphql
  query {
    user(id: 101) {
      resources {
        id
        name
      }
    }
  }
  ```
  The child `resources` field takes no argument. The gateway only authorizes `user#101`. If a developer creates a flawed resolver where `user.resources` returns objects across tenant boundaries or exposes unowned items, the gateway has zero visibility into the child collection.
- **Requirement:** Taint analysis and security graph modeling must trace relationship fields even when unparameterized.

### 3. Static Ownership Tables in SQLite
In `app/security/ownership.py`:
```python
if object_type.lower() == "user":
    cursor.execute("SELECT id FROM users WHERE id = ?", (object_id,))
else:
    cursor.execute("SELECT owner_id FROM objects WHERE id = ?", (object_id,))
```
- **Flaw:** Ownership is hard-coded to two database tables (`users` and `objects`). A real enterprise application contains multiple distinct domain tables (`documents`, `orders`, `invoices`, `memberships`).
- **Requirement:** Relationship-based access control (ReBAC) and authorization boundaries must be modeled as graph properties rather than hard-coded SQL queries against a single `objects` table.

### 4. Lack of Dynamic Taint Propagation
- **Flaw:** There is no concept of taint sources, taint tracking, propagation through resolvers, or taint sinks.
- **Requirement:** To detect direct and indirect BOLA, untrusted client inputs (object IDs, parameters, selection paths) must be tracked as **taint sources**, propagated through GraphQL type relationships, checked at **authorization boundaries**, and monitored before reaching sensitive data **sinks**.

### 5. Incomplete GraphQL AST Feature Coverage
- Inline fragments (`... on ResourceType`) are currently skipped.
- Directive processing (`@include(if: ...)`, `@skip(if: ...)`) is unhandled.
- Mutations and Subscriptions are currently unmodeled (gateway assumes operation `query`).

---

## 7. Missing Research Components (Target Extension)

To achieve the stated research objective: **"Authorization-Aware Context-Sensitive Taint Analysis for Direct and Indirect GraphQL BOLA"**, the following theoretical and engineering components are missing and must be developed:

1. **GraphQL Security Graph Model:**
   - Formal graph $G = (V, E)$ where vertices $V$ represent GraphQL Types, Fields, and Context entities (Subject, Role, Tenant).
   - Edges $E$ represent Field Containment, Schema Navigation, Foreign-Key Relationships, and Authorization Boundaries.
2. **Taint Specification Framework:**
   - **Taint Sources:** Client-supplied identifiers, variable substitutions, query parameters.
   - **Taint Propagators:** Field resolvers, collection traversals, nested selections, aliases.
   - **Authorization Boundaries:** Ownership guards, role constraints, tenancy fences, context matchers.
   - **Taint Sinks:** Sensitive object attributes, private fields, cross-tenant data nodes.
3. **Context-Sensitive Taint Transfer Rules:**
   - Formal transfer functions $f: (\tau_{parent}, \text{Context}) \to \tau_{child}$ that compute taint status based on whether an authorization boundary was crossed and verified.
4. **Indirect BOLA Detection Engine:**
   - Ability to detect BOLA when access to Object $B$ is obtained indirectly through legitimate access to Object $A$ via unconstrained relationship navigation.
5. **Automatic BOLA Test Generation:**
   - Automated exploration of the Security Graph to synthesize attack queries targeting direct ID manipulation, nested relationship hopping, and alias smuggling.
6. **Dynamic Verification Engine:**
   - Dual verification combining static query taint analysis with runtime assertion verification.

---

## 8. Recommended Implementation Roadmap for Subsequent Phases

Based on the verified architecture and identified gaps, the recommended implementation plan for subsequent phases is:

```
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Repository Audit & Safe Baseline (COMPLETED)                 │
│ - Verified architecture, tests (86/86 pass), limitations documented.   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: GraphQL Security Graph Construction                           │
│ - Parse Strawberry schema into formal Security Graph (Types, Fields).  │
│ - Map relationships (1-to-1, 1-to-many, self-references).             │
│ - Annotate nodes with schema return types (eliminating .capitalize()). │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 3: Taint Model & Boundary Semantics Specification                │
│ - Formalize Taint Sources (IDs, arguments, variables).                 │
│ - Define Authorization Boundaries (Ownership, Role, Relationship).    │
│ - Formalize Taint Sinks (sensitive fields, unauthorized nodes).        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: Context-Sensitive Taint Analysis Engine                       │
│ - Implement AST taint propagation algorithm.                           │
│ - Track taint state across nested paths, collections, and aliases.     │
│ - Detect indirect BOLA via untrusted relationship navigation.          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 5: Gateway Integration & Dual-Mode Runtime Enforcement           │
│ - Integrate Taint Analysis Engine into bola_enforcement_middleware.    │
│ - Fallback safely to existing policy engine for backward compatibility.│
│ - Update live trace, risk engine, and audit logging with taint metrics.│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 6: Automated BOLA Test Query Generator                           │
│ - Graph-driven generator synthesizing test queries from schema graph.  │
│ - Generates direct BOLA, indirect relationship hops, and alias tests.  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 7: Verification, Evaluation & Academic Reporting                 │
│ - Run full regression suite + new taint analysis test suite.           │
│ - Benchmark latency overhead and detection rate (direct vs indirect).  │
│ - Update documentation, guides, and final research artifacts.          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Baseline Checkpoint Verification

- **Git Commit Checkpoint:** `3f86608` (`checkpoint: baseline state before Phase 1 repository audit`)
- **Remote Synchronization:** Not pushed (adhering strictly to rule: *"Do not push to GitHub without my explicit approval"*).
- **Working Tree:** Intact, clean, and preserved.
- **Database File:** `shield.db` preserved intact without data loss.

---
*End of Project Audit Report.*
