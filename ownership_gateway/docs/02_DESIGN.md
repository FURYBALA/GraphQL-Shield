# 2. Project design

## 2.1 Problem statement

GraphQL APIs expose a typed object graph through a single endpoint. Authorization in GraphQL is normally written
by hand inside each resolver. If **one** resolver, **one** relationship field or **one** search or list field forgets the
ownership check, any authenticated user can read or modify other users' objects. This is Broken Object Level
Authorization (OWASP API1:2023). GraphQL-specific features (aliases, batching, fragments, variables, the `node`
interface and nested traversal) give attackers many paths to the same object, and help them evade simple
URL- or parameter-based defenses. Existing hardening middleware mostly limits query *shape* (depth, cost, aliases)
and does not reason about object *ownership*. Library-level permission frameworks require developers to write
rules for every resolver.

**Problem:** how can BOLA be prevented in GraphQL APIs **at runtime, without modifying the application**,
while staying robust to GraphQL-specific evasion techniques, keeping false positives low and adding little overhead?

## 2.2 Objectives

1. Automatically derive an **ownership model** from the GraphQL schema (introspection).
2. Enforce **object-level authorization** in a gateway, using a **hybrid** of pre-execution checks (for state-changing
   operations) and post-execution response verification (for all returned objects).
3. Handle GraphQL-specific evasion: aliases, batching, fragments, variables, `node(id)`, nested traversal and unscoped lists.
4. Detect **enumeration** behaviour and alert on it.
5. Provide a **dashboard** for visibility (events, violations, alerts, inferred model).
6. **Evaluate** effectiveness, false positives and latency against baselines and an ablation, using a reproducible attack corpus.

## 2.3 Architecture

```
                         ┌───────────────────────────── GraphQLShield gateway (:5000) ─────────────────────────────┐
                         │                                                                                          │
 Client ──HTTP POST────► │ [Auth]──►[Parse & Validate]──►[Limits]──►[Pre-flight Ownership]──►[Query Augmenter]─┐   │
 (Bearer token)          │                                              │  (mutations)                         │   │
                         │                                              ▼                                      ▼   │
                         │                                   Owner look-up (service token,              Forward ────┼──► Backend GraphQL API (:5001)
                         │                                   cached 30 s) ──────────────────────────────────────────┼──►  (unmodified, vulnerable)
                         │                                                                                     │   │
 Client ◄──JSON───────── │ [Strip __gs_*]◄──[Response Verifier / Redactor]◄────────────────────────────────────┘   │
                         │        │                                                                                 │
                         │        ▼                                                                                 │
                         │ [Event Logger: SQLite] ──► [Enumeration Detector] ──► alerts / temporary lock-out        │
                         │        │                                                                                 │
                         │        ▼                                                                                 │
                         │ [Dashboard + Attack Lab + JSON API]                                                      │
                         │                                                                                          │
                         │ [Schema Analyzer] ◄── introspection at startup ── builds Ownership Model + policy.json   │
                         └──────────────────────────────────────────────────────────────────────────────────────────┘
```

### Modules

| # | Module | File | Responsibility |
|---|---|---|---|
| M1 | Schema Analyzer | `gateway/schema_analyzer.py` | Introspection → owned types, owner fields, lookup fields, ID-argument → type map, node field |
| M2 | Request Validator & Limits | `gateway/enforcer.py` (`_handle_one`, `_depth`) | Parse and validate, depth/alias/batch limits, reserved-prefix check |
| M3 | Pre-flight Ownership Checker | `enforcer.py` (`_preflight`, `_lookup_owner`) | Resolves IDs (literals, variables, lists, base64 global IDs), looks up owners, blocks |
| M4 | Query Augmenter + Response Verifier | `enforcer.py` (`_augment*`, `_verify`) | Injects `__typename`/owner/id, walks the response, applies field-aware redaction |
| M5 | Logging, Detection & Store | `enforcer.py` (`_detect_enumeration`), `store.py` | SQLite events and alerts, sliding-window enumeration detector |
| M6 | Dashboard & Attack Lab | `gateway/app.py`, `templates/dashboard.html` | KPIs, side-by-side attack demo, query console, model view, logs, results |
| M7 | Evaluation Framework | `attacks/`, `eval/run_eval.py`, `tests/` | Attack and benign corpus, canary oracle, baseline/ablation runner, tests |
| T | Target app | `backend/app.py` | Vulnerable ClinicHub GraphQL API |

## 2.4 Technology stack (and why)

| Layer | Choice | Reason |
|---|---|---|
| Language | Python 3.11+ | Beginner-friendly, quick to build, fine for a research prototype |
| GraphQL engine | `graphql-core` 3.x | Reference implementation port: parser, validator, `TypeInfo`, introspection, AST printer |
| Web framework | Flask | Minimal; the gateway is about 150 lines |
| HTTP client | `requests` (keep-alive session) | Forwarding to the backend |
| Storage | SQLite (stdlib) | Zero setup; JSON functions for violation statistics |
| Auth | HMAC-SHA256 signed tokens | Same idea as a JWT (HS256), no extra dependency. Say "in production: OIDC/JWT" |
| Dashboard | Vanilla HTML/JS, polling | No build step |
| Testing / eval | pytest, matplotlib | 48 tests, publication charts |

## 2.5 Database design

```sql
requests(id PK, ts, uid, role, mode, operation, query, decision, reason, violations JSON, latency_ms, test_case)
alerts  (id PK, ts, uid, kind, detail)
```

`decision ∈ {allowed, redacted, blocked}`. `violations` is a list of
`{type, id, owner, path, fields, stage: preflight|response}`. Statistics come straight from SQL
(`json_each` gives violations by type).

The target app's data model:

```
User(id, name, role, email, phone) 1 ──< MedicalRecord(id, patientId → User, doctor, diagnosis, prescription)
User 1 ──< Invoice(id, patientId → User, amount, status, recordId → MedicalRecord)
```

## 2.6 Ownership model (output of M1 on ClinicHub, verified by `test_schema_inference`)

| Type | Owner field | Inferred by | Lookup field | Public fields |
|---|---|---|---|---|
| User | `id` | principal type | `user(id)` | id, name, role (policy) |
| MedicalRecord | `patientId` | heuristic | `record(id)` | none |
| Invoice | `patientId` | heuristic | `invoice(id)` | none |

ID-argument mapping: `updateRecord(id)→MedicalRecord` (return type), `payInvoice(invoiceId)→Invoice` (argument name),
`deleteInvoice(id)→Invoice` (field name; it returns only a Boolean). `node(id)` is detected as a Relay node field.

**Inference rules:**
1. A type named in `owner_fields` uses the configured owner field.
2. The principal type (User) is owned by its own `id`.
3. Otherwise, the first field named `ownerId|userId|patientId|customerId|accountId|authorId|createdById` with type `ID` is the owner field.
4. A lookup field is a non-list root Query field with one `ID` argument that returns the type.
5. An ID argument maps to a type through its argument name (`invoiceId`), then the field's return type, then the field name.

## 2.7 Enforcement decision rules

* **Bypass roles** (`admin`, `service`) are allowed. In the paper, call this "role-based override".
* **Pre-flight** (mutations in `shield` mode): for each targeted `(type, id)`, if `owner ≠ caller`, **block** the whole
  operation. If ownership can't be verified (no lookup field) and `fail_closed` is set, block as well.
* **Response verification**: for each returned object of an owned type, if `owner ≠ caller` **and** the requested
  fields include any non-public field, **redact** it (null plus an error with its path). Partial results are kept,
  consistent with GraphQL's error semantics.
* **Enumeration**: if a user causes violations on ≥ 5 distinct foreign objects within 60 s, raise an alert and lock the user out for 30 s (HTTP 429).

## 2.8 Implementation status (for the progress report)

| Component | Status |
|---|---|
| Vulnerable target app (3 types, 7 queries, 3 mutations, node, batching) | ✅ Done |
| M1 Schema analyzer + automatic ownership inference | ✅ Done |
| M2 Validation, depth/alias/batch limits | ✅ Done |
| M3 Pre-flight ownership (literals, variables, lists, global IDs, cache) | ✅ Done |
| M4 Query augmentation + field-aware response verification (aliases, fragments, interfaces) | ✅ Done |
| M5 SQLite logging + enumeration detector + lock-out | ✅ Done |
| M6 Dashboard: KPIs, attack lab, console, model, logs, alerts, results | ✅ Done |
| M7 Attack corpus (14 attacks / 10 categories), benign corpus (14), eval harness, 48 tests | ✅ Done |
| Baselines + ablation experiment with results tables and charts | ✅ Done (single target app) |
| Second/third target app (e.g. DVGA) + inference accuracy on public schemas | ⏳ Planned |
| Shared/relationship-based ownership (doctor ↔ patient, teams) | ⏳ Planned |
| Policy editor in dashboard, Docker Compose, production WSGI server, load test | ⏳ Planned |
| Paper writing | ⏳ Planned |

An honest estimate is **about 75-80% of the planned system implemented**. The remaining work is mostly
generalisation and evaluation breadth, not core functionality.

## 2.9 Roadmap after Review 2

| Week | Work |
|---|---|
| 1 | Shared ownership: an `access_rules` policy such as "a doctor can read records where `record.doctorId == caller`". Add a doctor user and attacks. |
| 2 | Port to a second app (DVGA or a small open-source GraphQL app); re-run the evaluation unchanged to show generality. |
| 3 | RQ4: inference accuracy on 5-10 public GraphQL schemas (hand-label owner fields; report precision and recall). |
| 4 | Load test (e.g. `locust`, 50-200 concurrent users) behind gunicorn; Docker Compose. |
| 5-6 | Paper draft, final report, final demo polish. |
