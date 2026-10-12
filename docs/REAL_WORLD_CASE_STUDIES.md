# Real-World Security Case Studies: GraphQL BOLA, Incident Reproduction, and Practical Applications

**Course Context:** Computer and Communication Network Security (CCNS)  
**Research Topic:** Correlating AST-Based GraphQL Path Analysis with Runtime Authorization Evidence for Explainable BOLA Auditing  
**Security Baseline:** OWASP API Security Top 10 (API1:2023 — Broken Object-Level Authorization)  
**Primary Incident Reference:** GitHub Security Advisory GHSA-m5pg-r4jp-qq75 / CVE-2026-28217 (Hoppscotch GraphQL Collection IDOR)  
**Document Status:** Complete & Evaluated against Local Test Harness  

---

## 1. Executive Summary

Broken Object-Level Authorization (BOLA), also cataloged as Insecure Direct Object References (IDOR), is consistently identified by industry authorities (including OWASP API Security Top 10: API1:2023) as the single most prevalent and high-impact vulnerability across modern API architectures. While BOLA vulnerabilities in traditional REST APIs typically expose isolated endpoints (`GET /api/documents/102`), in **GraphQL architectures** they become significantly more complex to audit and attribute. GraphQL allows client-driven query documents with nested selections, field aliasing, fragment indirection, and cyclic graph traversals.

This document provides a research-grade analysis of real-world GraphQL BOLA vulnerabilities, centered on **GitHub Security Advisory GHSA-m5pg-r4jp-qq75 (CVE-2026-28217)**, a publicly disclosed IDOR in Hoppscotch's GraphQL API (versions $\le$ 2026.1.1, patched in 2026.2.0). 

We strictly distinguish:
1. **Facts from the Real Incident:** The vulnerability discovered in the official Hoppscotch backend (`hoppscotch-backend`).
2. **Behavior of the Local Implementation:** A controlled, Hoppscotch-inspired local reproduction of the vulnerability pattern modeled within our gateway using the project's existing `Resource` / `User` schema.
3. **Proposed Extensions:** Future enhancements such as mutation authorization and automated dynamic graph fuzzing.

> [!IMPORTANT]
> **Academic Rigor Disclaimer:** We did **NOT** test against the production Hoppscotch server or execute unauthorized probes against third-party infrastructure. Rather, we constructed an isolated, controlled local reproduction of the `GHSA-m5pg-r4jp-qq75` vulnerability pattern using our existing `Resource` and `User` domain entities, evaluating how our pre-execution gateway policy engine and AST taint analysis intercept and explain this specific vulnerability pattern.

---

## 2. Why BOLA Matters in GraphQL and Multi-Tenant Applications

In multi-tenant SaaS environments, multiple independent organizations, teams, and individuals share the same compute and database infrastructure. Tenant isolation relies on strict, authorization-boundary enforcement at every object and field access point.

In GraphQL, authorization enforcement is uniquely challenging for four structural reasons:

1. **Client-Controlled Selection Sets:** Unlike REST where the server defines the response structure, GraphQL clients construct their own query shapes. An attacker can request deeply nested relational entities that developers forgot to protect at the resolver level.
2. **Field Aliasing:** Attackers can alias fields (`stolenDoc: resource(id: 102)` or `targetUser: user(id: 102)`), defeating naive regex or string-matching API firewalls that look for standard query keywords.
3. **Fragment Indirection:** Named and inline fragment spreads decompose queries across multiple selection trees, obscuring the source-to-sink data flow.
4. **Relational Collection Traversals:** Even if root query fields are protected, unconstrained navigation through one-to-many relationship fields (e.g., `user(id: 101) { resources { id name } }` or `user(id: 102) { resources { id name } }`) can bypass object-level authorization if child resolvers do not re-verify tenant ownership.

When BOLA occurs in a GraphQL API, an authenticated attacker with standard low-privilege credentials can access arbitrary cross-tenant data across the entire object graph.

---

## 3. Hoppscotch Incident Summary (Official Advisory Facts)

The following facts are verified against the official GitHub Security Advisory published by the Hoppscotch team:

### Incident Metadata
- **Advisory ID:** GHSA-m5pg-r4jp-qq75
- **CVE ID:** CVE-2026-28217
- **Advisory Title:** IDOR in GraphQL userCollection Query Exposes Other Users' Private Collections
- **Product / Package:** `hoppscotch-backend` (Self-Hosted Docker Image)
- **Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Broken Object-Level Authorization (BOLA)
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **Severity:** Moderate (CVSS 3.1 Base Score: 6.5)
- **CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
  - Attack Vector: Network (`AV:N`)
  - Attack Complexity: Low (`AC:L`)
  - Privileges Required: Low (`PR:L`) — requires valid authenticated user JWT
  - User Interaction: None (`UI:N`)
  - Scope: Unchanged (`S:U`)
  - Confidentiality: High (`C:H`) — collection data contains serialized HTTP headers and credentials
  - Integrity: None (`I:N`) — read-only query
  - Availability: None (`A:N`)
- **Affected Query:** `userCollection(userCollectionID: ID!)`
- **Affected Versions:** `<= 2026.1.1`
- **Patched Version:** `2026.2.0`
- **Reporter Credit:** `bugbunny-research` (reported via bugbunny.ai)
- **Official Advisory URL:** [https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-m5pg-r4jp-qq75](https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-m5pg-r4jp-qq75)
- **Publication Date:** February 26, 2026

### Vulnerable Source Code in Hoppscotch
In Hoppscotch backend (`packages/hoppscotch-backend/src/user-collection/user-collection.resolver.ts`, lines 130–153):
```typescript
@Query(() => UserCollection, {
  description: 'Get user collection with ID',
})
@UseGuards(GqlAuthGuard)
async userCollection(
  @Args({
    type: () => ID,
    name: 'userCollectionID',
    description: 'ID of the user collection',
  })
  userCollectionID: string,
  // NOTE: Missing @GqlUser() decorator — caller's identity was never injected
) {
  const userCollection =
    await this.userCollectionService.getUserCollection(userCollectionID);

  if (E.isLeft(userCollection)) throwErr(userCollection.left);
  return <UserCollection>{
    ...userCollection.right,
    userID: userCollection.right.userUid,  // Leaked victim user UID
    data: !userCollection.right.data
      ? null
      : JSON.stringify(userCollection.right.data),  // Leaked serialized requests & auth tokens
  };
}
```
And in `packages/hoppscotch-backend/src/user-collection/user-collection.service.ts` (lines 178–187):
```typescript
async getUserCollection(collectionID: string, tx: Prisma.TransactionClient | null = null) {
  try {
    const userCollection = await (tx || this.prisma).userCollection.findUniqueOrThrow(
      { where: { id: collectionID } },
    );
    return E.right(userCollection);
  } catch (error) {
    return E.left(USER_COLL_NOT_FOUND);
  }
}
```

### Inconsistent Authorization in Hoppscotch Codebase
Every other operation in `user-collection.service.ts` enforced caller ownership:
- `renameUserCollection` (line 365): called `isOwnerCheck(userCollectionID, userID)`
- `deleteUserCollection` (line 398): checked `collection.right.userUid !== userID`
- `moveUserCollection` (line 584): checked `collection.right.userUid !== userID`
- `updateUserCollectionOrder` (line 705): checked `collection.right.userUid !== userID`
- `updateUserCollection` (line 1203): called `isOwnerCheck(userCollectionID, userID)`
- `duplicateUserCollection` (line 1242): checked `collection.right.userUid !== userID`
The `userCollection` query was the **sole** endpoint in that resolver omitting caller ownership verification.

---

## 4. Official Remediation vs. Gateway Defense

### Official Remediation Options (from Advisory)
1. **Option 1 (Resolver Check — Preferred by Maintainers):** Inject `@GqlUser() user: AuthUser` in `userCollection` query resolver and assert `if (userCollection.right.userUid !== user.uid) throwErr(USER_NOT_OWNER)`.
2. **Option 2 (Service Layer Filtering):** Modify `getUserCollection(collectionID, userID)` to require caller UID and enforce `where: { id: collectionID, userUid: userID }`.

### Gateway-Mediated Defense (Our Research Focus)
While in-code developer fixes are essential, our research investigates **how an API gateway can detect and explain such vulnerabilities before they reach vulnerable resolvers**:
- **Pre-Execution ID Extraction:** The gateway parses the incoming GraphQL AST, identifies object identifiers (`userCollectionID` / `id`), and queries the database ownership mapping before resolver invocation.
- **Context-Sensitive Taint Tracking:** The AST taint propagation engine tracks the untrusted argument as it flows into the sensitive object sink.
- **Audit Correlation:** When the runtime policy engine denies or allows access, the correlation engine links the AST path to runtime evidence, generating an explainable audit record without changing production gateway outcomes.

---

## 5. Architectural Root Causes of GraphQL BOLA

1. **Authentication vs. Authorization Conflation:** Endpoints are protected by authentication guards (e.g., valid JWT required), but developers neglect **object-level authorization** (verifying that `caller.id == entity.owner_id`).
2. **Missing Pre-Execution Interception:** The GraphQL server executes resolvers independently. If a single field resolver lacks a check, data leaks.
3. **Primary-Key Fetch Without Tenant Predicate:** Executing `findUnique({ where: { id } })` instead of scoped queries `findFirst({ where: { id, userUid } })`.

---

## 6. Confidentiality Impact and Nested Relationship Risks

The confidentiality impact of collection IDOR in API platforms is severe:
- **Credential & Secret Exposure:** API request collections store authorization headers (Bearer tokens, Basic Auth credentials, API keys) embedded in saved request definitions.
- **Internal Infrastructure Discovery:** Private endpoint URLs, staging routes, and internal microservice names are disclosed.
- **Hierarchical Tree Traversal:** As noted in the advisory, related field resolvers (`parent`, `childrenREST`, and `childrenGQL`) lacked ownership filters, allowing attackers who obtained one collection ID to traverse the victim's entire workspace tree.

---

## 7. Mapping of Incident Characteristics to GraphQL Shield Components

| Hoppscotch Incident Characteristic | GraphQL Shield Implementation Component | Function / Class |
| :--- | :--- | :--- |
| **Client-supplied ID Argument** | Phase 3 Taint Source Model | `TaintSource` (`TaintTag.UNTRUSTED_IDENTIFIER`, arg `id` / `$colId`) |
| **Sensitive Collection Sink** | Phase 3 Sensitive Sink Discovery | `SensitiveSink` (`SinkKind.PROTECTED_OBJECT_LOOKUP`, target `ResourceType`) |
| **AST Traversal & Alias Indirection** | Phase 4 Context-Sensitive Taint Engine | `TaintPropagationEngine.analyze_document()` tracking dual `schema_path` & `response_path` |
| **Object Ownership Resolution** | Phase 1 & 2 Ownership Pipeline | `resolve_ownership(obj_type, obj_id)` checking SQLite `objects.owner_id` |
| **Zero-Trust Policy Enforcement** | Gateway Policy Engine | `PolicyEngine.evaluate()` enforcing `OWNER_MATCH` rule |
| **Audit-Only Observability** | Phase 5/7 Correlation Engine | `correlate_path_decision()` classifying `TRUE_POSITIVE_BLOCKED` vs `RUNTIME_PROTECTED_ALLOWED` |
| **Real-Time SOC Visibility** | Security Dashboard & Lab | `/dashboard` and `/api/v1/security/scenario-lab` |

---

## 8. Hoppscotch-Inspired Local Reproduction of the Vulnerability Pattern

### 8.1 Local Simulation Setup
To ensure safety, repeatability, and ethical boundaries, the incident is modeled locally using our project's existing `User` and `Resource` domain schema:
- **Simulated Attacker:** Alice (`user_id = 101`, `role = 'user'`)
- **Collection Owner:** Bob (`user_id = 102`, `role = 'user'`)
- **Target Resource:** Resource ID `102` (`Bob's Financial Record`, representing Bob's private collection)
- **Local Endpoint:** `POST http://127.0.0.1:8000/graphql`

### 8.2 Execution Trace & Actual Outputs
When Alice executes the attack query:
```graphql
query GetCollection($colId: Int!) {
  resource(id: $colId) {
    id
    name
    objectType
  }
}
```
with variables `{"colId": 102}`:

1. **Gateway Interception:**
   - Pre-execution object extractor normalizes AST and extracts `(object_type='Resource', object_id=102, path='resource')`.
   - `resolve_ownership("Resource", 102)` queries SQLite and discovers `owner_id = 102`.
   - `PolicyEngine` evaluates `caller(101)` vs `owner(102)`:
     - Decision: **`DENY`**
     - Reason: **`OWNERSHIP_MISMATCH`**
     - Risk Score: **`90 / 100 (HIGH)`**
   - HTTP Response: **`HTTP 403 Forbidden`** (Request dropped pre-execution; resolver never touches data).

2. **AST-Driven Taint Intelligence:**
   - Identifies taint source: Variable `$colId` / field argument `id`.
   - Attributed Schema Path: `resource`
   - Attributed Response Path: `resource`
   - Candidate Kind: `DIRECT_BOLA_CANDIDATE`
   - Sensitive Sink: `ResourceType` (Sensitivity: HIGH).

3. **Dynamic Correlation Outcome:**
   - Static finding bound to runtime denial $\to$ Status: **`TRUE_POSITIVE_BLOCKED`**.
   - Rationale: *"Static candidate DIRECT_BOLA_CANDIDATE flagged untrusted path; runtime policy confirmed authorization failure (OWNERSHIP_MISMATCH) and blocked."*
   - Authorization boundary: **Program-Verified** via live JWT caller binding and SQLite database lookup.

### 8.3 Legitimate Owner Contrast (False-Alarm Elimination)
When Bob executes the exact same query with `$colId = 102`:
- PolicyEngine verifies `caller(102) == owner(102)` $\to$ **`ALLOW (OWNER_MATCH)`**.
- Gateway returns **`HTTP 200 OK`** with collection data.
- Correlation status: **`RUNTIME_PROTECTED_ALLOWED`**.
- Eliminates false alarms: On our benchmark's isolated static-taint baseline (Method 2), static analysis alone yielded an **81.1% false-alarm rate (43/53)** because it flagged every tainted argument reaching a sink without knowing caller identity. Correlated defense reduces this false alarm rate to **0.0% (0/53)** on the evaluated benign cases.

---

## 9. Related Practical Use Cases

In addition to the Hoppscotch collection IDOR pattern, GraphQL Shield supports three practical SaaS use cases:

### Use Case 1: Multi-Tenant SaaS Document Management
- **Scenario:** SaaS platform where tenants maintain confidential documents and hierarchical project folders.
- **Attack:** Cross-tenant document theft (`stolenDoc: resource(id: 102)`).
- **Enforcement:** Gateway blocks access with `HTTP 403`, while AST taint analysis normalizes client alias `stolenDoc` back to canonical schema field `resource`.
- **Nested Verification:** Folder traversal (`resource(id: 201) { children { id name } }`) permits Alice to view her own nested files (IDs 202, 203) without false alarms.

### Use Case 2: Team Workspace Nested Collections & Aliases
- **Scenario:** Private workspace collections with parent-child relationships.
- **Attack:** Alice targets Bob's user node and attempts nested relational collection traversal:
  ```graphql
  query {
    targetUser: user(id: 102) {
      userDocs: resources { id name }
    }
  }
  ```
- **Enforcement:** Gateway blocks request pre-execution. AST taint engine extracts both root finding (`user`, alias `targetUser`) and nested relationship collection sink (`user.resources`, alias `targetUser.userDocs`, type `UserType.resources`).

### Use Case 3: Project / Issue-Tracking Resources (Authorization Layer Separation)
Demonstrates formal separation across three distinct authorization layers:
1. **Authentication Boundary:** Verifies caller identity (`who makes the request`). Unauthenticated requests are terminated at the HTTPBearer layer (`HTTP 403` / `401`).
2. **Object-Level Authorization (BOLA Defense):** Verifies whether the authenticated principal has rights to the target entity (`caller.id == target.owner_id`).
3. **Relationship Authorization:** Verifies whether the principal may traverse from a permitted parent object to related child entities.

---

## 10. Limitations: Controlled Local Reproduction vs. Production Deployment

1. **Schema Scope:** Our reproduction maps Hoppscotch's collection concepts to our typed `ResourceType` and `UserType` domain entities in SQLite. It does not run Hoppscotch's full multi-container Prisma/PostgreSQL stack.
2. **Mutation Operations:** The current gateway enforcement layer strictly validates GraphQL `query` operations. Mutation authorization (e.g., `updateUserCollection`, `deleteUserCollection`) is not active in this prototype and is documented as a future extension.
3. **Audit-Only Observability:** Taint analysis operates in audit-only mode to measure explainability and latency without altering live gateway decisions.

---

## 11. References

1. **Hoppscotch Security Advisory (GHSA-m5pg-r4jp-qq75 / CVE-2026-28217):**  
   GitHub Security Lab & Hoppscotch Team, *"IDOR in GraphQL userCollection Query Exposes Other Users' Private Collections,"* February 26, 2026.  
   URL: [https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-m5pg-r4jp-qq75](https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-m5pg-r4jp-qq75).

2. **OWASP API Security Top 10 (2023 Edition):**  
   OWASP Foundation, *"API1:2023 — Broken Object-Level Authorization,"* 2023.  
   URL: [https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

3. **Academic Literature on Graph API Taint Analysis:**  
   Leen Lambers, Lucas Sakizloglou, Taisiya Khakharova, Fernando Orejas, *"Taint Analysis for Graph APIs Focusing on Broken Access Control,"* Logical Methods in Computer Science (LMCS), Volume 22, Issue 1, March 10, 2026.  
   DOI: [10.46298/lmcs-22(1:18)2026](https://doi.org/10.46298/lmcs-22(1:18)2026). URL: [https://lmcs.episciences.org/17696](https://lmcs.episciences.org/17696).

4. **MITRE Common Weakness Enumeration:**  
   MITRE Corporation, *"CWE-639: Authorization Bypass Through User-Controlled Key,"* 2024.  
   URL: [https://cwe.mitre.org/data/definitions/639.html](https://cwe.mitre.org/data/definitions/639.html).
