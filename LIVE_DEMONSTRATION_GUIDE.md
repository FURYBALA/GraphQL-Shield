# GraphQL Shield: Live Interactive Demonstration

This guide provides the exact `curl` commands to manually demonstrate the BOLA Security Gateway. 
By typing these commands into your terminal, you will send real HTTP traffic to the FastAPI server. 

Because we added **Live Console Logging**, the server's terminal will print a complete Security Trace (AUTH, GRAPHQL, OWNERSHIP, AUTHORIZATION, ENFORCEMENT) for every request you make!

---

### Step 0: Start the Server

Open your first terminal and start the server:
```bash
python -m app.seed
uvicorn app.main:app --reload
```
*(Leave this terminal visible on your screen. The security trace logs will print here.)*

---

### Step 1: Authenticate as User 101

Open a second terminal. We need to log in as Alice (User 101) to get a JWT token.

**Run:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
-H "Content-Type: application/json" \
-d "{\"username\":\"alice\",\"password\":\"alice123\"}"
```
**Expected:** The server will return a JSON object with your `access_token`. Copy this token. We will use it in the next steps (replace `<YOUR_TOKEN>` below).

---

### Demo 1: Legitimate Resource Request

Alice legitimately requests her own Resource (Object ID: 101).

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 101) { id name } }\"}"
```
**Look at the Server Terminal:** You will see the Live Security Trace showing `Decision: ALLOW`. The backend executes and returns HTTP 200 with Alice's data.

---

### Demo 2: Direct BOLA Attack

Now, explain to your evaluator that you are keeping the *same user token*, but manually changing the requested object ID from `101` to `102` (which belongs to Bob).

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 102) { id name } }\"}"
```
**Look at the Server Terminal:** You will see:
- `Requesting User: 101`
- `True Owner ID: 102`
- `Decision: DENY`
- `Reason: OWNERSHIP_MISMATCH`
- `Enforcement: HTTP 403 Forbidden`

---

### Demo 3: Nested BOLA Attack

Attackers often hide BOLA attempts inside nested fields. Alice requests her own user profile, but nests a request for Bob's resource underneath it.

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ user(id: 101) { username resource(id: 102) { name } } }\"}"
```
**Look at the Server Terminal:** The parser recursively extracts the nested `Resource (102)`, evaluates it against Alice's identity, blocks it with `NESTED_AUTHORIZATION_VIOLATION`, and returns HTTP 403.

---

### Demo 4: Invalid / Expired JWT

Finally, demonstrate edge protection by using a forged or expired token.

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer fake_forged_token_here" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 101) { id name } }\"}"
```
**Expected:** The request is instantly rejected with HTTP 401 Unauthorized before it even reaches the GraphQL Gateway.

---

### Demo 5: Schema-Aware Ownership Inference

This demo proves that the gateway is **not** only following hard-coded rules: it understands ownership *from the GraphQL schema itself*.

**Step 5.1 — Show the GraphQL schema**

Open `app/graphql/types.py` (or introspect the live API):

```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ __schema { types { name fields { name type { name kind ofType { name } } } } } }\"}"
```

Point at the two relationships that matter:

```graphql
type User     { id: ID!, resources: [Resource] }   # User -> resources -> Resource
type Resource { id: ID!, owner_id: ID! }           # Resource.ownerId -> User
```

**Step 5.2 — Show what the gateway inferred from that schema**

On application startup the server already printed the analysis:

```
[Schema Ownership Inference]
  ResourceType.owner_id -> UserType  [HIGH]
  UserType.resources -> ResourceType  [MEDIUM]
  UserType.id -> UserType  [HIGH]
Types analyzed: 3
Ownership relationships detected: 3
```

Now inspect it live through the ADMIN endpoint (login as Charlie first):

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
-H "Content-Type: application/json" \
-d "{\"username\":\"charlie\",\"password\":\"charlie123\"}"

curl "http://localhost:8000/api/v1/security/schema-ownership" \
-H "Authorization: Bearer <ADMIN_TOKEN>"
```

**Expected:** JSON describing the real analysis, e.g.

```json
{
  "status": "analyzed",
  "types_analyzed": 3,
  "relationships_detected": 3,
  "high_confidence_rules": 2,
  "ambiguous_relationships": 0,
  "rules": [
    {"source_type": "ResourceType", "source_field": "owner_id",
     "target_type": "UserType", "confidence": "HIGH",
     "reason": "Field 'owner_id' on ResourceType is a scalar ownership identifier referencing UserType"}
  ],
  "priority": ["1. Explicit configured authorization / ownership rule", "..."]
}
```

*(This is live output from the real schema — nothing in this response is hardcoded.)*

You can also generate the standalone inference report for your slides:

```bash
python scripts/generate_inference_report.py
```

It writes `ownership_inference_report.json` with the types analyzed, the accepted rules (confidence + reason), the rejected/ambiguous relationships and the summary counts — all recomputed from the real schema on every run.

**Step 5.3 — Authenticate as User 101**

Use the Alice token from Step 1 (`alice` / `alice123`).

**Step 5.4 — Request Alice's own Resource 101**

```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 101) { id name } }\"}"
```
**Expected:** HTTP 200. In the server terminal, read the `[OWNERSHIP]` block:

```
Requesting User: 101
True Owner ID:   101
Resolution:      RESOLVED (EXPLICIT_DB)
Schema Rule:     ResourceType.owner_id -> UserType [HIGH] (INFERRED)
[AUTHORIZATION] Decision: ALLOW  Reason: OWNER_MATCH
```

**Step 5.5 — Change only the resource ID to 102**

```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 102) { id name } }\"}"
```
**Expected:** HTTP 403, `reason: OWNERSHIP_MISMATCH`, `risk_level: HIGH`.

**Step 5.6 — Explain the decision**

The gateway resolves ownership through a fixed priority order:

1. explicit configured rule + authoritative database ownership lookup,
2. validated schema-inferred rule (`ResourceType.owner_id -> UserType`),
3. otherwise `UNKNOWN_OWNERSHIP` → explicit policy required → DENY (fail closed).

For `resource(id: 102)` the schema-inferred rule tells the gateway that a `Resource` is owned through `owner_id` referencing a `User`; the database then says the owner is **102** while the authenticated user is **101** → `DENY`, BOLA detected, HTTP 403. Changing nothing but the ID is what flipped the decision — and the rule that justified it is visible in the trace and in the inference endpoint.

**Bonus — fail closed demo:** query a type the schema has no ownership rule for:

```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ widget(id: 1) { name } }\"}"
```
**Expected:** HTTP 403 with `reason: UNKNOWN_OWNERSHIP` — the gateway refuses to guess.

---

### Final Step: Live Security Dashboard

To prove that all decisions were permanently recorded:
1. Open your web browser.
2. Navigate to **http://localhost:8000/dashboard**
3. Show the evaluator the visual Audit Log, which now contains the exact `ALLOW` and `DENY` events you just triggered manually!
