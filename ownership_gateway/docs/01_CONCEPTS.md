# 1. Concepts from scratch (read this first)

## 1.1 GraphQL in five minutes

**REST** has many URLs, and each one returns a fixed shape:

```
GET /api/records/101        -> the whole record
GET /api/records/101/invoice
```

**GraphQL** has **one URL** (`POST /graphql`). The client sends a *query* that says exactly which fields
it wants, and the server returns JSON in the same shape:

```graphql
query {
  record(id: "101") {      # a "root field" with an argument
    diagnosis              # fields you want back
    patient { name }       # follow a relationship (nested object)
  }
}
```

```json
{ "data": { "record": { "diagnosis": "Type 2 diabetes", "patient": { "name": "Alice" } } } }
```

Key vocabulary (examiners like correct terms):

| Term | Meaning | In our project |
|---|---|---|
| **Schema / SDL** | The typed contract of the API: types, fields, arguments | `SDL` in `backend/app.py` |
| **Type** | An object kind (`User`, `MedicalRecord`, `Invoice`) | |
| **Query / Mutation** | Read operation / write operation | `record(id)`, `updateRecord(id, ...)` |
| **Resolver** | The function that fetches a field's data | `Q["record"].resolve = ...` |
| **Introspection** | Asking the API for its own schema (`__schema`) | the gateway does this at startup |
| **Alias** | Renaming a field so it can be requested many times: `a: record(id:"1") b: record(id:"2")` | attack A03 |
| **Fragment** | A reusable selection: `...F` with `fragment F on MedicalRecord { diagnosis }` | attack A06 |
| **Variables** | Values sent separately from the query text: `$id` | attack A05 |
| **Batching** | A JSON array with several operations in one HTTP request | attack A04 |
| **Node interface** | Relay convention: `node(id: "base64(Type:id)")` fetches *any* object | attack A07 |
| **`__typename`** | A meta-field that returns the concrete type name of an object | used by the gateway's response check |

## 1.2 What is BOLA?

**Broken Object Level Authorization** is #1 in the OWASP API Security Top 10 (2023, "API1:2023").
It is the API version of the older term IDOR (Insecure Direct Object Reference).

> The server checks **who you are** (authentication), but it does not check **whether this particular
> object belongs to you** (object-level authorization).

A real-life analogy: a hotel checks that you are a guest (you have a key card), but your card opens
**every** room. Changing room 204 to 205 should not work, but it does.

The example from our backend: Bob is logged in, and his own record is 201. He sends:

```graphql
{ record(id: "101") { diagnosis } }     # 101 is Alice's record
```

The resolver is `lambda _, info, id: record_obj(id)`. It never compares the record's `patientId` with
the caller's `uid`, so Bob receives Alice's diagnosis. That is a BOLA vulnerability.

### Why GraphQL makes BOLA worse

1. **One endpoint.** A URL-based firewall rule such as `/records/{id}` does not work, because every request goes to `/graphql`.
2. **The graph.** Objects link to other objects, so an attacker can enter through something allowed (a public
   profile) and *walk* to private data: `user(id:"1"){ records { diagnosis } }` (A08, A09).
3. **Aliases and batching.** Hundreds of IDs can be guessed in **one** HTTP request, which bypasses per-request rate limits (A03, A04).
4. **Many paths to the same object.** `record(id)`, `node(id)`, `searchRecords`, `user.records`, `invoice.record`
   all lead to the same `MedicalRecord`. The developer must remember the check in **every** resolver, and missing one is enough.
5. **Introspection** gives attackers a complete map of types and ID arguments.

## 1.3 What does "schema-aware" mean?

A normal web application firewall (WAF) sees only bytes: a URL and a JSON body. A **schema-aware**
gateway understands GraphQL. It parses the query into a syntax tree, knows the type of every field from
the schema, and uses that type information to make security decisions. For example:

* It knows that `updateRecord(id:)` targets a `MedicalRecord`, because the field returns a `MedicalRecord`.
* It knows that `payInvoice(invoiceId:)` targets an `Invoice`, from the argument name.
* It knows that `MedicalRecord.patientId` holds the owner, from naming conventions plus the `ID` type.
* It knows that `node(id)` can return `User`, `MedicalRecord` or `Invoice` (the possible types of the `Node` interface).

GraphQLShield builds this *ownership model* **automatically** from introspection. You can review it in the dashboard.

## 1.4 What is a security gateway?

A **gateway** (also called a reverse proxy) is a program that sits between clients and the real server.
Every request passes through it, like a security guard at the building entrance who:

* checks your ID card (**authentication**: verifies the token),
* checks what you are *bringing in* (**pre-execution**: is this query allowed, and is this mutation
  targeting an object you own?),
* checks what you are *taking out* (**post-execution**: does the response contain someone else's objects?),
* writes everything in a logbook (**logging**), and raises an alarm when someone tries many doors (**enumeration detection**).

Advantages: **no backend code changes**, one place to enforce policy for many services, and it works for
legacy or third-party APIs. Costs: extra network hop (latency), and it must correctly understand the
backend's data model (that is why schema analysis matters).

## 1.5 How GraphQLShield works: one request, step by step

Bob sends `{ user(id: "1") { name records { diagnosis } } }`.

1. **Authenticate.** The token is verified, so the caller is `uid=2, role=patient`.
2. **Parse and validate** against the schema. Malformed or invalid queries are rejected.
3. **Limits.** Depth 3 ≤ 8, aliases 0 ≤ 15, so the query passes.
4. **Pre-flight.** It's a query, not a mutation, so this is skipped. Reads are handled in step 6.
5. **Augment.** The gateway rewrites the query to:
   ```graphql
   { user(id: "1") { name records { diagnosis __gs_type: __typename __gs_owner: patientId __gs_id: id }
                     __gs_type: __typename __gs_owner: id __gs_id: id } }
   ```
6. **Forward** to the backend, which (vulnerably) returns Alice's data plus the injected fields.
7. **Verify.** The gateway walks the JSON. It sees `User` owned by `1`, but the caller is `2`. Bob requested
   `records`, which is not a public field of `User`, so this is a **violation**. The object is replaced with `null` and an error is added.
8. **Strip** all `__gs_*` fields, **log** the event, and **update the enumeration detector**.
9. Bob receives `{"data":{"user":null},"errors":[{"message":"GraphQLShield: access denied ...","path":["user"]}]}`.

If Bob had asked only for `{ user(id:"1") { name role } }`, all requested fields are public, so the request is **allowed**.
This is why GraphQLShield has fewer false positives than a simple "the ID must be yours" rule.

## 1.6 Why both pre-flight AND response checks? (the key design insight)

| Check | Strength | Weakness |
|---|---|---|
| Pre-flight (check ID arguments before execution) | Stops **side effects** (edit, pay, delete) | Only sees IDs in arguments. It misses nested traversal and unscoped lists, and it blocks public views (false positives) |
| Response verification (check returned objects) | Sees **every** object, however it was reached | Too late for mutations, because the damage is already done |

Our ablation experiment shows this. *Response-only* fails all 3 mutation attacks, and *argument-only*
misses 2 nested/list attacks and blocks 1 legitimate request. Only the hybrid achieves 14/14 with 0 false positives.
