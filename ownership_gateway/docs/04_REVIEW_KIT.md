# 4. Review 2 kit: what to do tonight, what to say, what they will ask

## 4.1 Priority checklist (in this order)

**Must do before the review (about 3-4 hours total)**
1. ☐ **Run it on your laptop** (30 min): `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt matplotlib`, then `./run.sh`,
   and open `http://127.0.0.1:5000/dashboard`. On Windows, run the two commands in `run.sh` in two terminals:
   `python -m backend.app` and `python -m gateway.app`.
2. ☐ **Rehearse the demo script in 4.3 three times** (60 min). Time it, and aim for 7 minutes.
3. ☐ **Read docs/01_CONCEPTS.md** until you can explain BOLA, aliases, the node interface, and why both checks are needed **without notes** (45 min).
4. ☐ **Walk through `gateway/enforcer.py`** with the module table in docs/02 §2.3. You must be able to point at `_preflight`, `_augment_set` and `_verify` (45 min).
5. ☐ **Make 10 slides** from the outline in 4.4. Use `eval/results/effectiveness.png`, `latency.png` and the dashboard screenshot.
6. ☐ Run `pytest -q` and `python -m eval.run_eval` once on your machine, and use **your** numbers on the slides.

**Nice to have (only if there is time)**
* Record a 3-minute screen video of the demo as a backup in case the laptop or projector fails.
* Do the literature search protocol (docs/03 §3.2).

**Do NOT do before the review:** add new features. A stable demo you understand scores more than a half-working new feature.

## 4.2 60-second pitch

> "GraphQL lets clients fetch exactly the data they want through a single endpoint, but authorization is usually written by hand
> inside every resolver. Forgetting it once gives you Broken Object Level Authorization, the number-one API risk in the OWASP
> API Top 10. In GraphQL it's worse, because aliases, batching, fragments, the node interface and nested relationships give an
> attacker many paths to the same object.
> **GraphQLShield** is a security gateway that sits in front of an unmodified GraphQL API. It introspects the schema and
> automatically infers who owns each type. Then it enforces ownership at two points: **before** a mutation runs, by looking up the
> target object's owner, and **after** a query runs, by rewriting the query to fetch each object's owner and redacting objects the
> caller doesn't own.
> On our benchmark of 14 attacks in 10 categories, it prevented all 14 with zero false positives on 14 legitimate requests,
> at about 2.6 milliseconds above a plain proxy. The best baseline, an argument-level ID check, prevented 12 and broke one legitimate request."

## 4.3 Demo script (about 7 minutes)

**Setup before you start presenting:** `./run.sh` is running; the dashboard is open with mode = `shield`; click **Reset data & logs**.
Have `docs/screenshots/` and `demo_cli.sh` ready as a backup.

> ⚠️ After **A03**, Bob is locked out for 30 s. A console query as Bob in that window returns **HTTP 429**. You can use
> this on purpose ("watch: Bob is now blocked entirely") or switch the console to another user. Each attack-lab button
> resets the lock-out, so the lab itself is never affected.

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the "Inferred ownership model" panel | "At startup the gateway introspected the backend. Nobody wrote these rules. It inferred that MedicalRecord is owned through `patientId`, that `payInvoice(invoiceId)` targets an Invoice, and that `deleteInvoice(id)` targets an Invoice even though it only returns a Boolean." |
| 0:45 | Attack lab → **A01** | "Bob is logged in. He asks for record 101, which is Alice's. Left: the backend directly. It leaks Alice's diabetes diagnosis, so BOLA is real. Right: through GraphQLShield, the record is redacted with a BOLA_REDACTED error." |
| 1:45 | **A03** (aliases) | "Five victim objects in one HTTP request using aliases. Per-request rate limits don't see this. All five are redacted." Then scroll to **Alerts**: "the enumeration detector flagged Bob and locked him out for 30 seconds." |
| 2:45 | **A08** (nested pivot) | "This is the interesting one. Viewing a user's public profile is allowed, but Bob walks from the profile into Alice's private records. There is no victim ID of a record anywhere in the request, so an ID-parameter check can't catch it. We catch it because we verify every object in the **response**." |
| 3:45 | **A10** (unscoped search) | "The search resolver forgot to filter by user. Notice that Bob's own record survives and only the others are redacted. That's precision, not just blocking." |
| 4:30 | **A12** (mutation) | "For writes, checking the response is too late, because the record would already be modified. So for mutations the gateway does a **pre-flight** ownership look-up and blocks before the backend runs." |
| 5:15 | Query console as **bob**: `{ user(id: "1") { name role } }` → allowed. Then add `email` → redacted | "Field-aware: public fields are fine, private ones are not." |
| 6:00 | Switch the mode to **argcheck**, run **A10** → succeeds. Switch back to **shield** | "This is the baseline used in our experiments." |
| 6:30 | Show the "Latest evaluation results" panel or a slide | "Five configurations, 14 attacks, 14 benign requests, and 48 automated tests. Full result: 14/14, 0 false positives." |

## 4.4 Slide outline (10 slides)

1. Title, your name and guide, "Review 2: ~75-80% implemented"
2. Problem: GraphQL + BOLA (code snippet of the vulnerable resolver, OWASP API1:2023)
3. Why GraphQL makes BOLA harder (5 access paths, with tiny examples)
4. Existing solutions and the gap (the docs/03 §3.1 table, compressed to 4 rows)
5. Proposed solution and contributions C1-C4
6. Architecture diagram (docs/02 §2.3) plus the 9-step request flow
7. Key technique: query augmentation and response verification (before/after query)
8. Implementation status table (docs/02 §2.8) with a dashboard screenshot
9. Results: Table 1 plus the effectiveness chart, with 3 takeaways
10. Limitations, next steps (roadmap), and the paper plan

## 4.5 Progress report (paste into your report)

**Completed (Review 2):** a vulnerable GraphQL target application (ClinicHub); a schema analyzer that infers an ownership
model automatically from introspection; a gateway with validation, depth/alias/batch limits, pre-flight ownership verification
for mutations (including variables, lists and Relay global IDs), query augmentation with field-aware response verification and
redaction, SQLite event logging, a sliding-window enumeration detector with temporary lock-out, and a web dashboard with an attack lab;
an attack corpus of 14 attacks in 10 categories and 14 benign requests with an automatic oracle; an evaluation harness comparing
five configurations; and 48 automated tests.
**Results:** on ClinicHub, GraphQLShield prevented 14/14 attacks with 0/14 false positives. An argument-level baseline prevented
12/14 with 1/14 false positives; a response-only ablation prevented 11/14; structural limits prevented 0/14.
**Remaining:** shared/relationship-based ownership; evaluation on additional applications and public schemas (inference accuracy);
a load test; deployment packaging; and the paper and final report.

## 4.6 Likely faculty questions and answers

**Q1. What exactly is BOLA, and how is it different from authentication?**
Authentication answers "who are you?". Object-level authorization answers "can *you* access *this specific object*?". In BOLA, the
first check is done and the second is missing. Bob is genuinely logged in, but the server returns Alice's record.

**Q2. Why not just fix the backend code?**
You should, and the gateway is defense in depth. But GraphQL has many paths to each object, so one forgotten resolver is enough
to create a hole. Organisations also run legacy or third-party APIs they can't modify. A gateway enforces one consistent policy
across all of them without code changes, and it logs and detects attacks centrally.

**Q3. What is new here? graphql-shield and Apollo already do authorization.**
The `graphql-shield` npm library and Apollo's `@policy` and `@requiresScopes` directives require developers to write a rule for each
type or field, inside the server. If the developer forgets, the hole remains. Our gateway (1) **infers** the ownership model from
the schema, (2) runs **outside** the application, and (3) verifies the **response**, so it catches objects reached through paths
nobody wrote a rule for (nested traversal, search lists, the node interface). It combines this with pre-flight checks for mutations.
The name is a coincidence. We are not related to that library.

**Q4. How does the gateway know who owns an object?**
From the schema. The principal type `User` is owned by its own `id`, and types with an `ID` field named
`patientId`/`ownerId`/`userId` etc. are owned through that field. It also finds a lookup field like `record(id)` for each type. Every
inference is visible in the dashboard and can be overridden in `policy.json`.

**Q5. What if the client doesn't ask for `patientId`?**
We don't rely on the client. The gateway rewrites the query to add `__gs_owner: patientId` and `__gs_type: __typename` to every
selection set that can contain an owned object, checks them, and strips them before replying. Clients may not use the `__gs_` prefix.
If they try, we reject the query, so they can't spoof the injected fields.

**Q6. Why is pre-flight only for mutations?**
For reads, response verification is strictly more complete, because it sees every returned object, and it avoids an extra round trip.
For writes, the response arrives after the damage is done. The ablation proves both points: response-only failed all 3 mutation attacks.

**Q7. How does pre-flight find the owner?**
It resolves the ID (literal, variable, list, or base64 `node` global ID) and maps it to a type. It then sends a small query as
the gateway's service identity, for example `record(id: $v) { patientId }`, and caches the result for 30 s.

**Q8. Isn't 100% suspicious?**
It's 100% on **our** benchmark of 14 attacks, which we wrote ourselves. That is a threat to validity, and we say so. It is not a
guarantee for all applications. The next steps are a second application, auto-generated attack variants, and inference accuracy on public schemas.

**Q9. Why did argcheck give a false positive?**
B05: Bob views Alice's *public* profile (`name`, `role`). An argument check only sees "user id 1 ≠ Bob" and blocks it. It can't see
which fields were requested. Our response check knows that `name` and `role` are public fields.

**Q10. What's the performance overhead?**
p50 was about 11.3 ms through GraphQLShield, against about 8.7 ms for a plain proxy and 3.5 ms direct, measured on one machine with
Flask's development server over 600 samples per configuration. The security logic adds about 2.6 ms. Most of the rest is the
extra proxy hop. A production deployment would use a production server, and we plan a load test.

**Q11. Time complexity?**
Augmentation is linear in the size of the query AST, and verification is linear in the size of the response JSON. Each pre-flight
look-up is one cached backend query per distinct targeted object.

**Q12. What about aliases and batching DoS?**
There are separate limits (depth 8, aliases 15, batch 5), and the enumeration detector catches slow-and-many attempts across requests.

**Q13. What about the doctor who needs to read patients' records?**
That's shared ownership. We currently support role override (admin) and single ownership. Relationship rules such as
"doctor can read if `record.doctorId == caller`" are the next milestone.

**Q14. Can an attacker bypass the gateway?**
Only if the backend is reachable directly. In deployment, the backend must accept traffic only from the gateway (network policy or mTLS).
That is a deployment requirement.

**Q15. What if introspection is disabled in production?**
The gateway can use its privileged service identity for introspection, or load the SDL file at deploy time. It only needs the schema once.

**Q16. Why redact instead of rejecting the whole request?**
GraphQL supports partial results with errors that carry a path, so legitimate data in the same response (like Bob's own record in
a search) still gets through. Mutations, on the other hand, are blocked entirely.

**Q17. How is the token secured?**
It's an HMAC-SHA256 signed token, the same idea as an HS256 JWT, and forged signatures are rejected (there's a test for this). In production,
use OIDC/JWT from an identity provider. Our contribution is authorization, not authentication.

**Q18. What's your research hypothesis, in one line?**
A gateway that combines schema-derived ownership inference with pre-execution checks for mutations and response verification for reads
prevents more GraphQL BOLA variants, with fewer false positives, than structural limits or argument-level checks, at low overhead.

**Q19. How did you test it?**
48 pytest tests. They cover the inference results, every attack being exploitable without protection, every attack being prevented
with protection, every benign request passing, removal of injected fields, the reserved-alias rejection, the depth limit, enumeration lock-out, and token forgery.

**Q20. Is this original work? Did you use tools?**
Answer this honestly in your own words. Explain how you built and understood each module. Being able to walk through `enforcer.py`
yourself is your strongest proof.
