# GraphQLShield evaluation results

Target: GraphQL Shield FastAPI app (/graphql-insecure, in-process enforcement bypassed)

Generated 2026-10-21 00:17:01 - 12 attacks, 10 benign requests, latency over 50 iterations x 9 read-only queries.

## Table 1 - Effectiveness, precision and overhead

| Configuration | Attacks prevented | Prevention rate | False positives | FPR | p50 latency (ms) | p95 latency (ms) | p50 overhead vs direct (ms) |
|---|---|---|---|---|---|---|---|
| No protection | 0/12 | 0% | 0/10 | 0% | 31.08 | 45.33 | 14.7 |
| Depth/alias limits (hardening baseline) | 0/12 | 0% | 0/10 | 0% | 31.51 | 47.91 | 15.13 |
| Argument-level ID check (WAF-style baseline) | 11/12 | 92% | 1/10 | 10% | 30.43 | 48.43 | 14.05 |
| Response verification only (ablation) | 9/12 | 75% | 0/10 | 0% | 30.65 | 47.67 | 14.27 |
| GraphQLShield (full) | 12/12 | 100% | 0/10 | 0% | 33.94 | 50.16 | 17.56 |

Direct backend (no gateway): p50 16.38 ms, p95 35.02 ms.

## Table 2 - Prevention by attack category

| Category | off | depth | argcheck | response_only | shield |
|---|---|---|---|---|---|
| Direct object reference | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Alias enumeration | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Query batching | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Variables | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Fragments | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Nested traversal | 0/3 | 0/3 | 2/3 | 3/3 | 3/3 |
| Field-level exposure | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Mutation tampering | 0/3 | 0/3 | 3/3 | 0/3 | 3/3 |

## Table 3 - Per-attack outcome (B = blocked/redacted, L = attack succeeded)

| Case | Category | Attack | off | depth | argcheck | response_only | shield |
|---|---|---|---|---|---|---|---|
| F01 | Direct object reference | Read another user's resource and secret key by ID | L | L | B | B | B |
| F02 | Alias enumeration | Enumerate 5 foreign resources in one request using aliases | L | L | B | B | B |
| F03 | Query batching | Batched array of operations targeting other users | L | L | B | B | B |
| F04 | Variables | Victim ID hidden in GraphQL variables | L | L | B | B | B |
| F05 | Fragments | Victim fields requested through a named fragment | L | L | B | B | B |
| F06 | Nested traversal | Pivot from a PUBLIC profile into the victim's resources | L | L | B | B | B |
| F07 | Nested traversal | Fetch a foreign resource nested under the attacker's OWN profile | L | L | L | B | B |
| F08 | Nested traversal | Walk a foreign folder's children | L | L | B | B | B |
| F09 | Field-level exposure | Read a private field (secretToken) of a public type | L | L | B | B | B |
| F10 | Mutation tampering | Rename another user's resource | L | L | B | L | B |
| F11 | Mutation tampering | Transfer another user's resource to the attacker | L | L | B | L | B |
| F12 | Mutation tampering | Delete another user's resource (Boolean return, no object) | L | L | B | L | B |

## Table 4 - Benign requests (P = passed, FP = wrongly blocked)

| Case | Request | off | depth | argcheck | response_only | shield |
|---|---|---|---|---|---|---|
| G01 | Read own resource and its secret key | P | P | P | P | P |
| G02 | Own profile with private token and resources | P | P | P | P | P |
| G03 | View another user's PUBLIC profile (username/role only) | P | P | **FP** | P | P |
| G04 | Own resource via fragment + variables | P | P | P | P | P |
| G05 | Own data with aliases | P | P | P | P | P |
| G06 | Rename own resource | P | P | P | P | P |
| G07 | Alice walks her own folder's children | P | P | P | P | P |
| G08 | Admin reads any user's resource | P | P | P | P | P |
| G09 | Admin batch over several users | P | P | P | P | P |
| G10 | Unowned health query | P | P | P | P | P |
